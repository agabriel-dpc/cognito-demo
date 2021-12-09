import argparse
import json
import sys
from getpass import getpass
from loguru import logger

import boto3
from qrcode import QRCode
import hashlib
import hmac
import base64

cognito_client = boto3.client('cognito-idp')

def secret_hash(username,client_secret,client_id):

    # convert str to bytes
    key = bytes(client_secret, 'latin-1')  
    msg = bytes(username + client_id, 'latin-1')  
    
    new_digest = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.b64encode(new_digest).decode()

def auth_req(client_secret, client_id, username, password):
    logger.info(f'authenticate: {client_id}: {username}/{password}')
    return cognito_client.initiate_auth(
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={'USERNAME': username, 'PASSWORD': password, 'SECRET_HASH' : secret_hash(username,client_secret,client_id)},
        ClientId=client_id
    )


def authenticate(client_secret, client_id, username):
    response = None
    password = None
    while not response:
        try:
            password = getpass()
            response = auth_req(client_secret, client_id, username, password)
        except cognito_client.exceptions.NotAuthorizedException as e:
            logger.error(e)
            pass
        except cognito_client.exceptions.PasswordResetRequiredException:
            logger.error('You need to reset your password.')
            password = forgot_password_flow(client_secret, client_id, username)
            response = auth_req(client_secret, client_id, username, password)

    return response, password


def forgot_password_flow(client_secret, client_id, username):
    response = cognito_client.forgot_password(
        ClientId=client_id,
        Username=username
    )
    logger.info(json.dumps(response['CodeDeliveryDetails']))
    confirmation_code = input('Enter the confirmation code: ')

    password_ok = False
    while not password_ok:
        new_password = getpass('Enter new password: ')
        confirmed_password = getpass('Confirm new password: ')
        if new_password == confirmed_password:
            password_ok = True

    cognito_client.confirm_forgot_password(
        ClientId=client_id,
        Username=username,
        ConfirmationCode=confirmation_code,
        Password=confirmed_password
    )
    logger.info('Password successfully changed')
    return confirmed_password


def second_factor_auth(client_secret, client_id, username, challenge_name, session):
    response = None
    while not response:
        try:
            mfa_code = input('MFA code: ')
            response = cognito_client.respond_to_auth_challenge(
                ChallengeName=challenge_name,
                Session=session,
                ClientId=client_id,
                ChallengeResponses={
                    'USERNAME': username,
                    f'{challenge_name}_CODE': mfa_code,
                    'SECRET_HASH' : secret_hash(username,client_secret,client_id)
                })
        except cognito_client.exceptions.CodeMismatchException:
            logger.error('Incorrect code, please try again.')
            pass

    cognito_client.set_user_mfa_preference(
        SoftwareTokenMfaSettings={
            'Enabled': True,
            'PreferredMfa': True
        },
        AccessToken=response['AuthenticationResult']['AccessToken']
    )

    return response


def totp_setup(session, client_secret, client_id, username, password):
    response = cognito_client.associate_software_token(Session=session)
    secret = response['SecretCode']
    qr_uri = f'otpauth://totp/Cognito:{username}?secret={secret}&issuer=Cognito'
    qr = QRCode()
    qr.add_data(qr_uri)
    qr.make(fit=True)
    qr.print_ascii()

    user_code = input('Scan the QR code, then input the TOTP: ')
    response = cognito_client.verify_software_token(
        Session=response['Session'],
        UserCode=user_code
    )

    if response['Status'] != 'SUCCESS':
        logger.info(f'Failed to verify MFA: {json.dumps(auth_response)}')
        sys.exit(1)

    token_response = auth_req(client_secret, client_id, username, password)

    cognito_client.set_user_mfa_preference(
        SoftwareTokenMfaSettings={
            'Enabled': True,
            'PreferredMfa': True
        },
        AccessToken=token_response['AuthenticationResult']['AccessToken']
    )

    return token_response


def print_auth_result(response):
    logger.info(json.dumps(response['AuthenticationResult'], indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Connect Cognito and authenticate with MFA', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-s','--client-secret', type=str)
    parser.add_argument('-c','--client-id', type=str)
    parser.add_argument('-u','--username', type=str)
    args = parser.parse_args()

    logger.info(args)
    exit


    logger.info("starting authentication...")
    auth_response, password = authenticate(args.client_secret, args.client_id, args.username)
    logger.info(f'response: {auth_response}')

    challenge_name = auth_response.get('ChallengeName')
    if challenge_name in ['SOFTWARE_TOKEN_MFA', 'SMS_MFA']:
        token_response = second_factor_auth(args.client_secret, args.client_id, args.username, challenge_name, auth_response['Session'])
        print_auth_result(token_response)
    elif challenge_name == 'MFA_SETUP':
        token_response = totp_setup(auth_response['Session'], args.client_secret, args.client_id, args.username, password)
        print_auth_result(token_response)
    elif challenge_name == 'NEW_PASSWORD_REQUIRED':
        logger.debug('NEW_PASSWORD_REQUIRED')
    elif 'AuthenticationResult' in auth_response:
        print_auth_result(auth_response)
    else:
        logger.error(f'Unknown response from Cognito: {json.dumps(auth_response)}')
        sys.exit(1)
