from crypt import methods
import dataclasses

import boto3
import botocore
import flask
from flask import Flask, request, redirect, render_template, url_for, jsonify 
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata, ClientMetadata
from flask_pyoidc.user_session import UserSession

from flask_session import Session
from requests.sessions import session

from cognitodemo.access import AwsAccesser
from cognitodemo.mfa import get_mfa_challenge, verify_mfa_challenge, user_has_software_token_mfa

from loguru import logger
import hashlib
import hmac
import base64
import os
from flask import send_from_directory

app = Flask(__name__)

app.config.from_envvar('COGNITO_DEMO_SETTINGS')

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "super secret key"

Session(app) # use filesystem for session storage

logger.debug("session data: ")
logger.debug(session)

app.config.update({'OIDC_REDIRECT_URI': 'https://dev-rina-cognito.central.tech/redirect_uri',
                   'DEBUG': True})

issuer = f'https://{app.config["PROVIDER_NAME"]}'
cognito_config = ProviderConfiguration(
    provider_metadata=ProviderMetadata(
        issuer=issuer,
        authorization_endpoint=f'{app.config["COGNITO_URL"]}/oauth2/authorize',
        jwks_uri=f'{issuer}/.well-known/jwks.json',
        token_endpoint=f'{app.config["COGNITO_URL"]}/oauth2/token',
    ),
    client_metadata=ClientMetadata(app.config["CLIENT_ID"], app.config["CLIENT_SECRET"]),
    auth_request_params={
        'scope': ['openid', 'aws.cognito.signin.user.admin']  # scope required to update MFA for logged-in user
    }
)
auth = OIDCAuthentication({'cognito': cognito_config},app=app)
logger.debug(cognito_config._provider_metadata)

auth.init_app(app) # nem biztos hogy kell
logger.debug("after init_app")

aws_accesser = AwsAccesser(app.config['AWS_ACCOUNT_ID'], app.config['IDENTITY_POOL_ID'], app.config['PROVIDER_NAME'])
logger.debug('after aws_accesser')

@app.route('/status')
def status():
    return "OK"

@auth.error_view
def error(error=None, error_description=None):
 return jsonify({'error': error, 'message': error_description})

@app.route('/test')
def test():
    logger.debug('in test')
    user_session = UserSession(flask.session,'cognito')

    act = user_session.access_token
    idt = user_session.id_token
    uin = user_session.userinfo

    logger.debug('act: ')
    logger.debug(act)
    logger.debug('idt: ')
    logger.debug(idt)
    logger.debug('uin: ')
    logger.debug(uin)

    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)
    
@app.route('/logout', methods=['GET'])
@auth.oidc_logout
def logout():
    logger.debug('in logout')
    session = UserSession(flask.session,'cognito') # add provider to avoid flask_pyoidc.user_session.UninitialisedSession: Trying to pick-up uninitialised session without specifying 'provider_name'
    session.clear()

    return redirect(url_for('test'), code=303)

@app.route('/login')
@auth.oidc_auth('cognito')
def login():
    app.logger.debug("in index")
    user_session = UserSession(flask.session)
    return redirect(url_for('test'), code=303)

@app.route('/')
@auth.oidc_auth('cognito')
def index():
    app.logger.debug("in index")
    user_session = UserSession(flask.session)
    try:
        if not user_has_software_token_mfa(user_session.access_token):
            challenge = get_mfa_challenge(user_session.access_token)
            flask.session['mfa-challenge'] = challenge
            return redirect(url_for('verify_mfa'), code=303)
    except:
        #TODO: more specific exception handling
        #TODO: auto-reload page, maybe html template + js reload
        user_session.clear()
        return "Session expired, please reload the page to log in again."
        #return redirect(url_for('/'))

    return render_template(
        'index.html',
        kibana_url=app.config['KIBANA_URL'],
        user_groups=user_session.id_token.get('cognito:groups', []),
        user_roles=user_session.id_token.get('cognito:roles', []),
        current_role=flask.session.get('aws-role')
    )

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    def show_mfa(user_session, code):
        service_name = app.config['QR_SERVICE_NAME']
        user_email = user_session.id_token['email']
        qr_uri = f'otpauth://totp/{service_name}:{user_email}?secret={code}&issuer={service_name}'
        return render_template('verify-mfa.html', secret=code, qr_uri=qr_uri)

    user_session = UserSession(flask.session)
    mfa_challenge = flask.session.get('mfa-challenge', None)
    if not mfa_challenge:
        return 'No MFA verification in progress, please try to login again.'

    if request.method == 'GET':
        return show_mfa(user_session, mfa_challenge)

    user_code = request.form['code']
    if len(user_code) != 6:
        flask.flash('Code must be 6 chars.','error')
        return show_mfa(user_session, mfa_challenge)

    if not verify_mfa_challenge(user_session.access_token, user_code):
        flask.flash('MFA verification failed, please try again.','error')
        return show_mfa(user_session, mfa_challenge)

    del flask.session['mfa-challenge']
    return redirect(url_for('index'), code=303)

@app.route('/favicon.ico', methods=['GET'])
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                          'favicon.ico',mimetype='image/vnd.microsoft.icon')


if __name__ == '__main__':
    logger.configure(level=logger.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    app.run()
