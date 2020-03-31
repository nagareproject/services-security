# Encoding: utf-8

# --
# Copyright (c) 2008-2019 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import os
import time

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import jwt
import requests

from . import common
from nagare import security

os.environ['no_proxy'] = '1'


class Authentication(common.Authentication):
    AUTH_ENDPOINT = '{scheme}://{host}:{port}/auth/realms/{realm}/protocol/openid-connect'
    CONFIG_SPEC = dict(
        common.Authentication.CONFIG_SPEC,
        scheme='string(default="https")',
        host='string(default="localhost")',
        port='integer(default=9000)',
        discovery_url='string(default=None)',
        timeout='integer(default=5)',
        realm='string',
        client_id='string',
        client_secret='string(default="")'
    )

    def __init__(
        self,
        name, dist,
        discovery_url, timeout,
        client_id, client_secret,
        services_service,
        **config
    ):
        services_service(super(Authentication, self).__init__, name, dist, **config)

        self.discovery_url = discovery_url
        self.timeout = timeout
        self.client_id = client_id
        self.client_secret = client_secret

        self.signing_key = None
        self.endpoints = {}

    @staticmethod
    def create_redirect_url(request, session_id, state_id):
        return request.create_redirect_url(_s=session_id, _c='{:05d}'.format(state_id))

    def handle_start(self, app):
        if self.discovery_url:
            r = requests.get(self.discovery_url, timeout=self.timeout).json()
            self.endpoints = {endpoint: url for endpoint, url in r.items() if endpoint.endswith('_endpoint')}
            certs = requests.get(r['jwks_uri']).json()
            self.signing_key = jwt.jwk_from_dict(certs['keys'][0])
        else:
            self.endpoints['auth_endpoint'] = self.AUTH_ENDPOINT.format(**self.config)

    def create_auth_request(self, redirect_url, scopes=()):
        params = dict(client_id=self.client_id, redirect_uri=redirect_url, response_type='code')
        if scopes:
            params['scope'] = ' '.join(scopes)

        return 'GET', self.endpoints['authorization_endpoint'], params, {}

    def create_token_request(self, redirect_url, session_state, code):
        payload = {
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_url,
            'session_state': session_state,
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        return 'POST', self.endpoints['token_endpoint'], {}, payload

    def create_refresh_token_request(self, refresh_token):
        payload = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        }

        return 'POST', self.endpoints['token_endpoint'], {}, payload

    def get_principal(self, request, session_id, previous_state_id, session, **params):
        principal = None
        credentials = {}

        if session:
            session_state = request.params.get('session_state')
            code = request.params.get('code')
            url = None

            credentials = session.get('nagare.credentials', {})

            if session_state and code:
                redirect_url = self.create_redirect_url(request, session_id, previous_state_id)
                method, url, params, data = self.create_token_request(redirect_url, session_state, code)
            else:
                if credentials and (credentials['exp'] < time.time()):
                    method, url, params, data = self.create_refresh_token_request(credentials['refresh_token'])

            if url:
                response = requests.request(method, url, params=params, data=data, timeout=self.timeout)
                if response.status_code == 200:
                    tokens = response.json()
                    id_token = jwt.JWT().decode(tokens['id_token'], self.signing_key, do_verify=True)

                    credentials = {k: id_token[k] for k in id_token if k not in ('exp', 'nbf', 'iat', 'iss', 'aud', 'sub', 'typ', 'azp', 'auth_time', 'session_state', 'acr')}
                    credentials['exp'] = int(time.time()) + (id_token['exp'] - id_token['auth_time'])
                    credentials['access_token'] = tokens['access_token']
                    credentials['refresh_token'] = tokens['refresh_token']

                    session['nagare.credentials'] = credentials

            principal = credentials.get('jti')

        return principal, credentials

    def login(self, h, scopes=('openid',)):
        redirect_url = self.create_redirect_url(h.request, h.session_id, h.state_id)
        _, url, params, _ = self.create_auth_request(redirect_url, scopes=scopes)

        response = h.response
        response.status_code = 307
        response.headers['Location'] = url + '?' + urlencode(params)

        return ''


class KeycloakAuthentication(Authentication):
    CONFIG_SPEC = dict(Authentication.CONFIG_SPEC, realm='string')
    del CONFIG_SPEC['discovery_url']

    def __init__(self, name, dist, scheme, host, port, realm, services_service, **config):
        self.base_url = '{}://{}:{}/auth/realms/{}'.format(scheme, host, port, realm)
        discovery_url = self.base_url + '/.well-known/openid-configuration'
        services_service(super(KeycloakAuthentication, self).__init__, name, dist, discovery_url, host=host, port=port, realm=realm, **config)

    def handle_request(self, chain, **params):
        response = super(Authentication, self).handle_request(chain, **params)

        user = security.get_user(only_valid=False)
        response.delete_session = False if user is None else user.delete_session

        return response

    def create_userinfo_request(self, access_token):
        payload = {'access_token': access_token}

        return 'POST', self.endpoints['userinfo_endpoint'], {}, payload

    def user_info(self, user=None):
        if user is None:
            user = security.get_user()

        if user is None:
            return {}

        method, url, params, data = self.create_userinfo_request(user.credentials['access_token'])
        response = requests.request(method, url, params=params, data=data, timeout=self.timeout)

        return response.json() if response.status_code == 200 else {}

    def create_end_session_request(self, refresh_token):
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        }

        return 'POST', self.endpoints['end_session_endpoint'], {}, payload

    def logout(self, location='', delete_session=True, user=None):
        """Deconnection of the current user

        Mark the user object as expired

        In:
          - ``location`` -- location to redirect to
          - ``delete_session`` -- is the session expired too?
        """
        if user is None:
            user = security.get_user()

        if user is None:
            return False

        user.logout_location = location
        user.delete_session = delete_session
        user.is_expired = True

        method, url, params, data = self.create_end_session_request(user.credentials['refresh_token'])
        response = requests.request(method, url, params=params, data=data, timeout=self.timeout)

        return response.status_code == 204
