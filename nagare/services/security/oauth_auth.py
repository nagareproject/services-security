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

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import jwt
import requests

from . import common

os.environ['no_proxy'] = '1'


class Authentication(common.Authentication):
    AUTH_ENDPOINT = 'http://{host}:{port}/auth/realms/{realm}/protocol/openid-connect'
    CONFIG_SPEC = dict(
        common.Authentication.CONFIG_SPEC,
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

        self.auth_endpoint = self.token_endpoint = self.refresh_endpoint = self.signing_key = None

    @staticmethod
    def create_redirect_url(request, session_id, state_id):
        return request.path_url + '?_s={}&_c={:05d}'.format(session_id, state_id)

    def handle_start(self, app):
        if self.discovery_url:
            r = requests.get(self.discovery_url, timeout=self.timeout).json()
            self.auth_endpoint = r['authorization_endpoint']
            self.token_endpoint = self.refresh_endpoint = r['token_endpoint']
            certs = requests.get(r['jwks_uri']).json()
            self.signing_key = jwt.jwk_from_dict(certs['keys'][0])
        else:
            self.auth_endpoint = self.AUTH_ENDPOINT.format(**self.config)

    def create_auth_request(self, redirect_url, scopes=()):
        params = dict(client_id=self.client_id, redirect_uri=redirect_url, response_type='code')
        if scopes:
            params['scope'] = ' '.join(scopes)

        return 'GET', self.auth_endpoint, params, {}

    def create_token_request(self, redirect_url, session_state, code):
        payload = {
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_url,
            'session_state': session_state,
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        return 'POST', self.token_endpoint, {}, payload

    def refresh_token_request(self, refresh_token):
        payload = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        }

        return 'POST', self.refresh_endpoint, {}, payload

    def refresh(self, refresh_token):
        method, url, params, data = self.refresh_token_request(refresh_token)
        requests.request(method, url, params=params, data=data, timeout=self.timeout).json()

    def get_principal(self, request, session_id, previous_state_id, session, **params):
        principal = None
        credentials = {}

        if session:
            session_state = request.params.get('session_state')
            code = request.params.get('code')

            if session_state and code:
                redirect_url = self.create_redirect_url(request, session_id, previous_state_id)
                method, url, params, data = self.create_token_request(redirect_url, session_state, code)
                response = requests.request(method, url, params=params, data=data, timeout=self.timeout)
                if response.status_code == 200:
                    tokens = response.json()
                    id_token = jwt.JWT().decode(tokens['id_token'], self.signing_key, do_verify=True)

                    credentials = {k: id_token[k] for k in id_token if k not in ('exp', 'nbf', 'iat', 'iss', 'aud', 'sub', 'typ', 'azp', 'auth_time', 'session_state', 'acr')}
                    credentials['access_token'] = tokens['access_token']
                    credentials['refresh_token'] = tokens['refresh_token']

                    session['nagare.credentials'] = credentials
                    principal = credentials['jti']
            else:
                credentials = session.get('nagare.credentials', {})
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

    def __init__(self, name, dist, host, port, realm, services_service, **config):
        self.base_url = 'http://{}:{}/auth/realms/{}'.format(host, port, realm)
        discovery_url = self.base_url + '/.well-known/openid-configuration'
        services_service(super(KeycloakAuthentication, self).__init__, name, dist, discovery_url, host=host, port=port, realm=realm, **config)
