# Encoding: utf-8

# --
# Copyright (c) 2008-2020 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import os
import time
import json
from base64 import urlsafe_b64decode

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
    ENDPOINTS = ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint')

    CONFIG_SPEC = dict(
        common.Authentication.CONFIG_SPEC,
        host='string(default="localhost")',
        port='integer(default=None)',
        ssl='boolean(default=True)',
        timeout='integer(default=5)',
        client_id='string',
        client_secret='string(default="")',
        secure='boolean(default=True)',
        verify='boolean(default=True)',
        discovery_endpoint='string(default=None)',
        end_session_endpoint='string(default=None)'
    )
    CONFIG_SPEC.update({endpoint: 'string(default=None)' for endpoint in ENDPOINTS})
    EXCLUDED_CLAIMS = {'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp'} | {'session_state', 'typ', 'nbf'}

    def __init__(
        self,
        name, dist,
        client_id, client_secret='', secure=True,
        host='localhost', port=None, ssl=True, verify=True, timeout=5,
        discovery_endpoint=None, end_session_endpoint=None,
        services_service=None,
        **config
    ):
        services_service(
            super(Authentication, self).__init__, name, dist,
            client_id=client_id, client_secret=client_secret, secure=secure,
            host=host, port=port, ssl=ssl, verify=verify, timeout=timeout,
            discovery_endpoint=discovery_endpoint, end_session_endpoint=end_session_endpoint,
            services_service=services_service,
            **config
        )

        self.timeout = timeout
        self.client_id = client_id
        self.client_secret = client_secret
        self.secure = secure
        self.verify = verify

        self.issuer = self.signing_keys = None

        if not port:
            port = 443 if ssl else 80

        endpoint_params = dict(
            config,
            scheme='https' if ssl else 'http',
            host=host,
            port=port,
            base_url='{}://{}:{}'.format(('https' if ssl else 'http'), host, port)
        )

        self.discovery_endpoint = (discovery_endpoint or '').format(**endpoint_params)
        self.end_session_endpoint = (end_session_endpoint or '').format(**endpoint_params)
        self.endpoints = {endpoint: (config[endpoint] or '').format(**endpoint_params) for endpoint in self.ENDPOINTS}

        missing_endpoints = [endpoint for endpoint, url in self.endpoints.items() if not url]
        if not self.discovery_endpoint and missing_endpoints:
            self.logger.error('Endpoints without values: ' + ', '.join(missing_endpoints))

    def send_request(self, method, url, params=None, data=None):
        return requests.request(
            method, url, params=params or {}, data=data or {},
            verify=self.verify, timeout=self.timeout
        )

    def handle_start(self, app):
        if self.discovery_endpoint:
            r = self.send_request('GET', self.discovery_endpoint).json()

            self.issuer = r['issuer']
            self.end_session_endpoint = r.get('end_session_endpoint')
            self.endpoints = {endpoint: r[endpoint] for endpoint in self.ENDPOINTS}

            certs = self.send_request('GET', r['jwks_uri']).json()
            self.signing_keys = {key['kid']: jwt.jwk_from_dict(key) for key in certs['keys']}

    def handle_request(self, chain, request, **params):
        response = super(Authentication, self).handle_request(chain, request=request, **params)

        user = security.get_user(only_valid=False)

        if (user is not None) and user.is_expired:
            location = user.logout_location
            if location is not None:
                if not location.startswith(('http', '/')):
                    location = request.create_redirect_url(location)

                response.status = 301
                response.location = location
                response.body = b''

            response.delete_session = user.delete_session

        return response

    def create_auth_request(self, session_id, state_id, redirect_url, scopes=(), **params):
        params = dict({
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_url,
            'scope': ' '.join({'openid'} | set(scopes)),
            'access_type': 'offline',
            'state': '#oauth#-{}-{}'.format(session_id, state_id)
        }, **params)

        return 'GET', self.endpoints['authorization_endpoint'], params, {}

    def create_token_request(self, redirect_url, code):
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_url,
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

    def create_end_session_request(self, refresh_token):
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        }

        return 'POST', self.end_session_endpoint, {}, payload

    def create_userinfo_request(self, access_token):
        payload = {'access_token': access_token}

        return 'POST', self.endpoints['userinfo_endpoint'], {}, payload

    def validate_id_token(self, id_token):
        audiences = set(id_token['aud'].split())
        authorized_party = id_token.get('azp')

        return (
            (not self.issuer or id_token['iss'] == self.issuer) and
            (self.client_id in audiences) and
            ((len(audiences) == 1) or (authorized_party is not None)) and
            ((authorized_party is None) or (self.client_id == authorized_party)) and
            (id_token['exp'] > time.time())
        )

    def create_credentials(self, id_token):
        return {k: id_token[k] for k in set(id_token) - self.EXCLUDED_CLAIMS}

    def get_principal(self, request, session, **params):
        principal = None
        credentials = {}

        if session:
            state = request.params.get('state')
            code = request.params.get('code')
            url = None

            credentials = session.get('nagare.credentials', {})

            if code and state and state.startswith('#oauth#-'):
                method, url, params, data = self.create_token_request(request.create_redirect_url(), code)
            else:
                if credentials and (credentials['exp'] < time.time()):
                    method, url, params, data = self.create_refresh_token_request(credentials['refresh_token'])

            if url:
                response = self.send_request(method, url, params, data)
                if response.status_code == 400:
                    self.logger.error(response.params.get('error') or response.json()['error'])
                    credentials = {}
                elif response.status_code != 200:
                    self.logger.error('Authentication error')
                    credentials = {}
                else:
                    tokens = response.json()

                    id_token = tokens['id_token']
                    header, _ = id_token.split('.', 1)
                    header = urlsafe_b64decode(header + '=' * (4 - len(header) % 4))
                    kid = json.loads(header)['kid']
                    id_token = jwt.JWT().decode(id_token, self.signing_keys[kid], do_verify=self.secure)
                    if not self.validate_id_token(id_token):
                        self.logger.error('Invalid id_token')
                        credentials = {}
                    else:
                        credentials = self.create_credentials(id_token)
                        credentials['exp'] = int(time.time()) + (id_token['exp'] - id_token['iat'])
                        credentials['access_token'] = tokens['access_token']
                        credentials['refresh_token'] = tokens['refresh_token']

                session['nagare.credentials'] = credentials

            principal = credentials.get('sub')

        return principal, credentials

    def login(self, h, scopes=(), **params):
        _, url, params, _ = self.create_auth_request(
            h.session_id, h.state_id,
            h.request.create_redirect_url(),
            scopes, **params
        )

        response = h.response
        response.status_code = 307
        response.headers['Location'] = url + '?' + urlencode(params)

        return ''

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

        if not url:
            status = True
        else:
            response = self.send_request(method, url, params, data)
            status = (response.status_code == 204)

        return status

    def user_info(self, user=None):
        if user is None:
            user = security.get_user()

        if user is None:
            return {}

        request = self.create_userinfo_request(user.credentials['access_token'])
        response = self.send_request(*request)

        return response.json() if response.status_code == 200 else {}


class AuthenticationWithDiscovery(Authentication):
    CONFIG_SPEC = dict(
        Authentication.CONFIG_SPEC,
        discovery_endpoint='string(default="{base_url}/.well-known/openid-configuration")'
    )


class KeycloakAuthentication(Authentication):
    CONFIG_SPEC = dict(
        Authentication.CONFIG_SPEC,
        realm='string',
        discovery_endpoint='string(default="{base_url}/auth/realms/{realm}/.well-known/openid-configuration")'
    )


class GoogleAuthentication(AuthenticationWithDiscovery):
    CONFIG_SPEC = dict(
        AuthenticationWithDiscovery.CONFIG_SPEC,
        host='string(default="accounts.google.com")'
    )
