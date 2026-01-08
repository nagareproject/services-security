# --
# Copyright (c) 2014-2025 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Authentication manager for JWT token based HTTP authentication"""

from jwcrypto import jwk, jws
from python_jwt import _JWTError, generate_jwt, process_jwt, verify_jwt

from . import token_auth


class Authentication(token_auth.Authentication):
    """Tokens based authentication manager"""

    CONFIG_SPEC = token_auth.Authentication.CONFIG_SPEC | {
        'base64_encoded': 'boolean(default=False)',
        'algorithms': 'string_list(default=list({}), help="accepted signing/encryption algorithms")'.format(
            ', '.join(jws.default_allowed_algs)
        ),
    }

    def __init__(self, name, dist, algorithms, services_service, **config):
        services_service(super().__init__, name, dist, algorithms=algorithms, **config)

        self.algorithms = algorithms

    def get_principal(self, **params):
        """Return the data associated with the connected user

        In:
          - ``request`` -- the WebOb request object

        Return:
          - A list with the id of the user and its password
        """
        principal, credentials, response = super().get_principal(**params)
        if principal is not None:
            verify_jwt(principal, allowed_algs=self.algorithms)
            _, credentials = process_jwt(principal)
            principal = credentials['sub']

        return principal, credentials, None

    # --------------------------------------------------------------------------------

    def create_user(self, token):
        """The user is validated, create the user object

        In:
          - ``token`` -- the user id

        Return:
          - the user object
        """
        raise NotImplementedError()
