# --
# Copyright (c) 2008-2019 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Authentication manager for the basic HTTP authentication scheme"""

import binascii

from . import common


class Authentication(common.Authentication):
    """Tokens based authentication manager
    """
    CONFIG_SPEC = dict(
        common.Authentication.CONFIG_SPEC,
        scheme='string(default="Bearer")',
        base64_encoded='boolean(default=True)'
    )

    def __init__(self, name, dist, scheme, base64_encoded, services_service, **config):
        services_service(super(Authentication, self).__init__, name, dist, **config)

        self.scheme = scheme
        self.base64_encoded = base64_encoded

    def get_principal(self, request, response, **params):
        """Return the data associated with the connected user

        In:
          - ``request`` -- the WebOb request object
          - ``response`` -- the WebOb response object

        Return:
          - A list with the id of the user and its password
        """
        encoding = request.accept_charset.best_match(['iso-8859-1', 'utf-8'])

        principal = None  # Anonymous user by default

        authorization = request.headers.get('authorization', '')
        if ' ' in authorization:
            scheme, principal = authorization.split(' ', 1)
            if scheme == self.scheme:
                try:
                    if self.base64_encoded:
                        principal = binascii.a2b_base64(principal).decode(encoding)
                except (binascii.Error, UnicodeDecodeError):
                    principal = None

        return principal, {}

    # --------------------------------------------------------------------------------

    def authenticate(self, token):
        raise NotImplementedError()

    def create_user(self, token):
        """The user is validated, create the user object

        In:
          - ``username`` -- the user id

        Return:
          - the user object
        """
        raise NotImplementedError()
