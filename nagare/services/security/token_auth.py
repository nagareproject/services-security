# --
# Copyright (c) 2008-2020 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Authentication manager for token based HTTP authentication"""

import binascii
from webob. exc import HTTPUnauthorized, HTTPForbidden

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
        services_service(
            super(Authentication, self).__init__, name, dist,
            scheme=scheme, base64_encoded=base64_encoded,
            **config
        )

        self.scheme = scheme
        self.base64_encoded = base64_encoded

    def fails(self, body=None, exc=None, **params):
        """Method called when authentication failed

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        super(Authentication, self).fails(body, exc or HTTPUnauthorized, **params)

    def denies(self, body=None, exc=None, **params):
        """Method called when a permission is denied

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        super(Authentication, self).denies(body, exc or HTTPForbidden, **params)

    def get_principal(self, request, **params):
        """Return the data associated with the connected user

        In:
          - ``request`` -- the WebOb request object

        Return:
          - A list with the id of the user and its password
        """
        principal = None  # Anonymous user by default

        authorization = request.headers.get('authorization', '')
        if ' ' in authorization:
            scheme, received_principal = authorization.split(' ', 1)
            if scheme == self.scheme:
                if not self.base64_encoded:
                    principal = received_principal
                else:
                    encoding = request.accept_charset.best_match(['iso-8859-1', 'utf-8'])

                    try:
                        principal = binascii.a2b_base64(received_principal).decode(encoding)
                    except (binascii.Error, UnicodeDecodeError):
                        pass

        return principal, {}, None

    # --------------------------------------------------------------------------------

    def create_user(self, token):
        """The user is validated, create the user object

        In:
          - ``token`` -- the user id

        Return:
          - the user object
        """
        raise NotImplementedError()
