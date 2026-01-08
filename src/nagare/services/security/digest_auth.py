# --
# Copyright (c) 2014-2025 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Authentication manager for the digest HTTP authentication scheme."""

import os
import time
import hashlib

from . import token_auth


class Authentication(token_auth.Authentication):
    """Authentication manager for the digest HTTP authentication scheme."""

    CONFIG_SPEC = token_auth.Authentication.CONFIG_SPEC | {
        'scheme': 'string(default="Digest")',
        'base64_encoded': 'boolean(default=False)',
        'realm': 'string(default="")',
    }

    def __init__(self, name, dist, realm='', services_service=None, **config):
        """Initialization.

        In:
          - ``realm`` -- authentication realm
        """
        services_service(super().__init__, name, dist, realm=realm, **config)

        self.realm = realm
        self.nonce_seed = os.urandom(16)

    def fails(self, body=None, exc=None, **params):
        """Method called when a permission is denied.

        In:
          - ``details`` -- a ``security.common.denial`` object
        """
        nonce = hashlib.md5(b'%r:%s' % (time.time(), self.nonce_seed)).hexdigest()  # noqa: S324
        headers = (('WWW-Authenticate', f'Digest realm="{self.realm}", nonce="{nonce}", qop="auth"'),)

        super().fails(body, exc, headers=headers, **params)

    login = fails

    def authenticate_user(
        self,
        principal,
        encoding,
        http_method,
        response=None,
        realm=b'',
        uri=b'',
        nonce=b'',
        nc=b'',
        cnonce=b'',
        qop=b'',
        **params,
    ):
        """Authentication.

        In:
          - ``username`` -- user id
          - ``password`` -- real password of the user
          - ``encoding`` -- encoding of username and password on the client
          - ``response``, ``realm``, ``uri``, ``nonce``, ``nc``, ``cnonce``,
            ``qop`` -- elements of the challenge response

        Return:
          - a boolean
        """
        if response is None:
            # Anonymous user
            return False

        password = self.get_user_password(principal).encode(encoding)

        # Make our side hash
        hda1 = hashlib.md5(b'%s:%s:%s' % (principal.encode(encoding), realm, password)).hexdigest()  # noqa: S324
        hda2 = hashlib.md5(http_method + b':' + uri).hexdigest()  # noqa: S324
        sig = b'%s:%s:%s:%s:%s:%s' % (hda1.encode(encoding), nonce, nc, cnonce, qop, hda2.encode(encoding))

        # Compare our hash with the response
        return hashlib.md5(sig).hexdigest().encode(encoding) == response  # noqa: S324

    def get_principal(self, request, response, **params):
        """Return the data associated with the connected user.

        In:
          - ``request`` -- the WebOb request object
          - ``response`` -- the WebOb response object

        Return:
          - A tuple with the id of the user and all the challenge response parameters
        """
        principal, credentials, response = super().get_principal(request=request, **params)

        encoding = request.accept_charset.best_match(['iso-8859-1', 'utf-8'])

        if principal is not None:
            credentials = [x.split('=', 1) for x in principal.split(',')]
            credentials = {k.lstrip(): v.strip('"') for k, v in credentials}
            principal = credentials.pop('username', None)
            credentials['http_method'] = request.method
            credentials = {k: v.encode(encoding) for k, v in credentials.items()}
            credentials['encoding'] = encoding

            if not self.authenticate_user(principal, **credentials):
                self.fails()

        return principal, credentials, response

    # --------------------------------------------------------------------------------

    def get_user_password(self, principal):
        raise NotImplementedError()

    def create_user(self, principal, **credentials):
        """The user is validated, create the user object.

        In:
          - ``principal`` -- the user id

        Return:
          - the user object
        """
        raise NotImplementedError()
