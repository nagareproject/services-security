# --
# Copyright (c) 2008-2019 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Authentication manager for the basic HTTP authentication scheme"""

from . import token_auth


class Authentication(token_auth.Authentication):
    """Authentication manager for the basic HTTP authentication scheme
    """
    CONFIG_SPEC = dict(
        token_auth.Authentication.CONFIG_SPEC,
        scheme='string(default="Basic")',
        realm='string(default="")'
    )

    def __init__(self, name, dist, realm='', services_service=None, **config):
        """Initialization

        In:
          - ``realm`` -- authentication realm
        """
        services_service(super(Authentication, self).__init__, name, dist, **config)
        self.realm = realm

    def get_principal(self, **params):
        """Return the data associated with the connected user

        Return:
          - A list with the id of the user and its password
        """
        principal, credentials = super(Authentication, self).get_principal(**params)

        if (principal is not None) and (principal.count(':') == 1):
            principal, password = principal.split(':')
            credentials = {'password': password}

        return principal, credentials

    def authenticate_user(self, principal, password):
        return password == self.get_user_password(principal)

    def fails(self, body=None, content_type='application/html; charset=utf-8', **params):
        """Method called when a permission is denied

        In:
          - ``details`` -- a ``security.common.denial`` object
        """
        headers = (('WWW-Authenticate', 'Basic realm="{}"'.format(self.realm)),)
        super(Authentication, self).fails(body or '', content_type=content_type, headers=headers, **params)

    def denies(self, body=None, content_type='application/html; charset=utf-8', **params):
        """Method called when a permission is denied

        In:
          - ``details`` -- a ``security.common.denial`` object
        """
        super(Authentication, self).denies(body or '', content_type=content_type, **params)

    # --------------------------------------------------------------------------------

    def get_user_password(self, principal):
        raise NotImplementedError()

    def create_user(self, principal, **credentials):
        """The user is validated, create the user object

        In:
          - ``username`` -- the user id

        Return:
          - the user object
        """
        raise NotImplementedError()
