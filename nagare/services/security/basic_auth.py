# --
# Copyright (c) 2008-2020 Net-ng.
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
        services_service(super(Authentication, self).__init__, name, dist, realm=realm, **config)
        self.realm = realm

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

    def get_principal(self, **params):
        """Return the data associated with the connected user

        Return:
          - A list with the id of the user and its password
        """
        principal, _ = super(Authentication, self).get_principal(**params)

        if (principal is not None) and (principal.count(':') == 1):
            principal, password = principal.split(':')
        else:
            principal = password = None

        return principal, {'password': password}

    # --------------------------------------------------------------------------------

    def create_user(self, principal, password):
        """Authenticate and create the user

        Call ``self.fails()`` on wrong password

        In:
          - ``principal`` -- the user id. Can be ``None``
          - ``password`` -- the user password. Can be ``None``

        Return:
          - the user object
        """
        raise NotImplementedError()
