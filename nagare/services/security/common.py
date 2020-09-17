# Encoding: utf-8

# --
# Copyright (c) 2008-2020 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

from nagare.services import plugin

from nagare.security import (
    set_manager, set_user, get_user,
    User,
    UnauthorizedException, ForbiddenException,
    Denial, public, private
)


class Authentication(plugin.Plugin):
    """An ``Authentication`` object identify, authenticate and create the
    user objects

    .. note::
        By definition, the user object ``None`` is the anonymous user
    """
    LOAD_PRIORITY = 102

    def fails(self, body=None, exception=UnauthorizedException, **params):
        """Method called when the authentication failed

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        raise exception(body='Authorization failed' if body is None else str(body), **params)

    def denies(self, body=None, exception=ForbiddenException, **params):
        """Method called when a permission is denied

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        raise exception(body='Access forbidden' if body is None else body, **params)

    def has_permissions(self, user, perms, subject, message=None):
        """The ``has_permission()`` generic method
        and default implementation: by default all accesses are denied

        In:
          - ``user`` -- user to check the permission for
          - ``perm`` -- permission(s) to check
          - ``subject`` -- object to check the permission on

        Return:
          - True if the access is granted
          - Else a ``security.common.Denial`` object
        """
        # If several permissions are to be checked, the access must be granted for at least one permission
        if isinstance(perms, (tuple, list, set)):
            has_permissions = any(self.has_permissions(user, perm, subject, message) for perm in perms)
        else:
            if perms is public:
                # Everybody has access to an object protected with the ``public`` permission
                has_permissions = True
            elif perms is private:
                # Nobody has access to an object protected with the ``private`` permission
                has_permissions = False
            else:
                has_permissions = self.has_permission(user, perms, subject)

        return has_permissions or Denial(message)

    def check_permissions(self, user, perms, subject, message=None, exception=None):
        has_permission = self.has_permissions(user, perms, subject, message)

        return has_permission or self.denies(None if has_permission is False else str(has_permission), exception)

    def handle_request(self, chain, **params):
        if get_user() is None:
            set_manager(self)

            # Retrieve the data associated with the connected user
            principal, credentials = self.get_principal(**params)
            user = self.create_user(principal, **credentials)
            if isinstance(user, User):
                user.credentials.setdefault('principal', principal)
                for k, v in credentials.items():
                    user.credentials.setdefault(k, v)

            set_user(user)

        return chain.next(**params)

    # --------------------------------------------------------------------------------

    def has_permission(self, user, perm, subject):
        return False

    # --------------------------------------------------------------------------------

    def get_principal(self, request, response, **params):
        """Return the data associated with the connected user

        In:
          - ``request`` -- the web request object
          - ``response`` -- the web response object

        Return:
          - A tuple with the principal (id) of the user and a dictionary of its credentials
        """
        raise NotImplementedError()

    def create_user(self, principal, **credentials):
        raise NotImplementedError()
