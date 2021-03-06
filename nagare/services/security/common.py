# Encoding: utf-8

# --
# Copyright (c) 2008-2021 Net-ng.
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

    def fails(self, body=None, exc=None, **params):
        """Method called when authentication failed

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        raise (exc or UnauthorizedException)(body, **params)

    def denies(self, body=None, exc=None, **params):
        """Method called when a permission is denied

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        raise (exc or ForbiddenException)(body, **params)

    def has_permissions(self, user, perms, subject, msg=None):
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
            has_permissions = any(self.has_permissions(user, perm, subject, msg) for perm in perms)
        else:
            if perms is public:
                # Everybody has access to an object protected with the ``public`` permission
                has_permissions = True
            elif perms is private:
                # Nobody has access to an object protected with the ``private`` permission
                has_permissions = False
            else:
                has_permissions = self.has_permission(user, perms, subject)

        if not has_permissions:
            if msg is None:
                msg = str(has_permissions) if isinstance(has_permissions, Denial) else None

            has_permissions = Denial(msg)

        return has_permissions

    def check_permissions(self, user, perms, subject, msg=None, exc=None):
        has_permissions = self.has_permissions(user, perms, subject, msg)
        if not has_permissions:
            msg = str(has_permissions) if isinstance(has_permissions, Denial) else None
            self.denies(msg, exc)

    def authenticate(self, **params):
        if get_user() is not None:
            return None, None

        set_manager(self)

        # Retrieve the data associated with the connected user
        principal, credentials, response = self.get_principal(**params)
        user = self.create_user(principal, **credentials)
        if isinstance(user, User):
            user.credentials.setdefault('principal', principal)
            for k, v in credentials.items():
                user.credentials.setdefault(k, v)

        set_user(user)

        return user, response

    @staticmethod
    def cleanup(user, **params):
        pass

    def handle_request(self, chain, response, **params):
        user, response1 = self.authenticate(response=response, **params)
        response2 = chain.next(response=response1 or response, **params)
        response = response1 or response2

        if user is not None:
            self.cleanup(user, response=response, **params)

        return response

    # --------------------------------------------------------------------------------

    @staticmethod
    def has_permission(user, perm, subject):
        return False

    # --------------------------------------------------------------------------------

    def get_principal(self, **params):
        """Return the data associated with the connected user

        In:
          - ``request`` -- the web request object
          - ``response`` -- the web response object

        Return:
          - A tuple :
            - principal (id) of the user
            - dictionary of user credentials
            - response object to return or `None`
        """
        raise NotImplementedError()

    def create_user(self, principal, **credentials):
        raise NotImplementedError()
