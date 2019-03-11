# Encoding: utf-8

# --
# Copyright (c) 2008-2019 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import webob
from nagare.services import plugin

from nagare.security import set_manager, set_user, Denial, public, private


class Authentication(plugin.Plugin):
    """An ``Authentication`` object identify, authenticate and create the
    user objects

    .. note::
        By definition, the user object ``None`` is the anonymous user
    """

    def check_user(self, **params):
        """Check the user is valid and create it
        """
        # Retrieve the data associated with the connected user
        principal, credentials = self.get_principal(**params)

        if (principal is None) or not self.authenticate(principal, **credentials):
            user = None
        else:
            user = self.create_user(principal)
            self.set_user_id(user, principal, **credentials)

        return user

    def set_user_id(self, user, id, **credentials):
        """Set the credentials of the user

        In:
          - ``user`` -- the user
          - ``id`` -- the user id
          - ``**kw`` -- the user credentials
        """
        user.set_id(id)

    def logout(self):
        """Deconnection of the current user
        """
        return None

    def denies(self, detail=None, exc=webob.exc.HTTPForbidden, headers=()):
        """Method called when a permission is denied

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        raise exc(str('Access forbidden' if detail is None else detail), headers=headers)

    def handle_request(self, chain, **params):
        set_manager(self)
        set_user(self.check_user(**params))

        return chain.next(**params)

    def has_permission(self, user, perms, subject, message=None):
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
        # Everybody has access to an object protected with the ``public`` permission
        if perms is public:
            return True

        if perms is not private:
            # If several permissions are to be checked, the access must be granted for at least one permission
            if isinstance(perms, (tuple, list, set)):
                if any(self.has_permission(user, perm, subject) for perm in perms):
                    return True

        return Denial(message)

    # --------------------------------------------------------------------------------

    def get_principal(self, request, response, **params):
        """Return the data associated with the connected user

        In:
          - ``request`` -- the web request object
          - ``response`` -- the web response object

        Return:
          - A tuple with the id of the user and a dictionary of its data
        """
        raise NotImplementedError()

    def authenticate(self, principal, **crendentials):
        raise NotImplementedError()

    def create_user(self, principal):
        """The user is validated, create the user object

        In:
          - ``username`` -- the user id

        Return:
          - the user object
        """
        raise NotImplementedError()
