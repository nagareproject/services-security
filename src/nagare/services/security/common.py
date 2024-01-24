# Encoding: utf-8

# --
# Copyright (c) 2008-2024 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

from nagare.security import User, PermissionsManager, get_user, set_user, set_manager
from nagare.services import plugin


class Authentication(plugin.Plugin, PermissionsManager):
    """An ``Authentication`` object identify, authenticate and create the user objects.

    .. note::
        By definition, the user object ``None`` is the anonymous user
    """

    LOAD_PRIORITY = 102

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

    def get_principal(self, **params):
        """Return the data associated with the connected user.

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
