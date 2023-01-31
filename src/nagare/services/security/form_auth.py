# --
# Copyright (c) 2008-2023 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Simple form based authentication manager.

The id and password of the user are first searched into the parameters of
the request. So, first, set a form with the fields names ``__ac_name``
and ``__ac_password`` (the ``__ac`` prefix is configurable).

Then the user id and the password are automatically kept into a cookie,
sent back on each request by the browser.
"""

import copy

from . import cookie_auth


class Authentication(cookie_auth.Authentication):
    """Simple form based authentication."""

    CONFIG_SPEC = dict(
        copy.deepcopy(cookie_auth.Authentication.CONFIG_SPEC),
        prefix='string(default="__ac", help="`_name` and `_password` fields prefix")',
    )

    def __init__(self, name, dist, prefix='__ac', **config):
        """Initialization.

        In:
          - ``prefix`` -- prefix of the names of the user id and password fields
            into the form
          - ``realm`` -- is the form based authentication completed by a
            basic HTTP authentication ?
          - all the other keyword parameters are passed to the ``set_cookie()``
            method of the ``WebOb`` response object
            (see https://docs.pylonsproject.org/projects/webob/en/stable/api/response.html#webob.response.Response.set_cookie)
        """
        super(Authentication, self).__init__(name, dist, prefix=prefix, **config)
        self.prefix = prefix

    def get_principal_from_params(self, params):
        """Search the data associated with the connected user into the request parameter.

        In:
          - ``params`` -- the request parameters

        Return:
          - A tuple with the id of the user and its password
        """
        name = params.get(self.prefix + '_name')
        password = params.get(self.prefix + '_password')

        return (
            (name, {'password': password}, None) if (name is not None) and (password is not None) else (None, {}, None)
        )

    def get_principal(self, request, **params):
        """Return the data associated with the connected user.

        In:
          - ``request`` -- the WebOb request object

        Return:
          - A list with the id of the user and its password
        """
        # First, search into the request parameters
        principal, credential, response = self.get_principal_from_params(request.params)
        if principal is None:
            # Second, search into the cookie
            principal, credential, response = super(Authentication, self).get_principal(request, **params)
            if principal is None:
                credential = {'password': None}
                response = None

        return principal, credential, response

    # --------------------------------------------------------------------------------

    def create_user(self, principal, password, **credentials):
        """Return an applicative user object.

        In:
          - ``principal`` -- the user id. Can be ``None``
          - ``password`` -- the user password. Can be ``None``

        Return:
          - the user object
        """
        raise NotImplementedError()
