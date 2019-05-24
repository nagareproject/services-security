# --
# Copyright (c) 2008-2019 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Simple form based authentication manager

The id and password of the user are first searched into the parameters of
the request. So, first, set a form with the fields names ``__ac_name``
and ``__ac_password`` (the prefix ``__ac`` is configurable).

Then the user id and the password are automatically kept into a cookie,
sent back on each request by the browser.
"""

import os
import json
from webob import exc

import branca
from nagare import security

from . import common


class Authentication(common.Authentication):
    """Simple form based authentication"""

    CONFIG_SPEC = dict(
        common.Authentication.CONFIG_SPEC,
        prefix='string(default="__ac")', key='string(default=None)',
        cookie_name='string(default="nagare-security")', max_age='integer(default=None)',
        path='string(default="/")', domain='string(default=None)',
        secure='boolean(default=False)', httponly='boolean(default=False)',
        comment='string(default=None)', overwrite='boolean(default=False)'
    )

    def __init__(
        self,
        name, dist,
        prefix='__ac', key=None,
        cookie_name=None, max_age=None,
        path='/', domain=None, secure=True, httponly=False,
        comment=None, overwrite=False, **config
    ):
        """Initialization

        In:
          - ``prefix`` -- prefix of the names of the user id and password fields
            into the form
          - ``realm`` -- is the form based authentication completed by a
            basic HTTP authentication ?
          - all the other keyword parameters are passed to the ``set_cookie()``
            method of the ``WebOb`` response object
            (see https://docs.pylonsproject.org/projects/webob/en/stable/api/response.html#webob.response.Response.set_cookie)
        """
        super(Authentication, self).__init__(name, dist, **config)
        self.prefix = prefix

        self.cookie_name = cookie_name or prefix
        self.max_age = max_age
        self.path = path
        self.domain = domain
        self.secure = secure
        self.httponly = httponly
        self.comment = comment
        self.overwrite = overwrite

        self.key = key or os.urandom(branca.CRYPTO_AEAD_XHCACHA20POLY1305_IETF_KEYBYTES)
        self.decoder = branca.Branca(self.key)

    def fails(self, body=None, content_type='application/html; charset=utf-8', **params):
        """Method called when a permission is denied

        In:
          - ``details`` -- a ``security.common.denial`` object
        """
        super(Authentication, self).fails(body or '', exc.HTTPUnauthorized, content_type=content_type, **params)

    def denies(self, body=None, content_type='application/html; charset=utf-8', **params):
        """Method called when a permission is denied

        In:
          - ``details`` -- a ``security.common.denial`` object
        """
        super(Authentication, self).denies(body or '', exc.HTTPForbidden, content_type=content_type, **params)

    def get_principal_from_params(self, params):
        """Search the data associated with the connected user into the request
        parameter

        In:
          - ``params`` -- the request parameters

        Return:
          - A tuple with the id of the user and its password
        """
        return params.get(self.prefix + '_name'), params.get(self.prefix + '_password')

    def get_principal_from_cookie(self, cookies):
        """Search the data associated with the connected user into the cookies

        In:
          - ``cookies`` -- cookies dictionary

        Return:
          - A list with the id of the user and its password
        """
        data = cookies.get(self.cookie_name)
        try:
            r = json.loads(self.decoder.decode(data, self.max_age)) if data else [None, None]
        except RuntimeError as e:
            self.logger.info("Invalid cookie '{}': {}".format(data, e.args[0]))
            r = [None, None]
        except Exception as e:
            self.logger.error('Cookie decoding: {}'.format(e))
            r = [None, None]

        if len(r) == 2:
            r.append({})

        return r

    def get_principal(self, request, **params):
        """Return the data associated with the connected user

        In:
          - ``request`` -- the WebOb request object

        Return:
          - A list with the id of the user and its password
        """
        # First, search into the request parameters
        principal, password = self.get_principal_from_params(request.params)
        credentials = {'password': password}
        if (principal is None) or (password is None):
            # Second, search into the cookies
            principal, password, credentials = self.get_principal_from_cookie(request.cookies)
            credentials.setdefault('password', password)

        if credentials is None:
            principal = None

        return principal, credentials

    def set_principal_to_cookie(self, request, response, principal, password, **credentials):
        data = (principal, password) if not credentials else (principal, password, credentials)

        response.set_cookie(
            self.cookie_name,
            branca.Branca(self.key).encode(json.dumps(data)),
            max_age=self.max_age,
            path=self.path,
            domain=self.domain,
            secure=self.secure,
            httponly=self.httponly,
            comment=self.comment,
            overwrite=self.overwrite
        )

    def handle_request(self, chain, request, response, session=None, **params):
        r = super(Authentication, self).handle_request(
            chain,
            request=request, response=response,
            **params
        )

        user = security.get_user(only_valid=False)

        if user is None:
            if self.cookie_name in request.cookies:
                response.delete_cookie(self.cookie_name, self.path, self.domain)
        else:
            if user.is_expired:
                if self.cookie_name in request.cookies:
                    response.delete_cookie(self.cookie_name, self.path, self.domain)

                if (session is not None) and user.delete_session:
                    session.delete()

                location = user.logout_location
                if location is not None:
                    if not location.startswith(('http', '/')):
                        location = request.application_url + '/' + location

                    response.status = 301
                    response.location = location
                    response.body = b''
            else:
                self.set_principal_to_cookie(request, response, **user.credentials)

        return r

    def logout(self, location='', delete_session=True):
        """Deconnection of the current user

        Mark the user object as expired

        In:
          - ``location`` -- location to redirect to
          - ``delete_session`` -- is the session expired too ?
        """
        user = security.get_user()
        if user is not None:
            user.logout_location = location
            user.delete_session = delete_session
            user.is_expired = True

    # --------------------------------------------------------------------------------

    def authenticate_user(self, principal, password, **credentials):
        raise NotImplementedError()

    def create_user(self, principal, **credentials):
        """The user is validated, create the user object

        In:
          - ``username`` -- the user id

        Return:
          - the user object
        """
        raise NotImplementedError()
