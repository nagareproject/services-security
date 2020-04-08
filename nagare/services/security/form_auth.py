# --
# Copyright (c) 2008-2020 Net-ng.
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

import json
from webob import exc

from nagare import security
from cryptography.fernet import InvalidToken, Fernet

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
        super(Authentication, self).__init__(
            name, dist,
            prefix=prefix, key=key,
            cookie_name=cookie_name, max_age=max_age,
            path=path, domain=domain, secure=secure, httponly=httponly,
            comment=comment, overwrite=overwrite,
            **config
        )
        self.prefix = prefix

        self.cookie_name = cookie_name or prefix
        self.max_age = max_age
        self.path = path
        self.domain = domain
        self.secure = secure
        self.httponly = httponly
        self.comment = comment
        self.overwrite = overwrite

        self.cipher = Fernet(key or Fernet.generate_key())

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
            r = json.loads(self.cipher.decrypt(data.encode('utf-8'), self.max_age)) if data else [None, None]
        except InvalidToken:
            self.logger.info("Invalid or expired cookie '{}'".format(data))
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
            self.cipher.encrypt(json.dumps(data).encode('utf-8')),
            max_age=self.max_age,
            path=self.path,
            domain=self.domain,
            secure=self.secure,
            httponly=self.httponly,
            comment=self.comment,
            overwrite=self.overwrite
        )

    def handle_request(self, chain, request, response, session=None, **params):
        response = super(Authentication, self).handle_request(
            chain,
            request=request, response=response, session=session,
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

                location = user.logout_location
                if location is not None:
                    if not location.startswith(('http', '/')):
                        location = request.create_redirect_url(location)

                    response.status = 301
                    response.location = location
                    response.body = b''

                response.delete_session = user.delete_session
            else:
                self.set_principal_to_cookie(request, response, **user.credentials)

        return response

    def logout(self, location='', delete_session=True, user=None):
        """Deconnection of the current user

        Mark the user object as expired

        In:
          - ``location`` -- location to redirect to
          - ``delete_session`` -- is the session expired too?
        """
        if user is None:
            user = security.get_user()

        if user is None:
            return False

        user.logout_location = location
        user.delete_session = delete_session
        user.is_expired = True

        return True

    # --------------------------------------------------------------------------------

    def create_user(self, principal, password, **crendentials):
        """
        In:
          - ``principal`` -- the user id. Can be ``None``
          - ``password`` -- the user password. Can be ``None``

        Return:
          - the user object
        """
        raise NotImplementedError()
