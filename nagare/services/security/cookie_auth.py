# --
# Copyright (c) 2008-2022 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Simple form based authentication manager

The id and password of the user are first searched into the parameters of
the request. So, first, set a form with the fields names ``__ac_name``
and ``__ac_password`` (the ``__ac`` prefix is configurable).

Then the user id and the password are automatically kept into a cookie,
sent back on each request by the browser.
"""

import json
from base64 import urlsafe_b64encode, urlsafe_b64decode

from nagare import security
from cryptography.fernet import Fernet, InvalidToken
from webob.exc import HTTPUnauthorized, HTTPForbidden

from . import common


class Authentication(common.Authentication):
    """Simple cookie based authentication"""

    CONFIG_SPEC = dict(
        common.Authentication.CONFIG_SPEC,
        key='string(default=None, help="cookie encryption key")',

        cookie={
            'activated': 'boolean(default=True)',
            'encrypt': 'boolean(default=True)',
            'name': 'string(default="nagare-security")',
            'max_age': 'integer(default=None)',
            'path': 'string(default="$app_url")',
            'domain': 'string(default=None)',
            'secure': 'boolean(default=True)',
            'httponly': 'boolean(default=True)',
            'comment': 'string(default=None)',
            'overwrite': 'boolean(default=False)',
            'samesite': 'string(default="lax")'
        }
    )

    def __init__(self, name, dist, cookie, key=None, **config):
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
        super(Authentication, self).__init__(name, dist, cookie=cookie.copy(), key=key, **config)

        self.key = key or Fernet.generate_key()
        self.encrypted = cookie.pop('encrypt')
        self.cookie = cookie if cookie.pop('activated') else None

    def fails(self, body=None, exc=None, **params):
        """Method called when authentication failed

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        super(Authentication, self).fails(body, exc or HTTPUnauthorized, **params)

    def denies(self, body=None, exc=None, **params):
        """Method called when a permission is denied

        In:
          - ``detail`` -- a ``security.common.denial`` object
        """
        super(Authentication, self).denies(body, exc or HTTPForbidden, **params)

    def encrypt(self, data):
        return Fernet(self.key).encrypt(data)

    def decrypt(self, data, max_age=None):
        return Fernet(self.key).decrypt(data, max_age)

    def to_cookie(self, principal, **credentials):
        cookie = json.dumps((principal, credentials), separators=(',', ':')).encode('utf-8')

        return self.encrypt(cookie) if self.encrypted else urlsafe_b64encode(cookie)

    def from_cookie(self, cookie, max_age):
        try:
            cookie = self.decrypt(cookie, max_age) if self.encrypted else urlsafe_b64decode(cookie)
        except InvalidToken:
            self.logger.debug("Invalid or expired cookie '{}'".format(cookie))
            principal = None
            credentials = {}
        else:
            principal, credentials = json.loads(cookie)

        return principal, credentials

    def get_principal(self, request, **params):
        """Search the data associated with the connected user into the cookies

        In:
          - ``cookies`` -- cookies dictionary

        Return:
          - A list with the id of the user and its password
        """
        principal = None
        credential = {}

        if self.cookie:
            data = request.cookies.get(self.cookie['name'])
            if data:
                try:
                    principal, credential = self.from_cookie(data.encode('utf-8'), self.cookie['max_age'])
                except Exception as e:
                    self.logger.error('Cookie decoding: {}'.format(e))

        return principal, credential, None

    def cleanup(self, user, request, response, **params):
        if user.is_expired:
            location = user.logout_location
            if location is not None:
                if not location.startswith(('http', '/')):
                    location = request.create_redirect_url(location)

                response.status = 301
                response.location = location
                response.body = b''

            response.delete_session = user.delete_session

        if self.cookie:
            cookie_name = self.cookie['name']

            if user.is_expired:
                if cookie_name in request.cookies:
                    response.delete_cookie(cookie_name, self.cookie['path'], self.cookie['domain'])
            else:
                self.set_cookie(self.to_cookie(**user.credentials), response=response, **params)

    def set_cookie(self, cookie, response, **params):
        response.set_cookie(value=cookie, **self.cookie)

    def logout(self, location='', delete_session=True, user=None):
        """Disconnection of the current user

        Mark the user object as expired

        In:
          - ``location`` -- location to redirect to
          - ``delete_session`` -- is the session expired too?
        """
        if user is None:
            user = security.get_user()

        if user is not None:
            user.logout_location = location
            user.delete_session = delete_session
            user.is_expired = True

        return user
