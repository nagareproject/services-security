# Encoding: utf-8

# --
# Copyright (c) 2008-2019 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

from nagare import local


__all__ = (
    'get_manager', 'set_manager', 'get_user', 'set_user',
    'SecurityException', 'UnauthorizedException', 'ForbiddenException',
    'has_permissions', 'check_permissions', 'permissions',
    'User', 'Permission', 'Private', 'Public', 'private', 'public', 'Denial'
)


def get_manager():
    return getattr(local.request, 'manager', None)


def set_manager(manager):
    local.request.manager = manager


def get_user(only_valid=True):
    user = getattr(local.request, 'user', None)
    return None if (user is None) or (user.is_expired and only_valid) else user


def set_user(user):
    local.request.user = user

# ---------------------------------------------------------------------------


class SecurityException(Exception):
    def __init__(self, body=None):
        super(SecurityException, self).__init__(body)


class UnauthorizedException(SecurityException):
    pass


class ForbiddenException(SecurityException):
    pass

# ---------------------------------------------------------------------------


def has_permissions(permissions, subject=None, message=None):
    return get_manager().has_permissions(get_user(), permissions, subject, message)


def check_permissions(permissions, subject=None, message=None):
    return get_manager().check_permissions(get_user(), permissions, subject, message)


def permissions(permissions, subject=None, message=None):
    return lambda f: lambda *args, **kw: check_permissions(permissions, subject, message) and f(*args, **kw)

# ---------------------------------------------------------------------------


class User(object):
    """Base class for the user objects
    """
    def __init__(self, id=None, **credentials):
        self.id = id
        self.credentials = credentials

        self.is_expired = False
        self.delete_session = False
        self.logout_location = None
        self._previous_user = None

    def __enter__(self):
        """Push this user to the stack
        """
        self._previous_user = get_user()
        set_user(self)

    def __exit__(self, *args, **kw):
        """Pop this user from the stack
        """
        set_user(self._previous_user)

    def __repr__(self):
        return '<User {}>'.format(self.id)

# ---------------------------------------------------------------------------


# The application can used anything for the permission objects
# So the following pre-defined permissions are optional helpers

class Permission(object):
    """Base class of all the permissions
    """
    pass


class Private(Permission):
    """To define the ``private`` permission singleton

    Nobody has access to objects protected with this permission
    """
    def __nonzero__(self):
        """Evaluated to ``False`` in a boolean context
        """
        return False

    __bool__ = __nonzero__


class Public(Permission):
    """To define the ``public`` permission singleton

    Every body has access to objects protected with this permission
    """
    pass


# The singleton permissions
private = Private()
public = Public()


class Denial(object):
    """Type of the objects return when an access is denied

    In a boolean context, it is evaluated to ``False``
    """
    def __init__(self, detail=None):
        """Initialisation

        In:
          - ``message`` -- denial description
        """
        self.detail = 'Access forbidden' if detail is None else detail

    def __nonzero__(self):
        """Evaluated to ``False`` in a boolean context
        """
        return False

    __bool__ = __nonzero__

    def __repr__(self):
        return 'security.Denial({})'.format(self.detail)

    def __str__(self):
        return self.detail
