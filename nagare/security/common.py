# Encoding: utf-8

# --
# Copyright (c) 2008-2021 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

from nagare import local, partial


__all__ = (
    'get_manager', 'set_manager', 'get_user', 'set_user',
    'SecurityException', 'PermissionsManager',
    'has_permissions', 'check_permissions', 'permissions',
    'User', 'Permission', 'Private', 'Public', 'private', 'public', 'Denial'
)

_marker = object()


class PermissionsManager(object):

    def fails(self, body=None, exc=None, **params):
        """Method called when authentication failed

        In:
          - ``detail`` -- a ``security.Denial`` object
        """
        raise (exc or UnauthorizedException)(body, **params)

    def denies(self, body=None, exc=None, **params):
        """Method called when a permission is denied

        In:
          - ``detail`` -- a ``security.Denial`` object
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

    @staticmethod
    def has_permission(user, perm, subject):
        return False

# ---------------------------------------------------------------------------


def get_manager():
    return getattr(local.request, 'manager', PermissionsManager())


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
    def __init__(self, body=None):
        super(UnauthorizedException, self).__init__('Authorization failed' if body is None else body)


class ForbiddenException(SecurityException):
    def __init__(self, body=None):
        super(ForbiddenException, self).__init__('Access forbidden' if body is None else body)

# ---------------------------------------------------------------------------


def has_permissions(permissions, subject=None, msg=None):
    return get_manager().has_permissions(get_user(), permissions, subject, msg)


def check_permissions(permissions, subject=None, msg=None, exc=None):
    get_manager().check_permissions(get_user(), permissions, subject, msg, exc)


def guarded_call(f, __permissions, __subject, __msg, __exc, self, *args, **kw):
    check_permissions(__permissions, self if __subject is None else __subject, __msg, __exc)
    return f(self, *args, **kw)


def permissions(permissions, subject=None, msg=None, exc=None):
    return lambda f: partial.Decorator(f, guarded_call, permissions, subject, msg, exc)

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
    @staticmethod
    def __nonzero__():
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

    @staticmethod
    def __nonzero__():
        """Evaluated to ``False`` in a boolean context
        """
        return False

    __bool__ = __nonzero__

    def __repr__(self):
        return 'security.Denial({})'.format(self.detail)

    def __str__(self):
        return self.detail
