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


class User(object):
    """Base class for the user objects
    """
    def __init__(self, id=None, *args):
        self.id = id
        self.credentials = args
        self.is_expired = False

        self._previous_user = None

    def set_id(self, id, *args):
        self.id = id
        self.credentials = args

    def get_id(self):
        return (self.id,) + self.credentials

    def __enter__(self):
        """Push this user to the stack
        """
        self._previous_user = get_user()
        set_user(self)

    def __exit__(self, *args, **kw):
        """Pop this user from the stack
        """
        set_user(self._previous_user)

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


class Denial(Exception):
    """Type of the objects return when an access is denied

    In a boolean context, it is evaluated to ``False``
    """
    def __init__(self, detail=None):
        """Initialisation

        In:
          - ``message`` -- denial description
        """
        super(Denial, self).__init__('Access forbidden' if detail is None else detail)

    def __nonzero__(self):
        """Evaluated to ``False`` in a boolean context
        """
        return False

    __bool__ = __nonzero__

    def __str__(self):
        return 'security.Denial({})'.format(self.args[0])
