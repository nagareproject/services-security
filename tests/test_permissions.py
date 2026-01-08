# --
# Copyright (c) 2014-2025 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import pytest

from nagare import local
from nagare.security import (
    Denial,
    SecurityException,
    ForbiddenException,
    PermissionsManager,
    public,
    private,
    permissions,
    set_manager,
)


class PM(PermissionsManager):
    def __init__(self):
        super().__init__()

        self.user = self.subject = self.kw = None
        self.perms = []

    @property
    def params(self):
        return self.user, self.perms, self.subject, self.kw

    def has_permission(self, user, perm, subject, **kw):
        self.user = user
        self.perms.append(perm)
        self.subject = subject
        self.kw = kw

        if perm == 'delete':
            return Denial('not allowed')

        return perm in {'public', 'read'}


class Request:
    pass


@pytest.fixture(autouse=True)
def pm():
    local.request = Request()
    pm = PM()
    set_manager(pm)

    return pm


# ---------------------------------------------------------------------------------------------------------------------


class MyException(SecurityException):
    pass


class TestPrivate:
    def test_private(self):
        @permissions(private)
        def f():
            pass

        with pytest.raises(ForbiddenException):
            f()

    def test_private_public(self):
        @permissions((private, public))
        def f(a, b, *args, **kw):
            return a, b, args, kw

        assert f(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})


class TestPublic:
    def test_public(self, pm):
        @permissions(public)
        def f(a, b, *args, **kw):
            return a, b, args, kw

        assert f(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})


class TestPermission:
    def test_public_function(self, pm):
        @permissions('public')
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        assert public_method(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})
        assert pm.params == (None, ['public'], None, {})

    @permissions('public')
    def public_method(self, a, b, *args, **kw):
        return a, b, args, kw

    def test_public_method(self, pm):
        assert self.public_method(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})
        assert pm.params == (None, ['public'], self, {})

    def test_public_function_kw(self, pm):
        @permissions(('private', 'public', 'read'), role='admin')
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        assert public_method(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})
        assert pm.params == (None, ['private', 'public'], None, {'role': 'admin'})

    @permissions(['private', 'public', 'read'], role='admin')
    def public_method_kw(self, a, b, *args, **kw):
        return a, b, args, kw

    def test_public_method_kw(self, pm):
        assert self.public_method_kw(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})
        assert pm.params == (None, ['private', 'public'], self, {'role': 'admin'})

    def test_public_function_subject(self, pm):
        @permissions('public', 'subject', role='admin')
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        assert public_method(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})
        assert pm.params == (None, ['public'], 'subject', {'role': 'admin'})

    @permissions('public', 'subject', role='admin')
    def public_method_subject(self, a, b, *args, **kw):
        return a, b, args, kw

    def test_public_method_subject(self, pm):
        assert self.public_method_subject(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})
        assert pm.params == (None, ['public'], 'subject', {'role': 'admin'})

    def test_public_function_msg1(self, pm):
        @permissions('public', msg='hello world')
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        assert public_method(10, 20, 30, x=42) == (10, 20, (30,), {'x': 42})
        assert pm.params == (None, ['public'], None, {})

    def test_public_function_msg2(self):
        @permissions('private')
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        with pytest.raises(ForbiddenException) as e:
            public_method(10, 20, 30, x=42)

        assert e.value.args == ('Access forbidden',)

    def test_public_function_msg3(self):
        @permissions('private', msg='hello world')
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        with pytest.raises(ForbiddenException) as e:
            public_method(10, 20, 30, x=42)

        assert e.value.args == ('hello world',)

    def test_public_function_msg4(self):
        @permissions('delete')
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        with pytest.raises(ForbiddenException) as e:
            public_method(10, 20, 30, x=42)

        assert e.value.args == ('not allowed',)

    def test_public_function_msg5(self):
        @permissions('delete', msg='hello world')
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        with pytest.raises(ForbiddenException) as e:
            public_method(10, 20, 30, x=42)

        assert e.value.args == ('hello world',)

    def test_public_function_exc1(self):
        @permissions('private', exc=MyException)
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        with pytest.raises(MyException) as e:
            public_method(10, 20, 30, x=42)

        assert e.value.args == ('Access forbidden',)

    def test_public_function_exc2(self):
        @permissions('private', None, 'hello world', MyException)
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        with pytest.raises(MyException) as e:
            public_method(10, 20, 30, x=42)

        assert e.value.args == ('hello world',)

    def test_public_function_exc3(self):
        @permissions('delete', exc=MyException)
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        with pytest.raises(MyException) as e:
            public_method(10, 20, 30, x=42)

        assert e.value.args == ('not allowed',)

    def test_public_function_exc4(self):
        @permissions('delete', None, 'hello world', MyException)
        def public_method(a, b, *args, **kw):
            return a, b, args, kw

        with pytest.raises(MyException) as e:
            public_method(10, 20, 30, x=42)

        assert e.value.args == ('hello world',)
