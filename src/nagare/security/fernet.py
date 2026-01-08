# --
# Copyright (c) 2014-2025 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

"""Fernet token generation (https://github.com/fernet/spec/blob/master/Spec.md)."""

import os
import hmac
import time
import base64
import binascii

import tinyaes


class InvalidToken(Exception):
    pass


class Fernet:
    MAX_CLOCK_SKEW = 60

    def __init__(self, key):
        try:
            key = base64.urlsafe_b64decode(key)
        except binascii.Error as exc:
            raise ValueError('Fernet key must be 32 url-safe base64-encoded bytes') from exc

        if len(key) != 32:
            raise ValueError('Fernet key must be 32 url-safe base64-encoded bytes')

        self._signing_key = key[:16]
        self._encryption_key = key[16:]

    @staticmethod
    def generate_key():
        return base64.urlsafe_b64encode(os.urandom(32))

    @staticmethod
    def pad(data):
        nb = 16 - len(data) % 16
        return data + bytes([nb] * nb)

    @staticmethod
    def unpad(m):
        return m[: -m[-1]]

    def encrypt(self, data):
        data = self.pad(data)
        iv = os.urandom(16)

        tinyaes.AES(self._encryption_key, iv).CBC_encrypt_buffer_inplace_raw(data)
        token = b'\x80' + int(time.time()).to_bytes(length=8, byteorder='big') + iv + data
        sign = hmac.new(self._signing_key, token, 'sha256')

        return base64.urlsafe_b64encode(token + sign.digest())

    def decrypt(self, data, ttl=None):
        try:
            data = base64.urlsafe_b64decode(data)
        except (TypeError, binascii.Error):
            raise InvalidToken()

        if not data or (data[0] != 0x80) or (len(data) < 9):
            raise InvalidToken()

        if ttl:
            timestamp = int.from_bytes(data[1:9], byteorder='big')
            current_time = int(time.time())
            if (timestamp + ttl < current_time) or (current_time + self.MAX_CLOCK_SKEW < timestamp):
                raise InvalidToken()

        sign = hmac.new(self._signing_key, data[:-32], 'sha256')
        if sign.digest() != data[-32:]:
            raise InvalidToken()

        iv = data[9:25]
        data = data[25:-32]
        tinyaes.AES(self._encryption_key, iv).CBC_decrypt_buffer_inplace_raw(data)

        return self.unpad(data)
