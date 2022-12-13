# --
# Copyright (c) 2008-2022 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import os
import codecs
import base64

from nagare.admin import command


class Key(command.Command):
    DESC = 'generate random keys'
    WITH_CONFIG_FILENAME = False

    def set_arguments(self, parser):
        parser.add_argument('-l', '--length', default=32, type=int, help='key length, in bytes')
        parser.add_argument('-p', '--prefix', default='')
        parser.add_argument('-s', '--suffix', default='')
        parser.add_argument(
            '-o',
            '--output',
            choices=['base64', 'base64_nopadding', 'base64_url', 'base64_url_nopadding', 'hex', 'number'],
            default='base64',
            help='output format',
        )

        super(Key, self).set_arguments(parser)

    @staticmethod
    def _run(commands_names, length, prefix, suffix, output):
        key = os.urandom(length)

        if (output == 'base64') or (output == 'base64_nopadding'):
            result = base64.standard_b64encode(key)

        elif (output == 'base64_url') or (output == 'base64_url_nopadding'):
            result = base64.urlsafe_b64encode(key)

        elif output == 'hex':
            result = codecs.encode(key, 'hex')

        elif output == 'number':
            if isinstance(key, str):
                result = ''.join(chr(ord('0') + (ord(b) % 10)) for b in key)
            else:
                result = bytes((ord('0') + (b % 10)) for b in key)

        result = result.decode('utf-8')

        if output.endswith('_nopadding'):
            result = result.rstrip('=')

        print(prefix + result + suffix)
        return 0
