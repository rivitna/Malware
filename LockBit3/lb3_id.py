# MIT License
#
# Copyright (c) 2023 Andrey Zhdanov (rivitna)
# https://github.com/rivitna
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import base64
import struct
import hashlib
import md4
import lb3_hash


def get_uuid_str(data):
    """Get UUID string from data"""
    h = hashlib.md5()
    h.update(data)
    x = struct.unpack('<L2H8B', h.digest())
    return '{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}' % x


def get_uuid_str_from_utf16(s):
    """Get UUID string from UTF16-string"""
    return get_uuid_str(s.encode('UTF-16LE'))


def get_ipc_name(s):
    """Get IPC Name"""
    return get_uuid_str_from_utf16(s + '_IPC$')


def get_victim_id(guid):
    """Get Victim ID"""

    h = hashlib.md5()
    h.update(guid.encode('UTF-16LE'))
    victim_id = base64.b64encode(h.digest())

    victim_id = bytearray(victim_id[:9])
    for i in range(len(victim_id)):
        if (victim_id[i] == 0x2B):    # '+'
            victim_id[i] = 0x78       # 'x'
        elif (victim_id[i] == 0x2F):  # '/'
            victim_id[i] = 0x69       # 'i'
        elif (victim_id[i] == 0x3D):  # '='
            victim_id[i] = 0x7A       # 'z'

    return victim_id.decode()


def get_bot_id(guid, bigendian=False):
    """Get Bot ID"""

    h1 = lb3_hash.get_wide_str_hash(guid, 0)

    h2 = md4.hash(h1.to_bytes(4, byteorder='little'))

    n = struct.unpack(('>' if bigendian else '<') + '4L', h2)

    return ('%.8x%.8x%.8x%.8x' % n)


if __name__ == '__main__':
    import sys
    import io

    with io.open('rsa_pubkey.bin', 'rb') as f:
        rsa_pub_key = f.read()

    guid = get_uuid_str(rsa_pub_key)

    victim_id = get_victim_id(guid)
    print('ransom ext: \"%s\"' % ('.' + victim_id))

    bot_id = get_bot_id(guid, True)
    print('bot_id:     \"%s\"' % bot_id)

    mutex_name = get_bot_id(guid, False)
    print('mutex:      \"Global\\%s\"' % mutex_name)
