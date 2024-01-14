# MIT License
#
# Copyright (c) 2023-2024 Andrey Zhdanov (rivitna)
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


MACHINE_GUID = '873ba7f3-0986-40d0-97df-a1e48ced854f'


MASK32 = 0xFFFFFFFF

ror32 = lambda v, s: ((v & MASK32) >> s) | ((v << (32 - s)) & MASK32)


def get_wide_str_hash(s, n=0):
    """Get Unicode-string hash"""

    for ch in s:

        m = ord(ch)
        if (m >= 0x41) and (m <= 0x5A):
            m |= 0x20
        n = m + ror32(n, 13)

    return ror32(n, 13)


def get_uid(machine_guid):
    """Get U-ID"""

    h = 0xFFFFFFFF
    for _ in range(3):
        h = get_wide_str_hash(machine_guid, h)

    s = h.to_bytes(4, byteorder='little')
    s += s[::-1]

    uid = base64.b64encode(s)
    uid = bytearray(uid[:9])
    for i in range(len(uid)):
        # '+', '/', '='
        if (uid[i] == 0x2B) or (uid[i] == 0x2F) or (uid[i] == 0x3D):
            uid[i] = 0x7A  # 'z'

    return uid.decode()


#
# Main
#
uid = get_uid(MACHINE_GUID)
print('U-ID: \"%s\"' % uid)
