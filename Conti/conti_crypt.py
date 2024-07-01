# MIT License
#
# Copyright (c) 2024 Andrey Zhdanov (rivitna)
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

import os
import struct
import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


SENTINEL_SIZE = 16


def rsa_construct_blob(blob: bytes) -> RSA.RsaKey:
    """Construct RSA key from BLOB"""

    is_private = False

    type_ver, key_alg, magic, key_bitlen = struct.unpack_from('<4L', blob, 0)
    # "RSA2"
    if (type_ver == 0x207) and (key_alg == 0xA400) and (magic == 0x32415352):
        is_private = True
    # "RSA1"
    elif (type_ver != 0x206) or (key_alg != 0xA400) or (magic != 0x31415352):
        raise ValueError('Invalid RSA blob')

    pos = 16
    key_len = math.ceil(key_bitlen / 8)

    e = int.from_bytes(blob[pos : pos + 4], byteorder='little')
    pos += 4
    n = int.from_bytes(blob[pos : pos + key_len], byteorder='little')

    if not is_private:
        return RSA.construct((n, e))

    key_len2 = math.ceil(key_bitlen / 16)

    pos += key_len
    p = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    q = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    dp = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    dq = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    iq = int.from_bytes(blob[pos : pos + key_len2], byteorder='little')
    pos += key_len2
    d = int.from_bytes(blob[pos : pos + key_len], byteorder='little')

    if (dp != d % (p - 1)) or (dq != d % (q - 1)):
        raise ValueError('Invalid RSA blob')

    return RSA.construct((n, e, d, p, q))


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes:
    """RSA decrypt data"""

    sentinel = os.urandom(SENTINEL_SIZE)
    cipher = PKCS1_v1_5.new(priv_key)
    data = cipher.decrypt(enc_data[::-1], sentinel)
    if data == sentinel:
        return None
    return data
