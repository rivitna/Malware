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

import sys
import io
import os
import struct
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


# x25519
X25519_KEY_SIZE = 32


# CRC32
CRC32_POLY = 0x4C11DB7
crc32_table = None


def create_crc32_table(poly: int) -> list:
    """Create CRC32 table"""

    table = list(range(256))

    for i in range(256):
        x = i << 24
        for j in range(8):
            if x & 0x80000000:
                x = (x << 1) ^ poly
            else:
                x <<= 1
        table[i] = x & 0xFFFFFFFF

    return table


def crc32(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """Get CRC32"""

    global crc32_table
    if crc32_table is None:
        crc32_table = create_crc32_table(CRC32_POLY)

    for b in data:
        crc = ((crc & 0xFFFFFF) << 8) ^ crc32_table[((crc >> 24) & 0xFF) ^ b]
    return crc


def derive_encryption_key(priv_key_data: bytes, pub_key_data: bytes) -> bytes:
    """Derive encryption key"""

    # Derive x25519 shared secret
    priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
    pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
    shared_secret = priv_key.exchange(pub_key)

    # Derive encryption key
    return hashlib.sha256(shared_secret).digest()


def cylance_decrypt_session_priv_key(enc_key_data: bytes,
                                     master_priv_key_data: bytes) -> bytes:
    """Cylance: Decrypt session private key from encrypted key data"""

    # Derive XOR key
    pub_key_data = enc_key_data[2 * X25519_KEY_SIZE : 3 * X25519_KEY_SIZE]
    xor_key = derive_encryption_key(master_priv_key_data, pub_key_data)

    # Check XOR key CRC32
    xor_key_crc, = struct.unpack_from('<L', enc_key_data,
                                      3 * X25519_KEY_SIZE)
    if xor_key_crc != crc32(xor_key):
        return None

    # Get session public key
    s_pub_key_data = enc_key_data[X25519_KEY_SIZE : 2 * X25519_KEY_SIZE]

    # Decrypt session private key
    s_priv_key_data = bytearray(enc_key_data[:X25519_KEY_SIZE])
    for i in range(X25519_KEY_SIZE):
        s_priv_key_data[i] ^= xor_key[i]

    return bytes(s_priv_key_data)


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./privkey.bin', 'rb') as f:
    master_priv_key_data = f.read(X25519_KEY_SIZE)

with io.open(filename, 'rb') as f:
    enc_key_data = base64.b64decode(f.read())

# Decrypt session private key from encrypted key data
s_priv_key_data = cylance_decrypt_session_priv_key(enc_key_data,
                                                   master_priv_key_data)
if s_priv_key_data is None:
    print('Error: Failed to decrypt session private key')
    sys.exit(1)

new_filename = filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(s_priv_key_data)
