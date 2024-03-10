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

import sys
import io
import os
import shutil
import struct
import math
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import salsa


RANSOM_EXT = '.nigra'

RANSOM_EXT_PREFIX = '.['
RANSOM_EXT_POSTFIX = ']'


# RSA
RSA_KEY_SIZE = 256
RSA_KEY_HEX_SIZE = 2 * RSA_KEY_SIZE

# Salsa20
SALSA_NONCE_SIZE = 8
SALSA_ROUNDS = 8

# Metadata
METADATA_SIZE = SALSA_NONCE_SIZE + RSA_KEY_HEX_SIZE


ENC_BLOCK_SIZE = 0x19000


SENTINEL_SIZE = 16


def load_str_list(filename):
    """Load string list"""

    try:
        with io.open(filename, 'rt', encoding='utf-8') as f:
            str_list = f.read().splitlines()

    except FileNotFoundError:
        return []

    return str_list


def is_important_file_ext(filename: str, blackexts: list) -> bool:
    """Check if the file extansion is important"""

    for ext in blackexts:
        if filename.endswith(ext):
            return True
    return False


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


def decrypt_file(filename: str,
                 is_important_file: bool,
                 priv_key: RSA.RsaKey) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Decrypt Salsa20 key
        enc_key = binascii.unhexlify(metadata[SALSA_NONCE_SIZE:])
        key = rsa_decrypt(enc_key, priv_key)
        if not key:
            return False

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        nonce = metadata[:SALSA_NONCE_SIZE]
        cipher = salsa.Salsa(salsa.Salsa.init_state(key, nonce),
                             SALSA_ROUNDS)

        f.seek(0)

        while True:

            enc_data = f.read(ENC_BLOCK_SIZE)
            if enc_data == b'':
                break

            data = cipher.decrypt(enc_data)

            f.seek(-len(enc_data), 1)
            f.write(data)

            if not is_important_file:
                break

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read master/session RSA private key BLOB
with io.open('./privkey.txt', 'rb') as f:
    priv_key_blob = binascii.unhexlify(f.read())

# Get RSA private key from BLOB
priv_key = rsa_construct_blob(priv_key_blob)
if (priv_key is None) or not priv_key.has_private():
    print('Error: Invalid RSA private key BLOB')
    sys.exit(1)

# Load extension blacklist
blackexts = load_str_list('./blackexts.txt')
print(len(blackexts))

# Copy file
new_filename = None

# Get original file name
if filename.endswith(RANSOM_EXT_POSTFIX + RANSOM_EXT):
    pos = len(filename) - (len(RANSOM_EXT_POSTFIX) + len(RANSOM_EXT))
    for i in range(2):
        pos = filename.rfind(RANSOM_EXT_PREFIX, 0, pos)
        if pos < 0:
            break
    if pos >= 0:
        new_filename = filename[:pos]

is_file_important = \
    is_important_file_ext(new_filename if new_filename else filename,
                          blackexts)

if not new_filename:
    new_filename = filename + '.dec'

shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, is_file_important, priv_key):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
