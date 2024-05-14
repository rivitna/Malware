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
import chacha
import proxima_crypt


RANSOM_EXTS = [
    '.BTC',
    '.FAST',
    '.havoc',
    '.alvaro',
    '.harward',
    '.rival',
    '.elibe',
    '.ELCTRONIC',
    '.ELECTRONIC',
]

RANSOM_EXT_PREFIX = '.EMAIL=['


METADATA_RATIO_POS = 0
METADATA_PUBKEY_POS = METADATA_RATIO_POS + 4
METADATA_PUBKEY_SIZE = proxima_crypt.X25519_KEY_SIZE
METADATA_NONCE_POS = METADATA_PUBKEY_POS + METADATA_PUBKEY_SIZE
METADATA_NONCE_SIZE = proxima_crypt.CHACHA_NONCE_SIZE
METADATA_KEY_CRC_POS = METADATA_NONCE_POS + METADATA_NONCE_SIZE
METADATA_SIZE = METADATA_KEY_CRC_POS + 4


# ChaCha20
CHACHA_ROUNDS = 12


ENC_BLOCK_SIZE = 0x20000


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        pub_key_data = metadata[METADATA_PUBKEY_POS :
                                METADATA_PUBKEY_POS + METADATA_PUBKEY_SIZE]

        # Derive ChaCha20 encryption key
        key = proxima_crypt.derive_encryption_key(priv_key_data,
                                                  pub_key_data)

        # Check encryption key CRC32
        key_crc, = struct.unpack_from('<L', metadata, METADATA_KEY_CRC_POS)
        if key_crc != proxima_crypt.crc32(key):
            return False

        nonce = metadata[METADATA_NONCE_POS :
                         METADATA_NONCE_POS + METADATA_NONCE_SIZE]

        cipher = chacha.ChaCha(key, nonce, 0, CHACHA_ROUNDS)

        ratio, = struct.unpack_from('<L', metadata, METADATA_RATIO_POS)
        block_space = ratio * ENC_BLOCK_SIZE

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        # Decrypt file data
        pos = 0

        while True:

            # Decrypt block
            f.seek(pos)
            enc_data = f.read(ENC_BLOCK_SIZE)
            if enc_data == b'':
                break

            data = cipher.decrypt(enc_data)

            f.seek(pos)
            f.write(data)

            pos += ENC_BLOCK_SIZE + block_space

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./privkey.bin', 'rb') as f:
    priv_key_data = f.read(proxima_crypt.X25519_KEY_SIZE)

# Copy file
new_filename = None

fname, fext = os.path.splitext(filename)

if fext in RANSOM_EXTS:
    pos = filename.find(RANSOM_EXT_PREFIX)
    if pos >= 0:
        new_filename = filename[:pos]

if not new_filename:
    new_filename = filename + '.dec'

shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
