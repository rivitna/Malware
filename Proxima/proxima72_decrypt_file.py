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
    '.Hercul',
    '.Dominik',
    '.Elons',
]


METADATA_CFG_POS = 0
METADATA_CFG_SIZE = 16
METADATA_PUBKEY_POS = METADATA_CFG_POS + METADATA_CFG_SIZE
METADATA_PUBKEY_SIZE = proxima_crypt.X25519_KEY_SIZE
METADATA_NONCE_POS = METADATA_PUBKEY_POS + METADATA_PUBKEY_SIZE
METADATA_NONCE_SIZE = proxima_crypt.CHACHA_NONCE_SIZE
METADATA_KEY_CRC_POS = METADATA_NONCE_POS + METADATA_NONCE_SIZE
METADATA_PUBKEY_CRC_POS = METADATA_KEY_CRC_POS + 4
METADATA_WRITTEN_BLOCKS_POS = METADATA_PUBKEY_CRC_POS + 4
METADATA_SIZE = METADATA_WRITTEN_BLOCKS_POS + 8


# ChaCha20
CHACHA_ROUNDS = 8

CHACHA_CUSTOM_CONSTANTS = b'hardcore blowjob'


ENC_BLOCK_SIZE = 0x40000


def is_file_encrypted(filename: str) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

    pub_key_data = metadata[METADATA_PUBKEY_POS :
                            METADATA_PUBKEY_POS + METADATA_PUBKEY_SIZE]

    # Check public key CRC32
    pub_key_crc, = struct.unpack_from('<L', metadata,
                                      METADATA_PUBKEY_CRC_POS)
    return (pub_key_crc == proxima_crypt.crc32(pub_key_data))


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file """

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

        # Decrypt encryption configuration
        enc_cfg = metadata[METADATA_CFG_POS :
                           METADATA_CFG_POS + METADATA_CFG_SIZE]
        cfg = cipher.decrypt(enc_cfg)

        # Encryption mode (1 - full, 2 - fast, 3 - split)
        enc_mode, = struct.unpack_from('<L', cfg, 0)

        block_space = 0
        if enc_mode == 3:
            # split
            block_space, = struct.unpack_from('<Q', cfg, 8)

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        # Decrypt file data
        num_blocks, = struct.unpack_from('<Q', metadata,
                                         METADATA_WRITTEN_BLOCKS_POS)

        pos = 0

        while num_blocks != 0:

            # Decrypt block
            f.seek(pos)
            enc_data = f.read(ENC_BLOCK_SIZE)
            if enc_data == b'':
                break

            data = cipher.decrypt(enc_data)

            f.seek(pos)
            f.write(data)

            if enc_mode == 2:
                # fast (single block)
                break

            pos += ENC_BLOCK_SIZE + block_space
            num_blocks -= 1

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

# Check if file is encrypted
if not is_file_encrypted(filename):
    print('Error: The file is damaged or not encrypted')
    sys.exit(1)

fname, fext = os.path.splitext(filename)
if fext in RANSOM_EXTS:
    new_filename = fname
else:
    new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Change ChaCha20 constants
chacha.CONSTANTS = CHACHA_CUSTOM_CONSTANTS

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
