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
import shutil
import struct
import chacha
import proxima_crypt


RANSOM_EXTS = [
    '.BLackShadow',
    '.BLackSh',
    '.BlackStore',
    '.ZeroCool',
    '.Black',
    '.X',
    '.Gomez',
    '.Jarjets',
    '.Off',
    '.Daniel',
    '.Xray',
    '.Tisak',
    '.SNet',
    '.Jack',
    '.Sergey',
    '.phoenix',
    '.uploaded',
    '.transferred',
    '.Antoni',
    '.Sezar',
    '.sysinfo',
]

# Cylance
CYLANCE_RANSOM_EXT = '.Cylance'
# Cylance (2023-03-24)
IS_CYLANCE_20230324 = True

# BTC (2023-06-12)
BTC_RANSOM_EXT = '.BTC'
BTC_RANSOM_EXT_PREFIX = '.EMAIL=['


METADATA_CFG_POS = 0
METADATA_CFG_SIZE = 16
METADATA_PUBKEY_POS = METADATA_CFG_POS + METADATA_CFG_SIZE
METADATA_PUBKEY_SIZE = proxima_crypt.X25519_KEY_SIZE
METADATA_NONCE_POS = METADATA_PUBKEY_POS + METADATA_PUBKEY_SIZE
METADATA_NONCE_SIZE = proxima_crypt.CHACHA_NONCE_SIZE
METADATA_KEY_CRC_POS = METADATA_NONCE_POS + METADATA_NONCE_SIZE
METADATA_PUBKEY_CRC_POS = METADATA_KEY_CRC_POS + 4
METADATA_SIZE = METADATA_PUBKEY_CRC_POS + 4


# ChaCha20
CHACHA_ROUNDS = 8

CHACHA_CUSTOM_CONSTANTS = b'hardcore blowjob'


ENC_BLOCK_SIZE = 0x100000


def is_file_encrypted(filename: str,
                      session_key_data_present: bool = False) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:

        additional_data_size = METADATA_SIZE
        if session_key_data_present:
            additional_data_size += (4 +
                                     proxima_crypt.ENC_SESSION_KEY_DATA_SIZE)

        # Read metadata
        try:
            f.seek(-additional_data_size, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

    pub_key_data = metadata[METADATA_PUBKEY_POS :
                            METADATA_PUBKEY_POS + METADATA_PUBKEY_SIZE]

    # Check public key CRC32
    pub_key_crc, = struct.unpack_from('<L', metadata,
                                      METADATA_PUBKEY_CRC_POS)
    return (pub_key_crc == proxima_crypt.crc32(pub_key_data))


def decrypt_file(filename: str,
                 priv_key_data: bytes,
                 session_key_data_present: bool = False,
                 is_master_key: bool = False) -> bool:
    """
    Decrypt file.
    For Cylance (168): session_key_data_present = True
    """

    with io.open(filename, 'rb+') as f:

        additional_data_size = METADATA_SIZE
        if session_key_data_present:
            additional_data_size += (4 +
                                     proxima_crypt.ENC_SESSION_KEY_DATA_SIZE)

        # Read metadata
        try:
            f.seek(-additional_data_size, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        if session_key_data_present and is_master_key:
            # Decrypt session private key
            enc_key_data = f.read(proxima_crypt.ENC_SESSION_KEY_DATA_SIZE)
            priv_key_data = proxima_crypt.decrypt_session_key(enc_key_data,
                                                              priv_key_data)
            if not priv_key_data:
                return False

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
        f.seek(-additional_data_size, 2)
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

            if enc_mode == 2:
                # fast (single block)
                break

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

session_key_data_present = False
is_master_key = False

fname, fext = os.path.splitext(filename)

if fext == BTC_RANSOM_EXT:

    pos = filename.find(BTC_RANSOM_EXT_PREFIX)
    if pos >= 0:
        new_filename = filename[:pos]
    else:
        new_filename = filename + '.dec'

elif fext == CYLANCE_RANSOM_EXT:

    if IS_CYLANCE_20230324:
        # Change ChaCha20 constants
        chacha.CONSTANTS = CHACHA_CUSTOM_CONSTANTS
    else:
        session_key_data_present = True

    new_filename = fname

else:

    # Change ChaCha20 constants
    chacha.CONSTANTS = CHACHA_CUSTOM_CONSTANTS

    if fext in RANSOM_EXTS:
        new_filename = fname
    else:
        new_filename = filename + '.dec'

# Check if file is encrypted
if not is_file_encrypted(filename, session_key_data_present):
    print('Error: The file is damaged or not encrypted')
    sys.exit(1)

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data,
                    session_key_data_present, is_master_key):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
