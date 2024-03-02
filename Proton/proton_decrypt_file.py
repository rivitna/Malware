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
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
from Crypto.Cipher import ChaCha20_Poly1305
import pure_blake3


RANSOM_EXT = '.Proton'

RANSOM_EXT_PREFIX = '.['
RANSOM_EXT_POSTFIX = ']'


# Archive and database file extensions
IMPORTANT_FILE_EXTS = [
    '.rar', '.zip', '.ckp', '.db3', '.dbf', '.dbc', 'dbs', '.dbt', '.dbv',
    '.frm', '.mdf', '.mrg', '.mwb', '.myd', '.ndf', '.qry', '.sdb', '.sdf',
    '.sql', '.tmd', '.wdb', '.bz2', '.tgz', '.lzo', '.db', '.7z', '.sqlite',
    '.accdb', '.sqlite3', '.sqlitedb', '.db-wal', '.db-shm', '.dacpac'
]


# X25519
X25519_KEY_SIZE = 32

# XChaCha20-Poly1305
XCHACHA_NONCE_SIZE = 24
XCHACHA_KEY_SIZE = 32

METADATA_SIZE = 2 * XCHACHA_NONCE_SIZE + 4 * X25519_KEY_SIZE


MAX_SMALL_FILE_SIZE = 0x180000

ENC_BLOCK_SIZE = 0x40000


def is_important_file_ext(filename: str) -> bool:
    """Check if the file extansion is important"""

    for ext in IMPORTANT_FILE_EXTS:
        if filename.endswith(ext):
            return True
    return False


def derive_encryption_key(priv_key1_data: bytes,
                          pub_key2_data: bytes) -> bytes:
    """Derive encryption key"""

    priv_key1 = X25519PrivateKey.from_private_bytes(priv_key1_data)

    # Get X25519 public key 1
    pub_key1 = priv_key1.public_key()
    pub_key1_data = pub_key1.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Derive X25519 shared secret
    pub_key2 = X25519PublicKey.from_public_bytes(pub_key2_data)
    shared_secret = priv_key1.exchange(pub_key2)

    # Derive XChaCha20-Poly1305 encryption key
    hasher = pure_blake3.Hasher()
    hasher.update(shared_secret)
    hasher.update(pub_key2_data)
    hasher.update(pub_key1_data)
    return hasher.finalize(XCHACHA_KEY_SIZE)


def decrypt_file(filename: str,
                 is_important_file: bool,
                 priv_key_data: bytes,
                 is_master_key: bool = False) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < METADATA_SIZE:
            return False

        orig_file_size = file_size - METADATA_SIZE

        # Read metadata
        f.seek(-METADATA_SIZE, 2)
        metadata = f.read(METADATA_SIZE)

        if is_master_key:
            # Decrypt session X25519 key pair
            pos = XCHACHA_NONCE_SIZE + X25519_KEY_SIZE
            enc_key_data = metadata[pos : pos + 2 * X25519_KEY_SIZE]

            # XChaCha20-Poly1305 nonce
            pos += 2 * X25519_KEY_SIZE
            nonce = metadata[pos : pos + XCHACHA_NONCE_SIZE]
            # Derive XChaCha20-Poly1305 key
            pos += XCHACHA_NONCE_SIZE
            pub_key_data = metadata[pos : pos + X25519_KEY_SIZE]
            key = derive_encryption_key(priv_key_data, pub_key_data)

            # XChaCha20-Poly1305 decrypt
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            key_data = cipher.decrypt(enc_key_data)
            s_priv_key_data = key_data[:X25519_KEY_SIZE]
            s_pub_key_data = key_data[X25519_KEY_SIZE:]

            # Check session X25519 key pair
            priv_key = X25519PrivateKey.from_private_bytes(s_priv_key_data)
            pub_key = priv_key.public_key()
            pub_key_data = pub_key.public_bytes(Encoding.Raw,
                                                PublicFormat.Raw)
            if pub_key_data != s_pub_key_data:
                return False

        else:
            s_priv_key_data = priv_key_data

        # XChaCha20-Poly1305 nonce
        nonce = metadata[:XCHACHA_NONCE_SIZE]
        # Derive XChaCha20-Poly1305 key
        pub_key_data = metadata[XCHACHA_NONCE_SIZE:
                                XCHACHA_NONCE_SIZE + X25519_KEY_SIZE]
        key = derive_encryption_key(s_priv_key_data, pub_key_data)

        # Decrypt file data
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

        if orig_file_size <= MAX_SMALL_FILE_SIZE:

            # Full
            f.seek(0)
            enc_data = f.read(orig_file_size)

            data = cipher.decrypt(enc_data)

            f.seek(0)
            f.write(data)

        else:

            # Spot
            if not is_important_file:
                num_blocks = 3
            else:
                if orig_file_size < 0x600000:
                    num_blocks = 4
                elif orig_file_size < 0x3200000:
                    num_blocks = 16
                elif orig_file_size < 0x6400000:
                    num_blocks = 32
                elif orig_file_size < 0x1F400000:
                    num_blocks = 64
                elif orig_file_size < 0x80000000:
                    num_blocks = 128
                elif orig_file_size < 0x300000000:
                    num_blocks = 256
                elif orig_file_size < 0x600000000:
                    num_blocks = 512
                else:
                    num_blocks = 1024

            block_step = orig_file_size // num_blocks

            for i in range(num_blocks):

                # Decrypt block
                if i != num_blocks - 1:
                    pos = i * block_step
                else:
                    pos = orig_file_size - ENC_BLOCK_SIZE

                f.seek(pos)
                enc_data = f.read(ENC_BLOCK_SIZE)
                if enc_data == b'':
                    break

                data = cipher.decrypt(enc_data)

                f.seek(pos)
                f.write(data)

        # Remove metadata
        f.truncate(orig_file_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./privkey.bin', 'rb') as f:
    priv_key_data = f.read(X25519_KEY_SIZE)

new_filename = None

# Get original file name
if filename.endswith(RANSOM_EXT_POSTFIX + RANSOM_EXT):
    pos = filename.rfind(RANSOM_EXT_PREFIX)
    if pos >= 0:
        new_filename = filename[:pos]

is_file_important = \
    is_important_file_ext(new_filename if new_filename else filename)

if not new_filename:
    new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, is_file_important, priv_key_data, True):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
