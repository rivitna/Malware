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
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pure_blake3


# Archive and database file extensions
IMPORTANT_FILE_EXTS = [
    '.rar', '.zip', '.ckp', '.db3', '.dbf', '.dbc', 'dbs', '.dbt', '.dbv',
    '.frm', '.mdf', '.mrg', '.mwb', '.myd', '.ndf', '.qry', '.sdb', '.sdf',
    '.sql', '.tmd', '.wdb', '.bz2', '.tgz', '.lzo', '.db', '.7z', '.sqlite',
    '.accdb', '.sqlite3', '.sqlitedb', '.db-wal', '.db-shm', '.dacpac',
    '.1c', '.1cd', '.vmdk', '.vmem', '.iso', '.tar', '.fdb', '.csv', '.mdb',
    '.sl2', '.mpd', '.rsd', '.rsd', '.tib'
]


# X25519
X25519_KEY_SIZE = 32

# ChaCha20-Poly1305
CHACHA_NONCE_SIZE = 12
CHACHA_KEY_SIZE = 32
CHACHA_TAG_SIZE = 16

# Curve25519ChaCha20Poly1305 box
CRYPTO_BOX_KEY_DATA_SIZE = (X25519_KEY_SIZE + CHACHA_TAG_SIZE +
                            CHACHA_NONCE_SIZE)

# Session key data size
SESSION_KEY_DATA_SIZE = 2 * X25519_KEY_SIZE
# Encrypted session key data size
ENC_SESSION_KEY_DATA_SIZE = SESSION_KEY_DATA_SIZE + CRYPTO_BOX_KEY_DATA_SIZE

# Metadata
METADATA_KEY_POS = 0
METADATA_KEY_SIZE = 32
METADATA_NONCE_POS = METADATA_KEY_POS + METADATA_KEY_SIZE
METADATA_NONCE_SIZE = 16
METADATA_FILE_SIZE_POS = METADATA_NONCE_POS + METADATA_NONCE_SIZE
METADATA_FILE_ALIGN_POS = METADATA_FILE_SIZE_POS + 8
METADATA_FILE_NAME_POS = METADATA_FILE_ALIGN_POS + 4
METADATA_FILE_NAME_SIZE = 524
METADATA_SIZE = METADATA_FILE_NAME_POS + METADATA_FILE_NAME_SIZE
# Encrypted metadata size
ENC_METADATA_SIZE = METADATA_SIZE + CRYPTO_BOX_KEY_DATA_SIZE


MAX_SMALL_FILE_SIZE = 0x70000

ENC_BLOCK_SIZE = 0x15000


def is_important_file_ext(filename: str) -> bool:
    """Check if the file extansion is important"""

    for ext in IMPORTANT_FILE_EXTS:
        if filename.endswith(ext):
            return True
    return False


def curve25519chacha20poly1305_decrypt(box_data: bytes,
                                       priv_key_data: bytes) -> bytes:
    """Decrypt Curve25519ChaCha20Poly1305 box"""

    if len(box_data) < CRYPTO_BOX_KEY_DATA_SIZE:
        return None

    data_size = len(box_data) - CRYPTO_BOX_KEY_DATA_SIZE
    pos = data_size

    # Get ChaCha20-Poly1305 MAC tag
    tag = box_data[pos : pos + CHACHA_TAG_SIZE]
    pos += CHACHA_TAG_SIZE

    # Get ChaCha20-Poly1305 nonce
    nonce = box_data[pos : pos + CHACHA_NONCE_SIZE]
    pos += CHACHA_NONCE_SIZE

    # Get X25519 public key 2
    pub_key2_data = box_data[pos : pos + X25519_KEY_SIZE]

    priv_key1 = X25519PrivateKey.from_private_bytes(priv_key_data)

    # Get X25519 public key 1
    pub_key1 = priv_key1.public_key()
    pub_key1_data = pub_key1.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Derive X25519 shared secret
    pub_key2 = X25519PublicKey.from_public_bytes(pub_key2_data)
    shared_secret = priv_key1.exchange(pub_key2)

    # Derive ChaCha20-Poly1305 encryption key
    hasher = pure_blake3.Hasher()
    hasher.update(shared_secret)
    hasher.update(pub_key1_data)
    hasher.update(pub_key2_data)
    key = hasher.finalize(CHACHA_KEY_SIZE)

    # ChaCha20-Poly1305 decrypt data
    enc_data = box_data[:data_size]
    cipher = ChaCha20Poly1305(key)
    try:
        return cipher.decrypt(nonce, enc_data + tag, None)

    except InvalidTag:
        return None


def decrypt_file(filename: str, priv_key_data: bytes,
                 is_master_key: bool = False) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        footer_size = ENC_METADATA_SIZE + ENC_SESSION_KEY_DATA_SIZE

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < footer_size:
            return False

        # Read footer data
        f.seek(-footer_size, 2)
        footer_data = f.read(footer_size)

        if is_master_key:

            # Decrypt session X25519 key pair
            enc_key_data = footer_data[ENC_METADATA_SIZE:]
            key_data = curve25519chacha20poly1305_decrypt(enc_key_data,
                                                          priv_key_data)
            if not key_data:
                return False

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

        # Decrypt metadata
        enc_metadata = footer_data[:ENC_METADATA_SIZE]
        metadata = curve25519chacha20poly1305_decrypt(enc_metadata,
                                                      s_priv_key_data)
        if not metadata:
            return False

        # Key and nonce
        key = metadata[METADATA_KEY_POS:
                       METADATA_KEY_POS + METADATA_KEY_SIZE]
        nonce = metadata[METADATA_NONCE_POS:
                         METADATA_NONCE_POS + METADATA_NONCE_SIZE]

        # Original file size, block align
        orig_file_size, block_align = \
            struct.unpack_from('<QL', metadata, METADATA_FILE_SIZE_POS)

        # Original file name
        name_pos = METADATA_FILE_NAME_POS
        for i in range(name_pos, len(metadata), 2):
            if (metadata[i] == 0) and (metadata[i + 1] == 0):
                break
        orig_file_name = metadata[name_pos : i].decode('UTF-16LE')

        # Decrypt file data
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()

        if orig_file_size <= MAX_SMALL_FILE_SIZE:

            # Full
            f.seek(0)
            enc_data = f.read(orig_file_size)

            data = decryptor.update(enc_data)

            f.seek(0)
            f.write(data)

        else:

            # Spot
            if is_important_file_ext(orig_file_name):
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
            else:
                if orig_file_size < 0x1E00000:
                    num_blocks = 3
                elif orig_file_size < 0xC800000:
                    num_blocks = 4
                elif orig_file_size < 0x1F400000:
                    num_blocks = 5
                elif orig_file_size < 0x40000000:
                    num_blocks = 8
                elif orig_file_size < 0x80000000:
                    num_blocks = 12
                else:
                    num_blocks = 16

            block_step = orig_file_size // num_blocks
            rem = block_step % block_align
            if rem != 0:
                block_step += block_align - rem

            for i in range(num_blocks):

                # Decrypt block
                pos = i * block_step

                f.seek(pos)
                enc_data = f.read(ENC_BLOCK_SIZE)
                if enc_data == b'':
                    break

                data = decryptor.update(enc_data)

                f.seek(pos)
                f.write(data)

        # Remove metadata
        f.truncate(orig_file_size)

    # Restore original file name
    dest_filename = os.path.join(os.path.abspath(os.path.dirname(filename)),
                                 orig_file_name)
    if os.path.isfile(dest_filename):
        os.remove(dest_filename)
    os.rename(filename, dest_filename)

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

new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data, True):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
