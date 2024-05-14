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
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


RANSOM_EXT = '.babyk'


ENC_MARKER = b'\xAB\xBC\xCD\xDE\xEF\xF0'


# x25519
X25519_KEY_SIZE = 32

# ChaCha20
CHACHA20_KEY_SIZE = 32
CHACHA20_NONCE_SIZE = 12
CHACHA20_NONCE_POS = 10

# Metadata
METADATA_SIZE = X25519_KEY_SIZE + len(ENC_MARKER)


MAX_SMALL_FILE_SIZE = 0x1400000
SMALL_FILE_MAX_ENC_SIZE = 0x400000

LARGE_FILE_BLOCK_SIZE = 0x100000
LARGE_FILE_BLOCK_STEP = 0xA00000


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < METADATA_SIZE:
            return False

        file_size -= METADATA_SIZE

        # Read metadata
        f.seek(file_size)
        metadata = f.read(METADATA_SIZE)

        marker = metadata[X25519_KEY_SIZE:]
        if marker != ENC_MARKER:
            return False

        pub_key_data = metadata[:X25519_KEY_SIZE]

        # Derive x25519 shared secret
        priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
        pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
        shared_secret = priv_key.exchange(pub_key)

        # Derive ChaCha20 encryption key and nonce
        key = hashlib.sha256(shared_secret).digest()
        n = hashlib.sha256(key).digest()
        n = n[CHACHA20_NONCE_POS : CHACHA20_NONCE_POS + CHACHA20_NONCE_SIZE]

        nonce = b'\0\0\0\0' + n
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()

        if file_size > MAX_SMALL_FILE_SIZE:

            # Large mode
            num_blocks = file_size // LARGE_FILE_BLOCK_STEP

            for i in range(num_blocks):

                pos = i * LARGE_FILE_BLOCK_STEP
                f.seek(pos)

                enc_data = f.read(LARGE_FILE_BLOCK_SIZE)
                if enc_data == b'':
                    break

                data = decryptor.update(enc_data)

                f.seek(pos)
                f.write(data)

        else:

            # Small mode
            enc_size = min(SMALL_FILE_MAX_ENC_SIZE, file_size)

            f.seek(0)
            enc_data = f.read(enc_size)

            data = decryptor.update(enc_data)

            f.seek(0)
            f.write(data)

        # Remove metadata
        f.truncate(file_size)
        
    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./privkey.bin', 'rb') as f:
    priv_key_data = f.read()

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    print('Error: Failed to decrypt file')
    sys.exit(1)
