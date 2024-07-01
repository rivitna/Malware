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
import struct
import shutil
from Crypto.PublicKey import RSA
import chacha
import conti_crypt


RANSOM_EXT = '.EXTEN'
RANSOM_EXT = '.GAZPROM'


# RSA
RSA_KEY_SIZE = 512

# ChaCha20
CHACHA_KEY_SIZE = 32
CHACHA_NONCE_SIZE = 8
CHACHA_ROUNDS = 8


# Metadata
METADATA_SIZE = RSA_KEY_SIZE + 12 + 10


HEADER_ENC_SIZE = 0x100000
ENC_BLOCK_SIZE = 0x500000


def decrypt_file(filename: str, priv_key: RSA.RsaKey) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Decrypt ChaCha20 key and nonce
        enc_key_data = metadata[:RSA_KEY_SIZE]
        key_data = conti_crypt.rsa_decrypt(enc_key_data, priv_key)
        if not key_data:
            return False

        key = key_data[:CHACHA_KEY_SIZE]
        nonce = key_data[CHACHA_KEY_SIZE:
                         CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE]

        orig_file_size, = struct.unpack_from('<Q', metadata,
                                             RSA_KEY_SIZE + 14)

        enc_mode = metadata[RSA_KEY_SIZE + 12]

        if enc_mode == 0x24:

            # full
            num_chunks = 1
            chunk_space = 0
            chunk_size = orig_file_size

        elif enc_mode == 0x26:

            # header
            num_chunks = 1
            chunk_space = 0
            chunk_size = min(HEADER_ENC_SIZE, orig_file_size)

        elif enc_mode == 0x25:

            # partly
            enc_percent = metadata[RSA_KEY_SIZE + 13]
            if enc_percent == 10:
                chunk_size = (orig_file_size // 100) * 4
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 15:
                chunk_size = (orig_file_size // 100) * 5
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 20:
                chunk_size = (orig_file_size // 100) * 7
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 25:
                chunk_size = (orig_file_size // 100) * 9
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 30:
                chunk_size = (orig_file_size // 100) * 10
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 35:
                chunk_size = (orig_file_size // 100) * 12
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 40:
                chunk_size = (orig_file_size // 100) * 14
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 50:
                chunk_size = (orig_file_size // 100) * 10
                num_chunks = 5
                chunk_space = chunk_size
            elif enc_percent == 60:
                chunk_size = (orig_file_size // 100) * 20
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 70:
                chunk_size = (orig_file_size // 100) * 23
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            elif enc_percent == 80:
                chunk_size = (orig_file_size // 100) * 27
                num_chunks = 3
                chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
            else:
                return False

        else:
            return False

        # Decrypt chunks
        chacha_blocks_per_chunk = ((chunk_size + (chacha.BLOCK_SIZE - 1)) //
                                   chacha.BLOCK_SIZE)

        f.seek(0)

        for i in range(num_chunks):

            # Decrypt chunk
            cipher = chacha.ChaCha(key, nonce, i * chacha_blocks_per_chunk,
                                   CHACHA_ROUNDS)

            if i != 0:
                f.seek(chunk_space, 1)

            size = chunk_size
            while size != 0:

                block_size = min(size, ENC_BLOCK_SIZE)
                enc_data = f.read(block_size)
                bytes_read = len(enc_data)
                if bytes_read == 0:
                    break

                data = cipher.decrypt(enc_data)

                f.seek(-bytes_read, 1)
                f.write(data)

                size -= bytes_read

            else:
                continue
            break

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read RSA private key BLOB
with io.open('./rsa_privkey.bin', 'rb') as f:
    priv_key_blob = f.read()

# Get RSA private key from BLOB
priv_key = conti_crypt.rsa_construct_blob(priv_key_blob)
if (priv_key is None) or not priv_key.has_private():
    print('Error: Invalid RSA private key BLOB')
    sys.exit(1)

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
