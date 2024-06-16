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

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.Cipher import AES


# Encryption key data marker
ENC_KEY_MARKER = b'KY'

# RSA
RSA_KEY_SIZE = 512

# AES GCM
KEY_SIZE = 32
NONCE_SIZE = 16
MAC_TAG_SIZE = 16


# Encrypted session key data size
MIN_ENC_SESSION_KEY_DATA_SIZE = len(ENC_KEY_MARKER) + RSA_KEY_SIZE


def rsa_decrypt(enc_data: bytes, priv_key_data: bytes) -> bytes:
    """RSA OAEP decrypt data"""

    key = RSA.import_key(priv_key_data)
    decryptor = PKCS1_OAEP.new(key, hashAlgo=SHA1)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def aes_gcm_decrypt(enc_data: bytes, key: bytes, nonce: bytes) -> bytes:
    """AES GCM decrypt data"""

    if len(enc_data) < MAC_TAG_SIZE:
        return None

    enc_data_size = len(enc_data) - MAC_TAG_SIZE
    tag = enc_data[enc_data_size:]
    enc_data = enc_data[:enc_data_size]
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    try:
        return cipher.decrypt_and_verify(enc_data, tag)
    except ValueError:
        return None


def decrypt_session_key_data(enc_session_key_data: bytes,
                             master_priv_key_data: bytes) -> bytes:
    """Decrypt session key data"""

    if len(enc_session_key_data) < MIN_ENC_SESSION_KEY_DATA_SIZE:
        return None

    enc_data_size = len(enc_session_key_data) - MIN_ENC_SESSION_KEY_DATA_SIZE
    enc_key_data_pos = enc_data_size + len(ENC_KEY_MARKER)

    # Check key marker
    marker = enc_session_key_data[enc_data_size : enc_key_data_pos]
    if marker != ENC_KEY_MARKER:
        return None

    enc_key_data = enc_session_key_data[enc_key_data_pos:]

    # Decrypt encryption key (RSA OAEP)
    key_data = rsa_decrypt(enc_key_data, master_priv_key_data)
    if not key_data:
        return None

    # Decrypt session key data (AES GCM)
    key = key_data[:KEY_SIZE]
    nonce = key_data[KEY_SIZE : KEY_SIZE + NONCE_SIZE]
    enc_data = enc_session_key_data[:enc_data_size]
    return aes_gcm_decrypt(enc_data, key, nonce)


if __name__ == '__main__':
    #
    # Main
    #
    import sys
    import io
    import os
    import base64

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    with io.open('rsa_privkey.txt', 'rt') as f:
        master_priv_key_data = base64.b64decode(f.read())

    with io.open(filename, 'rb') as f:
        enc_session_key_data = f.read()

    # Decrypt session private key data
    session_key_data = decrypt_session_key_data(enc_session_key_data,
                                                master_priv_key_data)
    if not session_key_data:
        print('Error: Failed to decrypt session private key')
        sys.exit(1)

    new_filename = filename + '.dec'
    with io.open(new_filename, 'wb') as f:
        f.write(session_key_data)
