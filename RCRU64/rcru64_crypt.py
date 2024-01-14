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

import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1


def rsa_decrypt(enc_data: bytes, priv_key_data: bytes) -> bytes:
    """RSA OAEP decrypt data"""

    key = RSA.import_key(priv_key_data)
    decryptor = PKCS1_OAEP.new(key, hashAlgo=SHA1)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def b64decode_and_rsa_decrypt(enc_data: bytes,
                              priv_key_data: bytes) -> bytes:
    """Base64 decode and RSA OAEP decrypt data"""

    return rsa_decrypt(base64.b64decode(enc_data), priv_key_data)


if __name__ == '__main__':
    import sys
    import io
    import os

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    with io.open('./rsa_privkey.txt', 'rb') as f:
        priv_key_data = base64.b64decode(f.read())

    with io.open(filename, 'rb') as f:
        enc_data = f.read()

    # Base64 decode and RSA decrypt data
    data = b64decode_and_rsa_decrypt(enc_data, priv_key_data)
    if data is None:
        print('Error: Failed to decrypt data')
        sys.exit(1)

    new_filename = filename + '.dec'
    with io.open(new_filename, 'wb') as f:
        f.write(data)
