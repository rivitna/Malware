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
import base64
import xml.etree.ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES


RANSOM_EXT = '.xxxxxxxxxxxxxx'

MB = 0x100000
GB = 0x40000000

ENC_BLOCK_SIZE = 88 * MB
ENC_BLOCK_STEP = 892 * MB
MAX_ENC_SIZE = 10 * GB


# RSA
RSA_KEY_SIZE = 256

# AES CFM
KEY_SIZE = 32
IV_SIZE = 16


# Metadata
METADATA_SIZE = RSA_KEY_SIZE


SENTINEL_SIZE = 16


def get_rsa_key_from_xml(key_xml_str: str, is_private: bool) -> RSA.RsaKey:
    """Get RSA private key from XML string"""

    root = ET.fromstring(key_xml_str)
    if root.tag != 'RSAKeyValue':
        return None

    elem = root.find('Modulus')
    if elem is None:
        return None

    n = int.from_bytes(base64.b64decode(elem.text), byteorder='big')

    elem = root.find('Exponent')
    if elem is None:
        return None

    e = int.from_bytes(base64.b64decode(elem.text), byteorder='big')

    if not is_private:
        return RSA.construct((n, e))

    elem = root.find('P')
    if elem is None:
        return None

    p = int.from_bytes(base64.b64decode(elem.text), byteorder='big')

    elem = root.find('Q')
    if elem is None:
        return None

    q = int.from_bytes(base64.b64decode(elem.text), byteorder='big')

    elem = root.find('DP')
    if elem is None:
        return None

    dp = int.from_bytes(base64.b64decode(elem.text), byteorder='big')

    elem = root.find('DQ')
    if elem is None:
        return None

    dq = int.from_bytes(base64.b64decode(elem.text), byteorder='big')

    elem = root.find('InverseQ')
    if elem is None:
        return None

    iq = int.from_bytes(base64.b64decode(elem.text), byteorder='big')

    elem = root.find('D')
    if elem is None:
        return None

    d = int.from_bytes(base64.b64decode(elem.text), byteorder='big')

    if (dp != d % (p - 1)) or (dq != d % (q - 1)):
        return None

    return RSA.construct((n, e, d, p, q))


def decrypt_file(filename: str, priv_key: RSA.RsaKey) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < METADATA_SIZE:
            return False

        file_size -= METADATA_SIZE

        # Read metadata
        f.seek(file_size)
        enc_metadata = f.read(METADATA_SIZE)

        # Decrypt metadata (RSA PKCS#1 v1.5)
        sentinel = os.urandom(SENTINEL_SIZE)
        cipher = PKCS1_v1_5.new(priv_key)
        metadata = cipher.decrypt(enc_metadata, sentinel)
        if metadata == sentinel:
            return False

        # Remove metadata
        f.truncate(file_size)

        key = metadata[:KEY_SIZE]
        iv = metadata[KEY_SIZE : KEY_SIZE + IV_SIZE]
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)

        if file_size < ENC_BLOCK_SIZE:

            # Full
            f.seek(0)
            enc_data = f.read(file_size)

            data = cipher.decrypt(enc_data)

            f.seek(0)
            f.write(data)

        else:

            pos = 0

            while pos < MAX_ENC_SIZE:

                # Decrypt block
                f.seek(pos)
                enc_data = f.read(ENC_BLOCK_SIZE)
                if enc_data == b'':
                    break

                data = cipher.decrypt(enc_data)

                f.seek(pos)
                f.write(data)

                pos += ENC_BLOCK_STEP

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./rsa_privkey.xml', 'rt') as f:
    key_xml_str = f.read()

# Get RSA private key from XML string
priv_key = get_rsa_key_from_xml(key_xml_str, True)
if (priv_key is None) or not priv_key.has_private():
    print('Error: Invalid RSA private key XML string')
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
