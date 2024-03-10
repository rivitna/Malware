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
import binascii
import salsa


RANSOM_EXT = '.nigra'

RANSOM_EXT_PREFIX = '.['
RANSOM_EXT_POSTFIX = ']'


ID_SIZE = 10

# RSA
RSA_KEY_SIZE = 256
RSA_KEY_HEX_SIZE = 2 * RSA_KEY_SIZE

# Salsa20
SALSA_KEY_SIZE = 32
SALSA_KEY_HEX_SIZE = 2 * 32
SALSA_NONCE_SIZE = 8
SALSA_ROUNDS = 8

# Metadata
METADATA_SIZE = SALSA_NONCE_SIZE + RSA_KEY_HEX_SIZE


ENC_BLOCK_SIZE = 0x19000


def load_str_list(filename):
    """Load string list"""

    try:
        with io.open(filename, 'rt', encoding='utf-8') as f:
            str_list = f.read().splitlines()

    except FileNotFoundError:
        return []

    return str_list


def is_important_file_ext(filename: str, blackexts: list) -> bool:
    """Check if the file extansion is important"""

    for ext in blackexts:
        if filename.endswith(ext):
            return True
    return False


def decrypt_file(filename: str,
                 is_important_file: bool,
                 key: bytes,
                 enc_key_hex_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Check encrypted key data
        if metadata[SALSA_NONCE_SIZE:] != enc_key_hex_data:
            return False

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        # Decrypt Salsa20 key
        nonce = metadata[:SALSA_NONCE_SIZE]
        cipher = salsa.Salsa(salsa.Salsa.init_state(key, nonce),
                             SALSA_ROUNDS)

        f.seek(0)

        while True:

            enc_data = f.read(ENC_BLOCK_SIZE)
            if enc_data == b'':
                break

            data = cipher.decrypt(enc_data)

            f.seek(-len(enc_data), 1)
            f.write(data)

            if not is_important_file:
                break

    return True


#
# Main
#
if not (2 <= len(sys.argv) <= 3):
    print('Usage:', os.path.basename(sys.argv[0]), 'filename [keyname]')
    sys.exit(0)

filename = sys.argv[1]

key_filename = None
if len(sys.argv) > 2:
    key_filename = sys.argv[2]

# Load extension blacklist
blackexts = load_str_list('./blackexts.txt')

new_filename = None
enc_id = None

# Parse encrypted file name
if filename.endswith(RANSOM_EXT_POSTFIX + RANSOM_EXT):
    pos = len(filename) - (len(RANSOM_EXT_POSTFIX) + len(RANSOM_EXT))
    pos = filename.rfind(RANSOM_EXT_POSTFIX + RANSOM_EXT_PREFIX, 0, pos)
    if pos > ID_SIZE + len(RANSOM_EXT_PREFIX):
        pos -= ID_SIZE + len(RANSOM_EXT_PREFIX)
        if filename[pos : pos + 2] == RANSOM_EXT_PREFIX:
            enc_id = filename[pos + 2 : pos + 2 + ID_SIZE]
            print('ID:', enc_id)
            new_filename = filename[:pos]

is_file_important = \
    is_important_file_ext(new_filename if new_filename else filename,
                          blackexts)

if not new_filename:
    new_filename = filename + '.dec'

if not key_filename:
    # Get key file name from ID
    if not enc_id:
        print('Error: Specify key file')
        sys.exit(1)
    key_filename = os.path.join(os.path.abspath(os.path.dirname(filename)),
                                enc_id + '.key')

# Read encryption key data
with io.open(key_filename, 'rb') as f:
    key_hex_data = f.read(SALSA_KEY_HEX_SIZE)
    enc_key_hex_data = f.read(RSA_KEY_HEX_SIZE)

key = binascii.unhexlify(key_hex_data)

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, is_file_important, key, enc_key_hex_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
