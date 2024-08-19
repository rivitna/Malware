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
from Crypto.Cipher import AES
import enmity_crypt


RANSOM_EXT1 = '.lock'
RANSOM_EXT2 = '.v2'
RANSOM_EXT_PREFIX = '.Mail-['


# Footer
FULL_ENC_MARKER = b'K:'

ENC_KEY_DATA_SIZE = enmity_crypt.RSA_KEY_SIZE


KEY_SIZE = enmity_crypt.KEY_SIZE
NONCE_SIZE = enmity_crypt.NONCE_SIZE
MAC_TAG_SIZE = enmity_crypt.MAC_TAG_SIZE


MIN_BIG_FILE_SIZE = 0x100000
ONCE_ENC_MAX_FILE_SIZE = 0x3200000

ENC_BLOCK_SIZE1 = 0x32000
ENC_BLOCK_SIZE2 = 0x10000
ENC_BLOCK_SPACE2 = 0x640000


def decrypt_file(filename: str, priv_key_data: bytes, pass2: bool) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < ENC_KEY_DATA_SIZE:
            return False

        max_footer_size = ENC_KEY_DATA_SIZE
        if not pass2:
            max_footer_size += len(FULL_ENC_MARKER)

        # Read footer
        try:
            f.seek(-max_footer_size, 2)
        except OSError:
            f.seek(0)

        footer_data = f.read(max_footer_size)

        enc_key_data_pos = len(footer_data) - ENC_KEY_DATA_SIZE

        enc_key_data = footer_data[enc_key_data_pos:
                                   enc_key_data_pos + ENC_KEY_DATA_SIZE]

        # Decrypt key data (RSA OAEP)
        key_data = enmity_crypt.rsa_decrypt(enc_key_data, priv_key_data)
        if not key_data:
            print('RSA private key: Failed')
            return False

        print('RSA private key: OK')

        # Check full encryption marker
        full_enc = ((enc_key_data_pos == len(FULL_ENC_MARKER)) and
                    (footer_data[:enc_key_data_pos] == FULL_ENC_MARKER))

        footer_size = ENC_KEY_DATA_SIZE
        if full_enc:
            footer_size += len(FULL_ENC_MARKER)

        orig_file_size = file_size - footer_size
        print('footer size:', footer_size)
        print('original file size:', orig_file_size)

        key = key_data[:KEY_SIZE]
        nonce = key_data[KEY_SIZE : KEY_SIZE + NONCE_SIZE]

        if full_enc:

            # Full
            print('mode: full')

            f.seek(0)
            enc_data = f.read(orig_file_size)

            data = enmity_crypt.aes_gcm_decrypt(enc_data, key, nonce)
            if not data:
                return False

            f.seek(0)
            f.write(data)

            orig_file_size -= MAC_TAG_SIZE

        else:

            # Decrypt data (AES GCM)
            cipher = AES.new(key, AES.MODE_GCM, nonce)

            if pass2:
                # Spot (2nd pass)
                print('mode: spot (2nd pass)')

                pos = 0
                max_pos = orig_file_size - ENC_BLOCK_SPACE2

                while pos < max_pos:

                    f.seek(pos)
                    enc_data = f.read(ENC_BLOCK_SIZE2)
                    if enc_data == b'':
                        break

                    data = cipher.decrypt(enc_data)

                    f.seek(pos)
                    f.write(data)

                    pos += ENC_BLOCK_SIZE2 + ENC_BLOCK_SPACE2

            else:
                # Part
                print('mode: part')

                f.seek(0)
                enc_data = f.read(ENC_BLOCK_SIZE1)

                data = cipher.decrypt(enc_data)

                f.seek(0)
                f.write(data)

        # Remove footer
        f.truncate(orig_file_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./sprivkey.txt', 'rb') as f:
    priv_key_data = base64.b64decode(f.read())

new_filename = filename

if filename.endswith(RANSOM_EXT2):

    # Decrypt file (2nd pass)
    print('Decryption #2')

    new_filename = new_filename[:-len(RANSOM_EXT2)]
    shutil.copy(filename, new_filename)

    if not decrypt_file(new_filename, priv_key_data, True):
        os.remove(new_filename)
        print('Error: Failed to decrypt file (2nd pass)')
        sys.exit(1)

if new_filename.endswith(RANSOM_EXT1):

    # Decrypt file (1st pass)
    print('Decryption #1')

    new_filename2 = new_filename[:-len(RANSOM_EXT1)]
    pos = new_filename2.find(RANSOM_EXT_PREFIX)
    if pos >= 0:
        new_filename2 = new_filename2[:pos]
    else:
        new_filename2 += '.dec'
    shutil.copy(new_filename, new_filename2)

    if not decrypt_file(new_filename2, priv_key_data, False):
        os.remove(new_filename2)
        print('Error: Failed to decrypt file')
        sys.exit(1)
