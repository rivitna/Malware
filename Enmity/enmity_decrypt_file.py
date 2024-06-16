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


# Footer
MODE_MARKER_SIZE = 2
MODE1_MARKER = b'LB'
MODE2_MARKER = b'DB'

# "N:", "K:"
FILENAME_MARKER_SIZE = 2
MAX_FILENAME_SIZE = 260

ENC_KEY_DATA_SIZE = enmity_crypt.RSA_KEY_SIZE
MAX_FOOTER_SIZE = (FILENAME_MARKER_SIZE + MAX_FILENAME_SIZE +
                   ENC_KEY_DATA_SIZE + MODE_MARKER_SIZE)


KEY_SIZE = enmity_crypt.KEY_SIZE
NONCE_SIZE = enmity_crypt.NONCE_SIZE
MAC_TAG_SIZE = enmity_crypt.MAC_TAG_SIZE


MIN_BIG_FILE_SIZE0 = 0x100000
MIN_BIG_FILE_SIZE2 = 0x1400000
ENC_BLOCK_SIZE0 = 0x19999
ENC_BLOCK_SIZE2 = 0x100000
MAX_ENC_POS2 = 0x15000000000
ENC_BLOCK_STEP = 0xA00000


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < ENC_KEY_DATA_SIZE:
            return False

        # Read footer
        try:
            f.seek(-MAX_FOOTER_SIZE, 2)
        except OSError:
            f.seek(0)

        footer_data = f.read(MAX_FOOTER_SIZE)

        # Encryption mode
        mode = 0

        enc_key_data_pos = len(footer_data) - ENC_KEY_DATA_SIZE
        if footer_data.endswith(MODE1_MARKER):
            mode = 1
        elif footer_data.endswith(MODE2_MARKER):
            mode = 2

        if mode != 0:
            enc_key_data_pos -= MODE_MARKER_SIZE

        enc_key_data = footer_data[enc_key_data_pos:
                                   enc_key_data_pos + ENC_KEY_DATA_SIZE]

        # Decrypt encryption key (RSA OAEP)
        key_data = enmity_crypt.rsa_decrypt(enc_key_data, priv_key_data)
        if not key_data:
            return False

        # Find name marker ("N:", "K:")
        pos = footer_data.rfind(b':', 0, enc_key_data_pos)
        if ((pos <= 0) or
            ((footer_data[pos - 1] != 0x4B) and
             (footer_data[pos - 1] != 0x4E))):
            return False

        orig_filename = footer_data[pos + 1 : enc_key_data_pos].decode()

        orig_file_size = file_size - (len(footer_data) - (pos - 1))

        key = key_data[:KEY_SIZE]
        nonce = key_data[KEY_SIZE : KEY_SIZE + NONCE_SIZE]

        success = False

        if ((mode == 1) or
            ((mode == 0) and
             (orig_file_size < MIN_BIG_FILE_SIZE0 + MAC_TAG_SIZE))):

            # Small file
            f.seek(0)
            enc_data = f.read(orig_file_size)
            data = enmity_crypt.aes_gcm_decrypt(enc_data, key, nonce)
            if data:
                f.seek(0)
                f.write(data)

                orig_file_size -= MAC_TAG_SIZE
                success = True

        if (not success and
            ((mode == 2) or
             ((mode == 0) and (orig_file_size >= MIN_BIG_FILE_SIZE0)))):

            # Big file
            if mode == 2:
                block_size = ENC_BLOCK_SIZE2
                max_pos = min(orig_file_size - MIN_BIG_FILE_SIZE2,
                              MAX_ENC_POS2)
            else:
                block_size = ENC_BLOCK_SIZE0
                max_pos = orig_file_size - ENC_BLOCK_SIZE0

            # Decrypt data (AES GCM)
            cipher = AES.new(key, AES.MODE_GCM, nonce)

            pos = 0

            while pos <= max_pos:

                f.seek(pos)
                enc_data = f.read(block_size)
                if enc_data == b'':
                    break

                data = cipher.decrypt(enc_data)

                f.seek(pos)
                f.write(data)

                pos += ENC_BLOCK_STEP

            success = True

        if not success:
            return False

        # Remove footer
        f.truncate(orig_file_size)

    # Restore original file name
    dest_filename = os.path.join(os.path.abspath(os.path.dirname(filename)),
                                 orig_filename)
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

with io.open('./sprivkey.txt', 'rb') as f:
    priv_key_data = base64.b64decode(f.read())

# Copy file
new_filename = filename + '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
