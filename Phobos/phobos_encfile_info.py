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
import struct
import binascii


# Metadata
METADATA_SIZE = 0xB2

AES_IV_POS = 0x14
AES_IV_SIZE = 16
PADDING_SIZE_POS = 0x24
ENC_KEY_DATA_POS = 0x28
RSA_KEY_SIZE = 128
FOOTER_SIZE_POS = 0xA8
ATTACKER_ID_POS = 0xAC
ATTACKER_ID_SIZE = 6


def print_encfile_info(filename: str) -> bool:
    """Get encrypted file info"""

    with io.open(filename, 'rb') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Attacker ID
        attacker_id = metadata[ATTACKER_ID_POS :
                               ATTACKER_ID_POS + ATTACKER_ID_SIZE]

        # Encrypted key data
        enc_key_data = metadata[ENC_KEY_DATA_POS :
                                ENC_KEY_DATA_POS + RSA_KEY_SIZE]

        # Footer size including metadata
        footer_size, = struct.unpack_from('<L', metadata, FOOTER_SIZE_POS)
        if footer_size <= METADATA_SIZE:
            return False

        # Read end block with encryption info
        endblock_size = footer_size - METADATA_SIZE
        if (endblock_size & 0xF) != 0:
            return False

        try:
            f.seek(-footer_size, 2)
        except OSError:
            return False
        
        enc_endblock_data = f.read(endblock_size)

        # AES IV
        aes_iv = metadata[AES_IV_POS : AES_IV_POS + AES_IV_SIZE]
        # Padding size
        padding_size, = struct.unpack_from('<L', metadata, PADDING_SIZE_POS)

    print('attacker id:', binascii.hexlify(attacker_id).decode().upper())
    print('footer size: %08X' % footer_size)
    print('end block size: %08X' % endblock_size)
    print('padding size: %d' % padding_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Get encrypted file info
if not print_encfile_info(filename):
    print('Error: file not encrypted or damaged')
    sys.exit(1)
