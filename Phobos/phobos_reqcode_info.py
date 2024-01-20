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
import base64
import binascii


RSA_KEY_SIZE = 128

ENC_KEY_ENTRY_SIZE = 4 + RSA_KEY_SIZE

ENC_KEY_DATA_XOR = 0x3345F0AC


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read request code (Phobos decryptor)
with io.open(filename, 'rb') as f:
    enc_key_data = base64.b64decode(f.read())

num_keys, crc = struct.unpack_from('<2L', enc_key_data, 0)
num_keys ^= ENC_KEY_DATA_XOR
crc ^= ENC_KEY_DATA_XOR
print('keys:', num_keys)
print('crc32: %08X' % crc)

enc_key_data = enc_key_data[8 : 8 + num_keys * ENC_KEY_ENTRY_SIZE]

# Check encrypted key data CRC32
if crc != binascii.crc32(enc_key_data):
    print('Error: Invalid key data.')
    sys.exit(1)

num_dec_keys = 0

key_data = b''

for i in range(num_keys):

    num_files, = struct.unpack_from('<L', enc_key_data,
                                    i * ENC_KEY_ENTRY_SIZE)
    num_files ^= ENC_KEY_DATA_XOR
    print('key #%d files: %d' % (i, num_files))
