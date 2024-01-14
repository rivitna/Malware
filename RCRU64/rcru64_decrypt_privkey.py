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
import base64
import rcru64_crypt


ENC_PART_MARKER1 = b'L8a'
ENC_PART_MARKER2 = b'J7x23'


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./rsa_privkey2.txt', 'rb') as f:
    priv_key_data = base64.b64decode(f.read())

with io.open(filename, 'rb') as f:
    enc_data = f.read()

pos = enc_data.find(ENC_PART_MARKER1)
if pos < 0:
    print('Error: Invalid encrypted private key data')
    sys.exit(1)

pos += len(ENC_PART_MARKER1)
enc_data = enc_data[pos:]
key_parts = enc_data.split(ENC_PART_MARKER2, 2)

# Base64 decode and RSA decrypt private key part #0
key_part0 = rcru64_crypt.b64decode_and_rsa_decrypt(key_parts[0],
                                                   priv_key_data)
if key_part0 is None:
    print('Error: Failed to decrypt private key part #0')
    sys.exit(1)

data = key_part0 + key_parts[1]

new_filename = filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(data)
