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


CHUNK_MARKER = b'$'


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./rsa_privkey1.txt', 'rb') as f:
    priv_key_data = base64.b64decode(f.read())

with io.open(filename, 'rb') as f:
    enc_data = f.read()

enc_data_chunks = sorted(list(filter(None, enc_data.split(CHUNK_MARKER))),
                         key = lambda chunk: chunk[0])

data = b''

for i, enc_data_chunk in enumerate(enc_data_chunks):

    # Base64 decode and RSA decrypt chunk data
    data_chunk = rcru64_crypt.b64decode_and_rsa_decrypt(enc_data_chunk[1:],
                                                        priv_key_data)
    if data_chunk is None:
        print('Error: Failed to decrypt data chunk #%d' % i)
        break

    data += data_chunk

new_filename = filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(data)
