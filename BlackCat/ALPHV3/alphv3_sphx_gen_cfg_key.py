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
import os
import io
import struct
import random
import alphv3_sphx_util
import alphv3_sphx_hash


KEY_LEN = 16
NOISE_MIN_LEN = 1
NOISE_MAX_LEN = 10


def gen_key_string(key: bytes) -> str:
    """Generate string for encryption key"""

    crc = alphv3_sphx_hash.crc16(key)
    crc = alphv3_sphx_hash.crc16_finish(crc)

    noise_len = random.randrange(NOISE_MIN_LEN, NOISE_MAX_LEN + 1)
    noise = os.urandom(noise_len)

    data = (key + alphv3_sphx_util.get_data_blob(noise) +
            crc.to_bytes(2, byteorder='little'))

    return alphv3_sphx_util.encode_data(data)


#
# Main
#
num_strings = 1

if len(sys.argv) > 1:
    n = int(sys.argv[1])
    if n > num_strings:
        num_strings = n

try:
    with io.open('./cfg_key.bin', 'rb') as f:
        key = f.read(KEY_LEN)
    if len(key) != KEY_LEN:
        raise ValueError('Invalid key length')

except FileNotFoundError:

    key = os.urandom(KEY_LEN)
    with io.open('./cfg_key.bin', 'wb') as f:
        f.write(key)
    print('The encryption key has been generated and saved')

for _ in range(num_strings):

    # Generate string for encryption key
    s = gen_key_string(key)
    print(s)
