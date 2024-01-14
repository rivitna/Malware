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
import alphv3_sphx_util
import alphv3_sphx_hash


# ConfigKeyDump struct (key, noise, crc)
KEY_LEN = 16
MIN_CFG_KEY_DUMP_LEN = KEY_LEN + 8 + 2


def extract_cfg_key_from_string(s: str) -> bytes:
    """Extract cfg encryption key from string"""

    data = alphv3_sphx_util.decode_data(s)
    if len(data) < MIN_CFG_KEY_DUMP_LEN:
        return None

    # Skip noise
    noise_size, = struct.unpack_from('<Q', data, KEY_LEN)
    if noise_size > len(data) - MIN_CFG_KEY_DUMP_LEN:
        return None

    key = data[:KEY_LEN]

    # Compare CRC
    crc, = struct.unpack_from('<H', data, KEY_LEN + 8 + noise_size)
    crc2 = alphv3_sphx_hash.crc16(key)
    crc2 = alphv3_sphx_hash.crc16_finish(crc2)
    if crc != crc2:
        return None

    return key


def extract_cfg_key_from_args(args: list[str]) -> (bytes, str):
    """Extract cfg encryption key from command line arguments"""

    s = ''

    for arg in args:
        for c in arg:
            if (c == ' ') or (c == '-'):
                continue
            s += c
            # Extract cfg encryption key from string
            key = extract_cfg_key_from_string(s)
            if key is not None:
                return key, s

    return None


#
# Main
#
if len(sys.argv) < 2:
    print('Usage:', os.path.basename(sys.argv[0]), '<alphv command line>')
    sys.exit(0)

# Extract cfg encryption key from command line arguments
key_info = extract_cfg_key_from_args(sys.argv[1:])
if key_info is None:
    print('Error: Failed to extract encryption key.')
    sys.exit(1)

print('Key argument string: \"%s\"' % key_info[1])

with io.open('./cfg_key.bin', 'wb') as f:
    f.write(key_info[0])
