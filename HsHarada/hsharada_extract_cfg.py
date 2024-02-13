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
import struct
import zlib


def check_ldsfld(data, pos, field):
    """Check IL instruction ldsfld"""

    # ldsfld <field>
    if (pos + 5 > len(data)) or (data[pos] != 0x7E):
        return False
    f, = struct.unpack_from('<L', data, pos + 1)
    return (f == field)


def find_config_data(data):
    """Find configuration data"""

    pos = 0

    while True:

        # Find newarr <etype>
        pos = data.find(0x8D, pos)
        if (pos < 0) or (pos + 15 > len(data)):
            return None, None

        # Check etype
        if ((data[pos + 1] & 0xF0 == 0x20) and
            (data[pos + 2] == 0) and
            (data[pos + 3] == 0) and
            (data[pos + 4] == 1) and
            # Check if previous instruction is ldarg.0 or ldarg 0
            (((pos >= 1) and (data[pos - 1] == 2)) or
             ((pos >= 4) and
              (data[pos - 4] == 0xFE) and
              (data[pos - 3] == 9) and
              (data[pos - 2] == 0) and
              (data[pos - 1] == 0))) and
            # stsfld <field>
            (data[pos + 5] == 0x80)):
                cfg_data_token, = struct.unpack_from('<L', data, pos + 6)
                # ldsfld <field>
                if check_ldsfld(data, pos + 10, cfg_data_token):
                    return (pos + 10), cfg_data_token

        pos += 1


def parse_ldc_i4(data, pos):
    """Parse IL instructions ldc.i4, ldc.i4.s, ldc.i4.n"""

    if pos < len(data):
        # ldc.i4
        if data[pos] == 0x20:
            if pos + 5 <= len(data):
                val, = struct.unpack_from('<L', data, pos + 1)
                return val, 5
        # ldc.i4.s
        elif data[pos] == 0x1F:
            if pos + 2 <= len(data):
                val = data[pos + 1]
                return val, 2
        # ldc.i4.n
        elif (0x16 <= data[pos] <= 0x1E):
            val = data[pos] - 0x16
            return val, 1

    return None, 0


def decompress_data(data):
    """Decompress data"""

    decompress = zlib.decompressobj(-zlib.MAX_WBITS)
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated


#
# Main
#
if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    file_data = f.read()

# Find configuration data
pos, cfg_data_token = find_config_data(file_data)

if pos is None:
    print('Error: Configuration data not found.')
    sys.exit(1)

print('cfg data position: %08X' % pos)
print('cfg data token: 0x%08X' % cfg_data_token)

# Skip ldsfld <field>
pos += 5

cfg_data_dict = {}

# Parse IL code
while True:

    # ldc.i4
    idx, inst_size = parse_ldc_i4(file_data, pos)
    if (idx is None) or (cfg_data_dict.get(idx) is not None):
        break
    pos += inst_size

    # ldc.i4
    val, inst_size = parse_ldc_i4(file_data, pos)
    if (val is None) or (val > 255):
        break
    pos += inst_size

    # stelem.i1
    if (pos >= len(file_data)) or (file_data[pos] != 0x9C):
        break
    pos += 1

    # skip nop
    if (pos < len(file_data)) and (file_data[pos] == 0):
        pos += 1

    cfg_data_dict[idx] = val

    # ldsfld <field>
    if not check_ldsfld(file_data, pos, cfg_data_token):
        break
    pos += 5

pack_cfg_data_size = max(cfg_data_dict.keys()) + 1
print('compressed cfg data size: %d' % pack_cfg_data_size)

pack_cfg_data = b''
for i in range(pack_cfg_data_size):
    val = cfg_data_dict.get(i)
    if val is None:
        print('Error: Failed to get configuration data.')
        sys.exit(1)
    pack_cfg_data += bytes([val])

cfg_data = decompress_data(pack_cfg_data)
print('cfg data size: %d' % len(cfg_data))

cfg_filename = filename + '.cfg'
with io.open(cfg_filename, 'wb') as f:
    f.write(cfg_data)
