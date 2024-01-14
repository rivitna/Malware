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

CRC32_POLY = 0xEDB88320


crc32_table = None


def get_crc32_table():
    table = list(range(256))
    for i in range(256):
        x = i
        for j in range(8):
            if x & 1:
                x = (x >> 1) ^ CRC32_POLY
            else:
                x >>= 1
        table[i] = x
    return table


def crc32(data, crc = 0):
    global crc32_table
    if crc32_table is None:
        crc32_table = get_crc32_table()
    for b in data:
        crc = crc32_table[(crc & 0xFF) ^ b] ^ (crc >> 8)
    return crc


if __name__ == '__main__':
    import sys
    import io

    if len(sys.argv) != 2:
        print('Usage: '+ sys.argv[0] + ' data_file')
        sys.exit(0)

    file_name = sys.argv[1]
    with io.open(file_name, 'rb') as f:
        data = f.read()

    crc = crc32(data)

    print(hex(crc))
