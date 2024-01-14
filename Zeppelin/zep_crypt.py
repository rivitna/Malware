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

import math
import struct
from Crypto.Cipher import AES


DATA_PREFIX = b'666'

AES_KEY_LEN = 32
AES_IV_LEN = 16
AES_BLOCK_LEN = 16


def aes_encrypt(data, key, iv):
    """AES encrypt data"""
    data = DATA_PREFIX + data
    data_size = len(data)
    if data_size & 0xF:
        data += (AES_BLOCK_LEN - (data_size & 0xF)) * b'\0'
    cypher = AES.new(key, AES.MODE_CBC, iv)
    enc_data = cypher.encrypt(data)
    return (struct.pack('<QQ', len(enc_data), data_size) + enc_data)


def aes_decrypt(enc_data, key, iv):
    """AES decrypt data"""
    enc_size, data_size = struct.unpack_from('<QQ', enc_data, 0)
    cypher = AES.new(key, AES.MODE_CBC, iv)
    data = cypher.decrypt(enc_data[16 : 16 + enc_size])
    data = data[:data_size]
    if data.startswith(DATA_PREFIX):
        data = data[len(DATA_PREFIX):]
    return data


def rsa_encrypt(rsa_n, rsa_e, data):
    """RSA encrypt data"""
    return int(pow(int.from_bytes(data, 'big'), rsa_e, rsa_n))


def rsa_decrypt(rsa_n, rsa_d, enc_n):
    """RSA decrypt data"""
    n = int(pow(enc_n, rsa_d, rsa_n))
    data_size = (n.bit_length() + 7) // 8
    return n.to_bytes(data_size, byteorder='big')


def rsa_encrypt_big(rsa_n, rsa_e, data):
    """RSA encrypt data by blocks"""

    digit_count = int(math.log10(rsa_n)) + 1
    block_len = math.trunc(digit_count / math.log10(256))

    enc_data = ''

    for block in (data[i : i + block_len]
                  for i in range(0, len(data), block_len)):
        enc_n = rsa_encrypt(rsa_n, rsa_e, block)
        s = str(enc_n)
        if len(s) < digit_count:
            enc_data += (digit_count - len(s)) * '0'
        enc_data += s

    return enc_data


if __name__ == '__main__':
    import sys
    import io

    if ((len(sys.argv) != 3) or
        (sys.argv[1] != 'rsa' and sys.argv[1] != 'aes')):
        print('Usage: '+ sys.argv[0] + 'aes|rsa filename')
        exit(0)

    filename = sys.argv[2]
    with io.open(filename, 'rb') as f:
        data = f.read()

    new_filename = filename + '.enc'

    if sys.argv[1] == 'rsa':

        with io.open('./rsa_n.txt', 'rt') as f:
            rsa_n = int(f.read(), 16)

        with io.open('./rsa_e.txt', 'rt') as f:
            rsa_e = int(f.read(), 16)

        enc_data = rsa_encrypt_big(rsa_n, rsa_e, data)

        with io.open(new_filename, 'wt') as f:
            f.write(enc_data)

    else:

        with io.open('./aes_keydata.bin', 'rb') as f:
            key_data = f.read(AES_KEY_LEN + AES_IV_LEN)

        enc_data = aes_encrypt(data, key_data[:AES_KEY_LEN],
                               key_data[AES_KEY_LEN:])

        with io.open(new_filename, 'wb') as f:
            f.write(enc_data)

    print('Done!')
