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

import struct


RSA_KEY_SIZE = 128
RSA_E = 0x10001

SALSA_KEY_DATA_SIZE = 64


MASK32 = 0xFFFFFFFF

add32 = lambda x, y: (x + y) & MASK32

rol32 = lambda v, s: ((v << s) & MASK32) | ((v & MASK32) >> (32 - s))


class Salsa(object):

    """Pure python implementation of Salsa cipher"""

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """Perform a Salsa round"""

        x[a] ^= rol32(add32(x[d], x[c]), 7)
        x[b] ^= rol32(add32(x[a], x[d]), 9)
        x[c] ^= rol32(add32(x[b], x[a]), 13)
        x[d] ^= rol32(add32(x[c], x[b]), 18)


    @staticmethod
    def salsa_core(state, rounds):
        """Generate a state of a single block"""

        working_state = state[:]

        for _ in range(0, rounds // 2):

            # Perform round of Salsa cipher
            Salsa.quarter_round(working_state,  4,  8, 12,  0)
            Salsa.quarter_round(working_state,  9, 13,  1,  5)
            Salsa.quarter_round(working_state, 14,  2,  6, 10)
            Salsa.quarter_round(working_state,  3,  7, 11, 15)
            Salsa.quarter_round(working_state,  1,  2,  3,  0)
            Salsa.quarter_round(working_state,  6,  7,  4,  5)
            Salsa.quarter_round(working_state, 11,  8,  9, 10)
            Salsa.quarter_round(working_state, 12, 13, 14, 15)

        for i in range(len(working_state)):
            working_state[i] = add32(state[i], working_state[i])

        return Salsa.words_to_bytes(working_state)


    @staticmethod
    def words_to_bytes(state):
        """Convert state to little endian bytestream"""

        return struct.pack('<16L', *state)


    @staticmethod
    def _bytes_to_words(data):
        """Convert a bytearray to array of word sized ints"""

        return list(struct.unpack('<' + str(len(data) // 4) + 'L', data))


    def __init__(self, init_state, rounds=20):
        """Set the initial state for the Salsa cipher"""

        if len(init_state) != 64:
            raise ValueError('Initial state must be 64 byte long')

        self.rounds = rounds
        self.pos = 0
        self.state = Salsa._bytes_to_words(init_state)


    def _encrypt_block(self, block, block_ofs=0):
        """Encrypt a single block"""

        # Receive the key stream for current block
        key_stream = Salsa.salsa_core(self.state, self.rounds)

        block = bytearray(block)
        for i in range(len(block)):
            block[i] ^= key_stream[i + block_ofs]

        self.pos += len(block)

        if self.pos & 0x3F == 0:
            # Increase block counter
            c = (self.state[8] | (self.state[9] << 32)) + 1
            self.state[8] = c & MASK32
            self.state[9] = (c >> 32) & MASK32

        return bytes(block)


    def encrypt(self, plaintext):
        """Encrypt the data"""

        encrypted_message = b''

        pos = 0

        if self.pos & 0x3F != 0:
            # Encrypt the first unaligned block
            block_ofs = self.pos & 0x3F
            block_len = min(64 - block_ofs, len(plaintext))
            encrypted_message += self._encrypt_block(plaintext[:block_len],
                                                     block_ofs)
            pos = block_len

        # Encrypt blocks
        for block in (plaintext[i : i + 64] for i
                      in range(pos, len(plaintext), 64)):
            encrypted_message += self._encrypt_block(block)

        return encrypted_message


    def decrypt(self, ciphertext):
        """Decrypt the data"""

        return self.encrypt(ciphertext)


def rsa_encrypt(pub_key_data, data):
    """RSA encrypt data"""

    n = int.from_bytes(pub_key_data[:RSA_KEY_SIZE], byteorder='little')
    x = int.from_bytes(data, 'little')
    res = int(pow(x, RSA_E, n))
    return res.to_bytes(RSA_KEY_SIZE, byteorder='little')


def rsa_decrypt(priv_key_data, enc_data):
    """RSA decrypt data"""

    d = int.from_bytes(priv_key_data[:RSA_KEY_SIZE], byteorder='little')
    n = int.from_bytes(priv_key_data[RSA_KEY_SIZE:], byteorder='little')
    x = int.from_bytes(enc_data, 'little')
    res = int(pow(x, d, n))
    return res.to_bytes(RSA_KEY_SIZE, byteorder='little')


def salsa_encrypt(key_data, data):
    """Salsa20 encrypt data"""

    cipher = Salsa(key_data)
    return cipher.encrypt(data)


def salsa_decrypt(key_data, enc_data):
    """Salsa20 decrypt data"""

    cipher = Salsa(key_data)
    return cipher.decrypt(enc_data)


if __name__ == '__main__':
    import sys
    import io
    import os

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        exit(0)

    filename = sys.argv[1]

    with io.open(filename, 'rb') as f:
        enc_data = f.read()

    with io.open('./key.bin', 'rb') as f:
        key_data = f.read()

    data = salsa_decrypt(key_data, enc_data)

    new_filename = filename + '.dec'
    with io.open(new_filename, 'wb') as f:
        f.write(data)
