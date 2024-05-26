# MIT License
#
# Copyright (c) 2022-2024 Andrey Zhdanov (rivitna)
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


KEY_SIZE = 32
NONCE_SIZE = 8
XNONCE_SIZE = 24
HNONCE_SIZE = 16

BLOCK_SIZE = 64


CONSTANTS = b'expand 32-byte k'


MASK32 = 0xFFFFFFFF

_add32 = lambda x, y: (x + y) & MASK32

_rol32 = lambda v, s: ((v << s) & MASK32) | ((v & MASK32) >> (32 - s))


def _quarter_round(x, a, b, c, d):
    """Perform a Salsa quarter round"""

    x[a] ^= _rol32(_add32(x[d], x[c]), 7)
    x[b] ^= _rol32(_add32(x[a], x[d]), 9)
    x[c] ^= _rol32(_add32(x[b], x[a]), 13)
    x[d] ^= _rol32(_add32(x[c], x[b]), 18)


def _double_round(x):
    """Perform two rounds of Salsa cipher"""

    _quarter_round(x,  4,  8, 12,  0)
    _quarter_round(x,  9, 13,  1,  5)
    _quarter_round(x, 14,  2,  6, 10)
    _quarter_round(x,  3,  7, 11, 15)
    _quarter_round(x,  1,  2,  3,  0)
    _quarter_round(x,  6,  7,  4,  5)
    _quarter_round(x, 11,  8,  9, 10)
    _quarter_round(x, 12, 13, 14, 15)


def _words_to_bytes(state):
    """Convert state to little endian bytestream"""

    return struct.pack('<16L', *state)


def _bytes_to_words(data):
    """Convert a bytearray to array of word sized ints"""

    return list(struct.unpack('<' + str(len(data) // 4) + 'L', data))


def hsalsa(key, nonce):
    """Pure python implementation of HSalsa"""

    if len(key) != KEY_SIZE:
        raise ValueError('Key must be 32 bytes long')

    if len(nonce) != HNONCE_SIZE:
        raise ValueError('Nonce must be 16 bytes long')

    c = _bytes_to_words(CONSTANTS)
    k = _bytes_to_words(key)
    n = _bytes_to_words(nonce)

    state = [c[0], k[0], k[1], k[2],
             k[3], c[1], n[0], n[1],
             n[2], n[3], c[2], k[4],
             k[5], k[6], k[7], c[3]]

    for _ in range(0, 10):
        # Perform two rounds of Salsa cipher
        _double_round(state)

    res = [state[0], state[5], state[10], state[15]] + state[6:10]
    return struct.pack('<8L', *res)


class Salsa(object):

    """Pure python implementation of Salsa cipher"""

    @staticmethod
    def salsa_core(state, rounds):
        """Generate a state of a single block"""

        working_state = state[:]

        for _ in range(0, rounds // 2):
            # Perform two rounds of Salsa cipher
            _double_round(working_state)

        for i in range(len(working_state)):
            working_state[i] = _add32(state[i], working_state[i])

        return _words_to_bytes(working_state)


    @staticmethod
    def init_state(key, nonce=NONCE_SIZE * b'\0', counter=0):
        """Get the initial state for the Salsa cipher"""

        if len(key) != KEY_SIZE:
            raise ValueError('Key must be 32 bytes long')

        if len(nonce) == XNONCE_SIZE:
            # XSalsa20
            key = hsalsa(key, nonce[:HNONCE_SIZE])
            nonce = nonce[HNONCE_SIZE:]

        elif len(nonce) != NONCE_SIZE:
            raise ValueError('Nonce must be 8 or 24 bytes long (XSalsa20)')

        # Convert bytearray key and nonce to little endian 32 bit unsigned ints
        c = _bytes_to_words(CONSTANTS)
        k = _bytes_to_words(key)
        n = _bytes_to_words(nonce)
        c0 = counter & MASK32
        c1 = (counter >> 32) & MASK32

        return [c[0], k[0], k[1], k[2],
                k[3], c[1], n[0], n[1],
                c0,   c1,   c[2], k[4],
                k[5], k[6], k[7], c[3]]


    def __init__(self, init_state, rounds=20):
        """Set the initial state for the Salsa cipher"""

        if isinstance(init_state, (bytes, bytearray)):

            if len(init_state) != 64:
                raise ValueError('Initial state must be 64 byte long')

            init_state = _bytes_to_words(init_state)

        elif isinstance(init_state, list):

            if len(init_state) != 16:
                raise ValueError('Initial state must be 16 unsigned ints')

        else:
            raise ValueError('Initial state must be bytes, bytearray or list')

        self.rounds = rounds
        self.block_pos = 0
        self.state = init_state


    def _encrypt_block(self, block):
        """Encrypt a single block"""

        # Receive the key stream for current block
        key_stream = Salsa.salsa_core(self.state, self.rounds)

        block_pos = self.block_pos

        block = bytearray(block)
        for i in range(len(block)):
            block[i] ^= key_stream[i + block_pos]

        block_pos += len(block)

        if block_pos >= BLOCK_SIZE:
            block_pos = 0
            # Increase block counter
            c = (self.state[8] | (self.state[9] << 32)) + 1
            self.state[8] = c & MASK32
            self.state[9] = (c >> 32) & MASK32

        self.block_pos = block_pos

        return bytes(block)


    def encrypt(self, plaintext):
        """Encrypt the data"""

        encrypted_message = b''

        pos = 0

        if self.block_pos != 0:
            # Encrypt the first unaligned block
            block_len = min(BLOCK_SIZE - self.block_pos, len(plaintext))
            encrypted_message += self._encrypt_block(plaintext[:block_len])
            pos = block_len

        # Encrypt blocks
        for block in (plaintext[i : i + BLOCK_SIZE] for i
                      in range(pos, len(plaintext), BLOCK_SIZE)):
            encrypted_message += self._encrypt_block(block)

        return encrypted_message


    def decrypt(self, ciphertext):
        """Decrypt the data"""

        return self.encrypt(ciphertext)
