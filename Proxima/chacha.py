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

NONCE_SIZE1 = 8
NONCE_SIZE2 = 12
XNONCE_SIZE = 24
HNONCE_SIZE = 16

BLOCK_SIZE = 64


CONSTANTS = b'expand 32-byte k'


MASK32 = 0xFFFFFFFF

_add32 = lambda x, y: (x + y) & MASK32

_xor32 = lambda x, y: (x ^ y) & MASK32

_rol32 = lambda v, s: ((v << s) & MASK32) | ((v & MASK32) >> (32 - s))


def _quarter_round(x, a, b, c, d):
    """Perform a ChaCha quarter round"""

    x[a] = _add32(x[a], x[b])
    x[d] = _rol32(_xor32(x[d], x[a]), 16)

    x[c] = _add32(x[c], x[d])
    x[b] = _rol32(_xor32(x[b], x[c]), 12)

    x[a] = _add32(x[a], x[b])
    x[d] = _rol32(_xor32(x[d], x[a]), 8)

    x[c] = _add32(x[c], x[d])
    x[b] = _rol32(_xor32(x[b], x[c]), 7)


def _double_round(x):
    """Perform two rounds of ChaCha cipher"""

    _quarter_round(x, 0, 4, 8, 12)
    _quarter_round(x, 1, 5, 9, 13)
    _quarter_round(x, 2, 6, 10, 14)
    _quarter_round(x, 3, 7, 11, 15)
    _quarter_round(x, 0, 5, 10, 15)
    _quarter_round(x, 1, 6, 11, 12)
    _quarter_round(x, 2, 7, 8, 13)
    _quarter_round(x, 3, 4, 9, 14)


def _words_to_bytes(state):
    """Convert state to little endian bytestream"""

    return struct.pack('<16L', *state)


def _bytes_to_words(data):
    """Convert a bytearray to array of word sized ints"""

    return list(struct.unpack('<' + str(len(data) // 4) + 'L', data))


def hchacha(key, nonce):
    """Pure python implementation of HChaCha"""

    if len(key) != KEY_SIZE:
        raise ValueError('Key must be 32 bytes long')

    if len(nonce) != HNONCE_SIZE:
        raise ValueError('Nonce must be 16 bytes long')

    k = _bytes_to_words(key)
    n = _bytes_to_words(nonce)

    state = _bytes_to_words(CONSTANTS) + k + n

    for _ in range(0, 10):
        # Perform two rounds of ChaCha cipher
        _double_round(state)

    res = state[0:4] + state[12:16]
    return struct.pack('<8L', *res)


class ChaCha(object):

    """Pure python implementation of ChaCha cipher"""

    @staticmethod
    def chacha_core(state, rounds):
        """Generate a state of a single block"""

        working_state = state[:]

        for _ in range(0, rounds // 2):
            # Perform two rounds of ChaCha cipher
            _double_round(working_state)

        for i in range(len(working_state)):
            working_state[i] = _add32(state[i], working_state[i])

        return _words_to_bytes(working_state)


    def __init__(self, key, nonce=NONCE_SIZE2 * b'\0', counter=0, rounds=20):
        """Set the initial state for the ChaCha cipher"""

        if len(key) != KEY_SIZE:
            raise ValueError('Key must be 32 bytes long')

        if len(nonce) == XNONCE_SIZE:
            # XChaCha20
            key = hchacha(key, nonce[:HNONCE_SIZE])
            nonce = b'\0\0\0\0' + nonce[HNONCE_SIZE:]

        if len(nonce) == NONCE_SIZE1:
            # ChaCha20
            nonce = b'\0\0\0\0' + nonce

        elif len(nonce) != NONCE_SIZE2:
            raise ValueError('Nonce must be 8/12 or 24 bytes long (XChaCha20)')

        self.rounds = rounds
        self.block_pos = 0

        # Convert bytearray key and nonce to little endian 32 bit unsigned ints
        key = _bytes_to_words(key)
        nonce = _bytes_to_words(nonce)
        self.state = _bytes_to_words(CONSTANTS) + key + [counter] + nonce


    def _encrypt_block(self, block):
        """Encrypt a single block"""

        # Receive the key stream for current block
        key_stream = ChaCha.chacha_core(self.state, self.rounds)

        block_pos = self.block_pos

        block = bytearray(block)
        for i in range(len(block)):
            block[i] ^= key_stream[i + block_pos]

        block_pos += len(block)

        if block_pos >= BLOCK_SIZE:
            block_pos = 0
            # Increase block counter
            self.state[12] = _add32(self.state[12], 1)

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
