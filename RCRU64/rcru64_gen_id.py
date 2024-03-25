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

import os


VICTIM_ID_LEN = 5
RANSOM_EXT_LEN = 3


RND_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDFGHIJKLMNOPQRSTUVWXYZ'
RND_CHAR_MAX_INDEX = 50


# Pseudorandom number generator (PRNG) Mersenne Twister
twister = None


MASK32 = 0xFFFFFFFF

add32 = lambda x, y: (x + y) & MASK32

mul32 = lambda x, y: (x * y) & MASK32


def mersenne_init(seed: int) -> list:
    """Init pseudorandom number generator (PRNG) Mersenne Twister"""

    twister = 624 * [0]
    twister[0] = seed & MASK32

    for i in range(1, 624):
        twister[i] = add32(mul32(0x6C078965,
                                 twister[i - 1] ^ (twister[i - 1] >> 30)),
                           i)

    return twister


def mersenne_gen(twister: list) -> None:
    """Mersenne Twister.
    Generate (fill) the array of 624 uints with untempered values"""

    for i in range(624):
        v = (twister[i] & 0x80000000) + (twister[(i + 1) % 624] & 0x7FFFFFFF)
        twister[i] = twister[(i + 397) % 624] ^ (v >> 1)
        if (v & 1) != 0:
            twister[i] ^= 0x9908B0DF


def mersenne_get(twister: list, index: int) -> int:
    """Mersenne Twister.
    Return a single number from the array based upon the current index,
    tempering it in the process"""

    if index == 0:
        mersenne_gen(twister)

    v = twister[index]
    v ^= v >> 11
    v ^= (v << 7) & 0x9D2C5680
    v ^= (v << 15) & 0xEFC60000
    v ^= v >> 18

    index = (index + 1) % 624

    return v, index


def gen_random_str(str_len: int) -> str:
    """Generate random string"""

    global twister, twister_index

    if not twister:
        # Init pseudorandom number generator (PRNG) Mersenne Twister
        seed = int.from_bytes(os.urandom(4), byteorder='little')
        twister = mersenne_init(seed)
        twister_index = 0

    rnd_str = ''

    for i in range(str_len):

        v, twister_index = mersenne_get(twister, twister_index)
        rnd_str += RND_CHARS[v % (RND_CHAR_MAX_INDEX + 1)]

    return rnd_str.upper()


#
# Main
#
victim_id = gen_random_str(VICTIM_ID_LEN)
ransom_ext = '.' + gen_random_str(RANSOM_EXT_LEN)

print('victim ID: ', victim_id)
print('ransom ext:', ransom_ext)
