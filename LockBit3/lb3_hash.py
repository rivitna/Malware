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

MASK32 = 0xFFFFFFFF

ror32 = lambda v, s: ((v & MASK32) >> s) | ((v << (32 - s)) & MASK32)


def get_wide_str_hash(s, n=0):
    """Get Unicode-string hash"""

    for ch in s.encode():

        m = ch
        if (m >= 0x41) and (m <= 0x5A):
            m |= 0x20
        n = m + ror32(n, 13)

    return ror32(n, 13)


def get_str_hash(s, n=0):
    """Get string hash"""

    for ch in s:

        n = ord(ch) + ror32(n, 13)

    return ror32(n, 13)


def get_api_func_name_hash(lib_name, fnc_name):
    """Get API function name hash"""

    return get_str_hash(fnc_name, get_wide_str_hash(lib_name, 0))


if __name__ == '__main__':
    import io

    with io.open('./api_names.txt', 'rt') as f:
        func_names = f.read().splitlines()

    with io.open('./api_hashes.txt', 'wt') as f:
        for name in func_names:
            name = name.strip()
            if (name == ''):
                continue
            names = name.split('\t')
            h = get_api_func_name_hash(names[0], names[1])
            f.write('%08X\t%s\n' % (h, names[1]))
