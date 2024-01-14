# MIT License
#
# Copyright (c) 2024 Andrey Zhdanov (rivitna)
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

import io
import os
import shutil


RANSOM_EXT = 'demo'
ATTACKER_ID = b'\xBA\x0B\xAB\xC0\xFF\xEE'


DECRYPTOR_FILENAME = 'ph_decrypt.ex'

CFG_DATA_POSITIONS = [ 0xD510, 0xEC00 ]


RANSOM_EXT_OFFSET = 12
ATTACKER_ID_SIZE = 6
MAX_RANSOM_LEN = 260


#
# Main
#
new_decr_filename = './' + RANSOM_EXT + '_' + DECRYPTOR_FILENAME
shutil.copy('./' + DECRYPTOR_FILENAME, new_decr_filename)

ransom_ext = RANSOM_EXT[:MAX_RANSOM_LEN - 1].encode('UTF-16-LE')
ransom_ext += b'\0' * (2 * MAX_RANSOM_LEN - len(ransom_ext))

with io.open(new_decr_filename, 'rb+') as f:

    for pos in CFG_DATA_POSITIONS:
        # Write cfg data
        f.seek(pos)
        f.write(ATTACKER_ID[:ATTACKER_ID_SIZE])
        f.seek(pos + RANSOM_EXT_OFFSET)
        f.write(ransom_ext)
