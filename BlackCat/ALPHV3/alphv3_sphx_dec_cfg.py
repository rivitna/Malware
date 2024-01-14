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
import alphv3_sphx_crypt


MAX_CFG_SIZE = 0x40000


#
# Main
#
if len(sys.argv) != 3:
    print('Usage:', os.path.basename(sys.argv[0]), 'keyfile cfgfile')
    sys.exit(0)

key_filename = sys.argv[1]
cfg_filename = sys.argv[2]

with io.open(key_filename, 'rb') as f:
    key = f.read(alphv3_sphx_crypt.AES_KEY_SIZE)

with io.open(cfg_filename, 'rb') as f:

    cfg_size = int.from_bytes(f.read(4), byteorder='big', signed=False)
    if not (0 < cfg_size < MAX_CFG_SIZE - 4):
        raise Exception('Invalid cfg data size')

    print('cfg data size: ' + str(cfg_size))
    enc_cfgdata = f.read(cfg_size)

cfgdata = alphv3_sphx_crypt.aes_decrypt(enc_cfgdata, key)

new_filename = cfg_filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(cfgdata)
