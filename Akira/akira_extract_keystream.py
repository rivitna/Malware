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
import struct


# RSA
RSA_KEY_SIZE = 512

METADATA_SIZE = RSA_KEY_SIZE + 22


ENC_BLOCK_SIZE = 0x10000


def extract_keystream(enc_filename: str, orig_filename: str) -> bool:
    """Extract ChaCha20 keystream"""

    with io.open(enc_filename, 'rb') as fenc:

        # Read metadata
        try:
            fenc.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = fenc.read(METADATA_SIZE)

        # Encryption mode (0 - full, 1 - part, 2 - spot)
        enc_mode = metadata[RSA_KEY_SIZE + 12]
        if not (0 <= enc_mode <= 2):
            return False

        # Encryption percent (0..100)
        enc_percent = metadata[RSA_KEY_SIZE + 13]
        if not (0 <= enc_percent <= 100):
            return False

        file_size, = struct.unpack_from('<Q', metadata, RSA_KEY_SIZE + 14)

        if enc_mode == 0:
            # full
            # (.avdx .vhd .pvm .bin .avhd .vsv .vmx .vmsn .vmsd .vmrs .vmem
            #  .vmcx .vhdx .vmdk .nvram .iso .raw .qcow2 .vdi .subvol)
            num_chunks = 1
            chunk_size = file_size
            chunk_step = 0
        elif enc_mode == 1:
            # part (file size <= 2000000)
            num_chunks = 1
            chunk_size = (file_size * enc_percent) // 100
            chunk_step = 0
        else:
            # spot (file size > 2000000)
            enc_size = (file_size * enc_percent) // 100
            n = 3 if (enc_percent < 50) else 5
            chunk_size = enc_size // n
            num_chunks = 2 if (enc_percent < 50) else 4
            chunk_step = (file_size - chunk_size * num_chunks) // n

        # Decrypt file data
        chacha_blocks_per_chunk = (chunk_size + (64 - 1)) // 64

        with io.open(orig_filename, 'rb') as forig:

            pos = 0

            for i in range(num_chunks):

                chacha_counter = i * chacha_blocks_per_chunk

                out_filename = './keystream_%08X.bin' % chacha_counter
                with io.open(out_filename, 'wb') as fout:

                    # Extract keystream block
                    p = pos
                    size = chunk_size
                    while size != 0:

                        block_size = min(size, ENC_BLOCK_SIZE)
                        fenc.seek(p)
                        enc_data = fenc.read(block_size)
                        if enc_data == b'':
                            break

                        forig.seek(p)
                        orig_data = forig.read(block_size)
                        if len(orig_data) != len(enc_data):
                            return False

                        key_data = bytearray(enc_data)
                        for i in range(len(key_data)):
                            key_data[i] ^= orig_data[i]

                        fout.write(key_data)

                        size -= block_size
                        p += block_size

                    else:
                        pos += chunk_step

                        chacha_last_block_num = (chacha_counter +
                                                 (chunk_size // 64))
                        print('Keystream blocks %08X-%08X saved.' %
                                  (chacha_counter, chacha_last_block_num))

                        last_block_bytes = chunk_size & 0x3F
                        if last_block_bytes != 0:
                            missing_bytes = 64 - last_block_bytes
                            print('Keystream block %08X last %d bytes are missing.' %
                                      (chacha_last_block_num, missing_bytes))

                        continue

                    break

    return True


#
# Main
#
if len(sys.argv) != 3:
    print('Usage:', os.path.basename(sys.argv[0]),
          'enc_filename orig_fileName')
    sys.exit(0)

enc_filename = sys.argv[1]
orig_filename = sys.argv[2]

# Extract ChaCha20 keystream
if not extract_keystream(enc_filename, orig_filename):
    print('Error: Failed to extract keystream')
    sys.exit(1)
