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
import errno
import struct
from binascii import crc32
from Crypto.Cipher import AES


# Configuration data file position
CFG_INFO_POS = 0x9E08

CFG_KEY_LEN = 32
CFG_IV = 16 * b'\0'

CFG_ENTRY_SIZE = 12


def mkdirs(dir):
    """Create directory hierarchy"""

    try:
        os.makedirs(dir)

    except OSError as exception:
        if (exception.errno != errno.EEXIST):
            raise


def save_data_to_file(file_name, data):
    """Save binary data to file"""
    with io.open(file_name, 'wb') as f:
        f.write(data)


def get_cfg_info(file_data, cfg_info_pos):
    """Get configuration data information"""

    mz_sign, = struct.unpack_from('<H', file_data, 0)
    if (mz_sign != 0x5A4D):
        return None

    nt_hdr_pos, = struct.unpack_from('<L', file_data, 0x3C)

    pe_sign, = struct.unpack_from('<L', file_data, nt_hdr_pos)
    if (pe_sign != 0x00004550):
        return None

    # Parse PE header
    img_hdr_pos = nt_hdr_pos + 4
    num_sections, = struct.unpack_from('<H', file_data, img_hdr_pos + 2)
    opt_hdr_pos = img_hdr_pos + 0x14
    opt_hdr_size, = struct.unpack_from('<H', file_data, img_hdr_pos + 0x10)
    nt_hdr_size = 4 + 0x14 + opt_hdr_size
    first_section_hdr_pos = nt_hdr_pos + nt_hdr_size

    cfg_rva_offset, cfg_size = struct.unpack_from('<LL', file_data,
                                                  cfg_info_pos)
    cfg_rva = None
    cfg_pos = None

    # Enumerate PE sections
    pos = first_section_hdr_pos

    for i in range(num_sections):

        s_vsize, s_rva, s_psize, s_pos = struct.unpack_from('<4L', file_data,
                                                            pos + 8)

        if cfg_rva is None:
            if cfg_info_pos >= s_pos:
                ofs = cfg_info_pos - s_pos
                if ofs + 4 <= s_psize:
                    cfg_rva = s_rva + ofs + cfg_rva_offset

        else:
            if cfg_rva >= s_rva:
                ofs = cfg_rva - s_rva
                if ofs + cfg_size <= s_vsize:
                    cfg_pos = s_pos + ofs
                    break

        pos += 0x28

    if cfg_pos is None:
        return None

    return cfg_pos, cfg_size


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

file_name = sys.argv[1]

with io.open(file_name, 'rb') as f:
    file_data = f.read()

pos = CFG_INFO_POS

cfg_info = get_cfg_info(file_data, pos)
if cfg_info is None:
    print('Error: Configuration data not found.')
    sys.exit(1)

print('cfg data position: %08X' % cfg_info[0])
print('cfg data size: %d' % cfg_info[1])

cfg_data = file_data[cfg_info[0] : cfg_info[0] + cfg_info[1]]

pos += 8
# Configuration data decryption key
cfg_key = file_data[pos : pos + CFG_KEY_LEN]
pos += CFG_KEY_LEN
# Configuration data CRC32
cfg_crc, = struct.unpack_from('<L', file_data, pos)

print('cfg data CRC32: %08X' % cfg_crc)

if cfg_crc != crc32(cfg_data):
    print('Error: Invalid configuration data.')
    sys.exit(1)

del file_data

# Create destination directory
dest_dir = os.path.abspath(os.path.dirname(file_name)) + '/cfg/'
mkdirs(dest_dir)

cfg_num_entries, cfg_entry_data_size = struct.unpack_from('<LL', cfg_data, 0)
print('cfg entries: %d' % cfg_num_entries)

cfg_entry_data_pos = cfg_num_entries * CFG_ENTRY_SIZE + 8

pos = 8

for _ in range(cfg_num_entries):

    entry_index, entry_pos, entry_size = struct.unpack_from('<3L', cfg_data,
                                                            pos)
    entry_size2 = (entry_size + 15) & ~0xF
    enc_entry_data = cfg_data[cfg_entry_data_pos + entry_pos :
                              cfg_entry_data_pos + entry_pos + entry_size2]

    cipher = AES.new(cfg_key, AES.MODE_CBC, CFG_IV)
    entry_data = cipher.decrypt(enc_entry_data)

    save_data_to_file(dest_dir + ('cfg_%02X.bin' % entry_index),
                      entry_data[:entry_size])

    pos += CFG_ENTRY_SIZE
