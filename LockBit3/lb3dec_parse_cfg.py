# MIT License
#
# Copyright (c) 2023 Andrey Zhdanov (rivitna)
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
import base64
import binascii
import lb3_dec
import lb3_hash
import lb3_id


# Configuration data file position
# If None try detect automatically position
CFG_POS = None  # 0x22E00

# Configuration data section name
CFG_SECTION_NAME = b'.data'


# Ransom note name
RANSOM_NOTE_NAME = 'README.txt'


RSA_KEY_SIZE = 0x80


def load_hash_list(file_name):
    """Load hash list"""

    try:
        with io.open(file_name, 'rt', encoding='utf-8') as f:
            str_list = f.read().splitlines()

    except FileNotFoundError:
        return {}

    return { lb3_hash.get_wide_str_hash(s): s for s in str_list if s != '' }


def get_lb3dec_cfg_pos(file_data):
    """Get decryptor configuration data position"""

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

    cfg_pos = None

    # Enumerate PE sections
    pos = first_section_hdr_pos

    for i in range(num_sections):

        s_name = file_data[pos : pos + 8]
        i = s_name.find(0)
        if (i >= 0):
            s_name = s_name[:i]

        s_vsize, s_rva, s_psize, s_pos = \
            struct.unpack_from('<4L', file_data, pos + 8)

        if (s_pos != 0):
            if (s_name == CFG_SECTION_NAME):
                if (min(s_vsize, s_psize) > 12):
                    cfg_pos = s_pos
                    cfg_sec_size = s_vsize

        pos += 0x28

    return cfg_pos


def mkdirs(dir):
    """Create directory hierarchy"""

    try:
        os.makedirs(dir)

    except OSError as exception:
        if (exception.errno != errno.EEXIST):
            raise


def save_data_to_file(file_name, data):
    """Save binary data to file."""
    with io.open(file_name, 'wb') as f:
        f.write(data)


#
# Main
#
if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

file_name = sys.argv[1]

# Load file data
with io.open(file_name, 'rb') as f:
    file_data = f.read()

cfg_pos = CFG_POS
if cfg_pos is None:

    # Get configuration data position
    cfg_pos = get_lb3dec_cfg_pos(file_data)
    if cfg_pos is None:
        print('Error: Configuration data not found.')
        sys.exit(1)

# Load hash list
hash_list = load_hash_list('./strings.txt')

# Create destination directory
dest_dir = os.path.abspath(os.path.dirname(file_name)) + '/cfg/'
mkdirs(dest_dir)

print('cfg data position: %08X' % cfg_pos)

# Extract configuration data
rnd_seed, = struct.unpack_from('<Q', file_data, cfg_pos)
print(('rnd seed: %08X') % rnd_seed)

cfg_pos += 8

cfg_data_size, = struct.unpack_from('<L', file_data, cfg_pos)
print('cfg data size: %d' % cfg_data_size)

cfg_pos += 4

enc_cfg_data = file_data[cfg_pos : cfg_pos + cfg_data_size]

cfg_data = lb3_dec.decrypt2(enc_cfg_data, rnd_seed)

save_data_to_file(dest_dir + 'cfg_data.bin', cfg_data)
print('cfg data saved to file.')

# RSA private key
rsa_priv_key = cfg_data[:2 * RSA_KEY_SIZE]
save_data_to_file(dest_dir + 'rsa_privkey.bin', rsa_priv_key)
save_data_to_file(dest_dir + 'priv.key', base64.b64encode(rsa_priv_key))
print('RSA private key saved to file.')

# RSA public key
rsa_pub_key = rsa_priv_key[RSA_KEY_SIZE:]
save_data_to_file(dest_dir + 'rsa_pubkey.bin', rsa_pub_key)
save_data_to_file(dest_dir + 'pub.key',
                  base64.b64encode(b'\1\0\1' + 125 * b'\0' + rsa_pub_key))
print('RSA public key saved to file.')

# Decryption ID
decr_id = binascii.hexlify(rsa_pub_key[:8]).decode().upper()
print('decryption id: \"%s\"' % decr_id)
# GUID
guid = lb3_id.get_uuid_str(rsa_pub_key)
print('guid: \"%s\"' % guid)
# Ransom extension
victim_id = lb3_id.get_victim_id(guid)
print('ransom ext: \"%s\"' % ('.' + victim_id))
# Ransom note name
ransom_note_name = victim_id + '.' + RANSOM_NOTE_NAME
print('ransom note name: \"%s\"' % ransom_note_name)

pos = 2 * RSA_KEY_SIZE
i = cfg_data.find(0, pos)
if (i >= 0):
    b64_data = cfg_data[pos : i]
else:
    b64_data = cfg_data[pos:]

# Field "white_folders"
data = base64.b64decode(b64_data)

fld_data = ''
for i in range(0, len(data), 4):

    h, = struct.unpack_from('<L', data, i)
    if h == 0:
        break

    if fld_data != '':
        fld_data += ';'
    s = hash_list.get(h)
    fld_data += s if (s is not None) else ('0x%08X' % h)

save_data_to_file(dest_dir + 'white_folders.txt', fld_data.encode('UTF-8'))
print('white_folders saved to file.')
