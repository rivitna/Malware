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

import sys
import io
import os
import errno
import struct
import hashlib


# Configuration data file position and size
CFG_DATA_POS = 0xCA00
CFG_DATA_SIZE = 0xA13C

KEY1_SIZE = 128
KEY2_SIZE = 128

VICTIM_ID = b'00000000'

# Fields
FIELD_UNKNOWN = 0
FIELD_BLOB    = 1
FIELD_STR     = 2
FIELD_WSTR    = 3
FIELD_UI32    = 4

FIELDS = [
    ( 'rsa_n',               516, FIELD_BLOB,    True ),
    ( 'rsa_e',               516, FIELD_BLOB,    True ),
    ( 'drives',               54, FIELD_WSTR,    True ),
    ( 'apifuncs',           1498, FIELD_UNKNOWN, True ),
    ( 'ransom_note2',      13864, FIELD_UNKNOWN, True ),
    ( 'attacker_id',           6, FIELD_UNKNOWN, True ),
    ( 'email_suffix',        128, FIELD_WSTR,    True ),
    ( 'ransom_ext',          128, FIELD_WSTR,    True ),
    ( 'id_suffix',            10, FIELD_WSTR,    True ),
    ( 'mutex_prefix',         38, FIELD_WSTR,    True ),
    ( '',                    140, FIELD_WSTR,    True ),
    ( '',                     28, FIELD_WSTR,    True ),
    ( '',                     20, FIELD_WSTR,    True ),
    ( '',                     36, FIELD_WSTR,    True ),
    ( '',                     40, FIELD_WSTR,    True ),
    ( '',                     28, FIELD_WSTR,    True ),
    ( '',                     42, FIELD_WSTR,    True ),
    ( '',                    128, FIELD_WSTR,    True ),
    ( '',                    128, FIELD_WSTR,    True ),
    ( 'ransom_note1_name',   128, FIELD_WSTR,    True ),
    ( 'ransom_note2_name',   128, FIELD_WSTR,    True ),
    ( 'email1',              128, FIELD_STR,     True ),
    ( 'email2',             1024, FIELD_STR,     True ),
    ( '',                     26, FIELD_WSTR,    True ),
    ( '',                     20, FIELD_WSTR,    True ),
    ( '',                     12, FIELD_WSTR,    True ),
    ( '',                     40, FIELD_WSTR,    True ),
    ( '',                    159, FIELD_STR,     True ),
    ( 'runas_count',           4, FIELD_UI32,    False ),
    ( '',                    561, FIELD_UNKNOWN, False ),
    ( 'cmds',                 66, FIELD_STR,     True ),
    ( '',                   4096, FIELD_WSTR,    True ),
    ( 'black_exts',         4096, FIELD_WSTR,    True ),
    ( 'doc_exts',           4096, FIELD_WSTR,    True ),
    ( '',                   4096, FIELD_WSTR,    True ),
    ( 'white_files',        1024, FIELD_WSTR,    True ),
    ( 'white_dirs',         1024, FIELD_WSTR,    True ),
    ( 'black_processes',    1024, FIELD_WSTR,    True ),
    ( 'black_services',     1024, FIELD_WSTR,    True ),
    ( 'ransom_note1',       1024, FIELD_WSTR,    True ),
]


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


def rc4_ksa(key):
    """RC4 KSA"""
    key_len = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def rc4_prga(s):
    """RC4 PRGA"""
    i = 0
    j = 0
    while True:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[j], s[i] = s[i], s[j]
        yield s[(s[i] + s[j]) & 0xFF]


def get_strz(data, pos, max_size):
    """Get Unicode string"""
    for i in range(pos, pos + max_size, 1):
        if data[i] == 0:
            return data[pos : i]
    return data[pos : pos + max_size]


def get_wstrz(data, pos, max_size):
    """Get Unicode string"""
    for i in range(pos, pos + max_size, 2):
        if (data[i] == 0) and (data[i + 1] == 0):
            return data[pos : i]
    return data[pos : pos + max_size]


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

cfg_pos = CFG_DATA_POS
cfg_data_size = CFG_DATA_SIZE

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    f.seek(cfg_pos)
    key1 = f.read(KEY1_SIZE)
    cfg_data = bytearray(f.read(cfg_data_size))

# Decrypt configuration data
s = rc4_ksa(key1)
keystream = rc4_prga(s)
for i in range(len(cfg_data)):
    cfg_data[i] ^= next(keystream)

key2 = cfg_data[:KEY2_SIZE]
cfg_data = bytearray(cfg_data[KEY2_SIZE:])

cfg_pos += KEY1_SIZE + KEY2_SIZE

print('cfg data position: %08X' % cfg_pos)
print('cfg data size: %d' % len(cfg_data))

fields = {}

# Extract fields
pos = 0

for fld_name, fld_size, fld_type, fld_enc in FIELDS:

    if fld_enc:
        p = pos
        end_p = p + fld_size

        # Decrypt field
        s = rc4_ksa(key2)
        keystream = rc4_prga(s)

        if fld_type == FIELD_UNKNOWN:
            for i in range(p, end_p, 1):
                cfg_data[i] ^= next(keystream)

        elif fld_type == FIELD_BLOB:
            size, = struct.unpack_from('<L', cfg_data, p)
            p += 4
            end_p = min(p + size, end_p)
            for i in range(p, end_p, 1):
                cfg_data[i] ^= next(keystream)

        elif fld_type == FIELD_STR:
            for i in range(p, end_p, 1):
                cfg_data[i] ^= next(keystream)
                if cfg_data[i] == 0:
                    end_p = i
                    break

        elif fld_type == FIELD_WSTR:
            for i in range(p, end_p, 2):
                cfg_data[i] ^= next(keystream)
                cfg_data[i + 1] ^= next(keystream)
                if (cfg_data[i] == 0) and (cfg_data[i + 1] == 0):
                    end_p = i
                    break

        if fld_name:
            fields[fld_name] = cfg_data[p : end_p]

    elif fld_name:
        if fld_type == FIELD_UNKNOWN:
            val = cfg_data[pos : pos + fld_size]
        if fld_type == FIELD_BLOB:
            size, = struct.unpack_from('<L', cfg_data, pos)
            val = cfg_data[pos + 4: pos + 4 + size]
        elif fld_type == FIELD_STR:
            val = get_strz(cfg_data, pos, fld_size)
        elif fld_type == FIELD_WSTR:
            val = get_wstrz(cfg_data, pos, fld_size)
        elif fld_type == FIELD_UI32:
            val, = struct.unpack_from('<L', cfg_data, pos)
        fields[fld_name] = val

    pos += fld_size

# Create destination directory
dest_dir = os.path.abspath(os.path.dirname(filename)) + '/cfg/'
mkdirs(dest_dir)

save_data_to_file(dest_dir + 'cfgdata.bin', cfg_data)
print('cfg data saved to file.')

# RSA public key
rsa_n = fields.get('rsa_n')
if rsa_n:
    rsa_n_sha1 = hashlib.sha1(rsa_n).hexdigest()
    print('RSA modulus (n) SHA-1:', rsa_n_sha1)
    save_data_to_file(dest_dir + 'rsa_n.bin', rsa_n)
    print('RSA modulus (n) saved to file.')
rsa_e = fields.get('rsa_e')
if rsa_e:
    save_data_to_file(dest_dir + 'rsa_e.bin', rsa_e)
    print('RSA exponent (e) saved to file.')

# Attacker ID
attacker_id = fields.get('attacker_id')
if attacker_id:
    attacker_id = attacker_id.decode()
    print('attacker ID: \"%s\"' % attacker_id)

# Ransom extension
ransom_ext = fields.get('ransom_ext')
if ransom_ext:
    ransom_ext = ransom_ext.decode('UTF-16LE')
    email_suffix = fields.get('email_suffix')
    if email_suffix:
        ransom_ext = email_suffix.decode('UTF-16LE') + ransom_ext
    id_suffix = fields.get('id_suffix')
    if id_suffix:
        ransom_ext = id_suffix.decode('UTF-16LE') + 'XXXXXXXX' + ransom_ext
    print('ransom ext: \"%s\"' % ransom_ext)

# E-mail #1
email1 = fields.get('email1')
if email1:
    print('e-mail #1: \"%s\"' % email1.decode())
# E-mail #2
email2 = fields.get('email2')
if email2:
    print('e-mail #2: \"%s\"' % email2.decode())

# Mutex
mutex_prefix = fields.get('mutex_prefix')
if mutex_prefix and attacker_id:
    mutex_name = mutex_prefix.decode('UTF-16LE') + attacker_id
    print('mutex: \"%s\"' % mutex_name)

# Ransom note #1
ransom_note1_name = fields.get('ransom_note1_name')
if ransom_note1_name:
    ransom_note1_name = ransom_note1_name.decode('UTF-16LE')
    print('ransom note #1 name: \"%s\"' % ransom_note1_name)
else:
    ransom_note1_name = 'ransom_note1'
ransom_note1 = fields.get('ransom_note1')
if ransom_note1:
    save_data_to_file(dest_dir + ransom_note1_name, ransom_note1)
    print('ransom note #1 saved to file.')

# Ransom note #2
ransom_note2_name = fields.get('ransom_note2_name')
if ransom_note2_name:
    ransom_note2_name = ransom_note2_name.decode('UTF-16LE')
    print('ransom note #2 name: \"%s\"' % ransom_note2_name)
else:
    ransom_note2_name = 'ransom_note2'
ransom_note2 = fields.get('ransom_note2')
if ransom_note2:
    ransom_note2 = ransom_note2.rstrip(b'\0')
    # Insert ransom note fields 
    pos = 0
    for i in range(4):
        pos = ransom_note2.find(0)
        if pos < 0:
            break
        if i <= 1:
            # Insert E-mail #1
            if email1:
                ransom_note2 = (ransom_note2[:pos] + email1 +
                                ransom_note2[pos + 1:])
                pos += len(email1) - 1
        if i == 3:
            # Insert E-mail #2
            if email2:
                ransom_note2 = (ransom_note2[:pos] + email2 +
                                ransom_note2[pos + 1:])
                pos += len(email2) - 1
        elif i == 2:
            # Insert victim ID
            ransom_note2 = (ransom_note2[:pos] + VICTIM_ID +
                            ransom_note2[pos + 1:])
            pos += len(VICTIM_ID) - 1
        pos += 1

    save_data_to_file(dest_dir + ransom_note2_name, ransom_note2)
    print('ransom note #2 saved to file.')

# Commands
cmds = fields.get('cmds')
if cmds:
    save_data_to_file(dest_dir + 'cmds.txt', cmds)
    print('commands saved to file.')

# Black extension list
black_exts = fields.get('black_exts')
if black_exts:
    save_data_to_file(dest_dir + 'black_exts.txt', black_exts)
    print('black extension list saved to file.')

# Document extension list
doc_exts = fields.get('doc_exts')
if doc_exts:
    save_data_to_file(dest_dir + 'doc_exts.txt', doc_exts)
    print('document extension list saved to file.')

# File whitelist
white_files = fields.get('white_files')
if white_files:
    save_data_to_file(dest_dir + 'white_files.txt', white_files)
    print('file whitelist saved to file.')

# Directory whitelist
white_dirs = fields.get('white_dirs')
if white_dirs:
    save_data_to_file(dest_dir + 'white_dirs.txt', white_dirs)
    print('directory whitelist saved to file.')

# Process blacklist
black_processes = fields.get('black_processes')
if black_processes:
    save_data_to_file(dest_dir + 'black_processes.txt', black_processes)
    print('process blacklist saved to file.')

# Service blacklist
black_services = fields.get('black_services')
if black_services:
    save_data_to_file(dest_dir + 'black_services.txt', black_services)
    print('service blacklist saved to file.')
