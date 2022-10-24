import sys
import io
import os.path


MARKER1 = b'wxyz0123456789+/'
KEY_START = b'\x30\x82\x02'
MAX_MARKER_SPACE = 32
NUM_PUBKEYS = 2
PUBKEY_SIZE = 678


#
# Main
#

if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

file_name = sys.argv[1]

with io.open(file_name, 'rb') as f:
    file_data = f.read()

pos = file_data.find(MARKER1)
if (pos < 0):
    raise Exception('Marker1 not found')

print('\"%s\" found at: %08X' % (MARKER1.decode(), pos))

pos += len(MARKER1)

pos = file_data.find(KEY_START, pos,
                     pos + MAX_MARKER_SPACE + len(KEY_START))
if (pos < 0):
    raise Exception('Key #1 not found')

print('Key #1 found at: %08X' % pos)

pos2 = pos + PUBKEY_SIZE

if (file_data[pos2 : pos2 + len(KEY_START)] != KEY_START):
    raise Exception('Invalid key #2')

pubkeys = file_data[pos : pos + NUM_PUBKEYS * PUBKEY_SIZE]

key_filepath = os.path.join(os.path.dirname(file_name), 'rsa_pubkeys.bin')
with io.open(key_filepath, 'wb') as f:
    f.write(pubkeys)

print('Done!')
