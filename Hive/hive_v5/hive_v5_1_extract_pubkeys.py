import sys
import io
import os.path


MARKER1 = b'wxyz0123456789+/'
MARKERS2 = [ b'LoopError', b'StreamCipherError' ]
MAX_MARKER_SPACE = 32
NUM_PUBKEYS = 2
PUBKEY_SIZE = 32


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

for marker2 in MARKERS2:
    pos2 = file_data.find(marker2, pos,
                          pos + MAX_MARKER_SPACE + len(marker2))
    if (pos2 >= 0):
        print('\"%s\" found at: %08X' % (marker2.decode(), pos2))
        key_pos = pos2 + len(marker2)
        print('Public keys found at: %08X' % key_pos)
        break
else:
    raise Exception('Marker2 not found')

pubkeys = file_data[key_pos : key_pos + NUM_PUBKEYS * PUBKEY_SIZE]

key_filepath = os.path.join(os.path.dirname(file_name), 'pubkeys.bin')
with io.open(key_filepath, 'wb') as f:
    f.write(pubkeys)

print('Done!')
