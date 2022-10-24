import sys
import io
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


PRIVKEY1_DER_DATA_LEN = 2949
PRIVKEY2_DER_DATA_LEN = 2951

SENTINEL_SIZE = 20


def decrypt_storage(enc_data, privkey_der_data):
    """Decrypt keystream storage"""

    key = RSA.import_key(privkey_der_data)

    enc_xor_key_size = key.size_in_bits() // 8

    # Decrypt XOR key (RSA)
    rsa_cipher = PKCS1_v1_5.new(key)
    sentinel = os.urandom(SENTINEL_SIZE)
    xor_key = rsa_cipher.decrypt(enc_data[:enc_xor_key_size], sentinel)

    # Encrypt data
    data = bytearray(enc_data[enc_xor_key_size:])
    for i in range(len(data)):
        data[i] ^= xor_key[i % len(xor_key)]

    return bytes(data)


#
# Main
#

if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

file_name = sys.argv[1]

# Load RSA private keys
with io.open('rsa_privkeys.bin', 'rb') as f:
    privkeys = f.read()

# Load encrypted keystream
with io.open(file_name, 'rb') as f:
    enc_data = f.read()

# Decrypt keystream in 2 steps
data = decrypt_storage(enc_data,
                       privkeys[PRIVKEY1_DER_DATA_LEN : PRIVKEY1_DER_DATA_LEN + PRIVKEY2_DER_DATA_LEN])
data = decrypt_storage(data, privkeys[:PRIVKEY1_DER_DATA_LEN])

new_file_name = file_name + '.dec'
with io.open(new_file_name, 'wb') as f:
    f.write(data)

print('Done!')
