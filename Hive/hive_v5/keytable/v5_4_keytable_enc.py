import sys
import io
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


PUBKEY_DER_DATA_LEN = 678


def encrypt_storage(data, pubkey_der_data):
    """Encrypt keystream storage"""

    pubkey = RSA.import_key(pubkey_der_data)

    xor_key_size = pubkey.size_in_bits() // 8 - 11

    # Generate XOR key
    xor_key = os.urandom(xor_key_size)

    # Encrypt data
    enc_data = bytearray(data)
    for i in range(len(enc_data)):
        enc_data[i] ^= xor_key[i % xor_key_size]

    # Encrypt XOR key (RSA)
    rsa_cipher = PKCS1_v1_5.new(pubkey)
    enc_xor_key = rsa_cipher.encrypt(xor_key)

    return (enc_xor_key + bytes(enc_data))


#
# Main
#

if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

file_name = sys.argv[1]

# Load RSA public keys
with io.open('rsa_pubkeys.bin', 'rb') as f:
    pubkeys = f.read()

# Load keystream
with io.open(file_name, 'rb') as f:
    data = f.read()

# Encrypt keystream in 2 steps
enc_data = encrypt_storage(data, pubkeys[:PUBKEY_DER_DATA_LEN])
enc_data = encrypt_storage(enc_data,
                           pubkeys[PUBKEY_DER_DATA_LEN : 2 * PUBKEY_DER_DATA_LEN])

new_file_name = file_name + '.enc'
with io.open(new_file_name, 'wb') as f:
    f.write(enc_data)

print('Done!')
