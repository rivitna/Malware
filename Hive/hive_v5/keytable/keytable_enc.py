import sys
import os
import io
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import ChaCha20_Poly1305
import x25519


KEY_LEN = 32
XCHACHA_NONCE_LEN = 24

BASE_POINT = b'\t' + b'\0' * 31
HCHACHA_NONCE = 16 * b'\0'


def encrypt_storage(data, pubkey2):
    """Encrypt key table storage"""

    # Generate Curve25519-donna private key
    privkey1 = os.urandom(KEY_LEN)
    # Generate XChaCha20-Poly1305 nonce
    nonce = os.urandom(XCHACHA_NONCE_LEN)

    # Derive Curve25519-donna public key
    pubkey1 = x25519.curve25519(privkey1, BASE_POINT)
    # Derive Curve25519-donna shared key
    sharedkey = x25519.curve25519(privkey1, pubkey2)
    # Derive XChaCha20-Poly1305 key
    key = ChaCha20._HChaCha20(sharedkey, HCHACHA_NONCE)

    # XChaCha20-Poly1305 encrypt
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    enc_data, digest = cipher.encrypt_and_digest(data)

    return (nonce + pubkey1 + enc_data + digest)


#
# Main
#

if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

file_name = sys.argv[1]

# Load Curve25519-donna public keys
with io.open('pubkeys.bin', 'rb') as f:
    pubkeys = f.read()

# Load key table
with io.open(file_name, 'rb') as f:
    data = f.read()

# Encrypt key table in 2 steps
enc_data = encrypt_storage(data, pubkeys[:32])
enc_data = encrypt_storage(enc_data, pubkeys[32:64])

new_file_name = file_name + '.enc'
with io.open(new_file_name, 'wb') as f:
    f.write(enc_data)

print('Done!')
