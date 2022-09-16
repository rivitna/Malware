import sys
import io
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import ChaCha20_Poly1305
import x25519


XCHACHA_KEY_LEN = 32
XCHACHA_NONCE_LEN = 24

BASE_POINT = b'\t' + b'\0' * 31
HCHACHA_NONCE = 16 * b'\0'


def decrypt_storage(enc_data, privkey2):
    """Decrypt key table storage"""

    # Extract XChaCha20-Poly1305 nonce
    nonce = enc_data[:XCHACHA_NONCE_LEN]
    # Extract Curve25519-donna public key
    pubkey = enc_data[XCHACHA_NONCE_LEN : XCHACHA_NONCE_LEN + XCHACHA_KEY_LEN]

    enc_data = enc_data[XCHACHA_NONCE_LEN + XCHACHA_KEY_LEN :]

    # Derive Curve25519-donna shared key
    sharedkey = x25519.curve25519(privkey2, pubkey)
    # Derive XChaCha20-Poly1305 key
    key = ChaCha20._HChaCha20(sharedkey, HCHACHA_NONCE)

    # XChaCha20-Poly1305 decrypt
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    data = cipher.decrypt_and_verify(enc_data[:-16], enc_data[-16:])
    return data


#
# Main
#

if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

file_name = sys.argv[1]

# Load Curve25519-donna private keys
with io.open('privkeys.bin', 'rb') as f:
    privkeys = f.read()

# Load encrypted key table
with io.open(file_name, 'rb') as f:
    enc_data = f.read()

# Decrypt key table in 2 steps
data = decrypt_storage(enc_data, privkeys[32:64])
data = decrypt_storage(data, privkeys[:32])

new_file_name = file_name + '.dec'
with io.open(new_file_name, 'wb') as f:
    f.write(data)

print('Done!')
