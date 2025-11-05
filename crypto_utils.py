# Derive AES key from master password and salt.
# Encrypt and decrypt a piece of text

# cryptography.hazmat.primitives.kdf.pbkdf2
# Creates a Key Derivation Function (KDF).
# Converts a user’s master password into a fixed-length key for AES.
# Using PBKDF2 adds random salt and thousands of iterations to slow brute-force attacks.

# cryptography.hazmat.primitives.ciphers.aead.AESGCM
# Implements AES encryption in GCM mode.
# GCM mode encrypts and authenticates data.
# It ensures that if someone changes the ciphertext, decryption will fail.

# os.urandom
# Generates cryptographically secure random bytes for salts and nonces.
# Used instead of random.random because it’s unpredictable.

# base64
# Converts binary data (keys, salts, nonces) to strings so you can store them in JSON safely.

# crypto_utils.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import b64encode, b64decode
from os import urandom
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib



# TODO: Derive a 32-byte AES key from the master password using PBKDF2
# Uses PBKDF2 with SHA256.
# Returns 32-byte key.
# Output should be  32 bytes for AES-256.
def derive_key(master_password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    # salt must be raw bytes, not Base64 text
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 32 bytes = AES-256 key
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return key

    


# Return base64-encoded nonce and ciphertext
# Uses AES-GCM to encrypt text.
# Returns Base64 nonce and ciphertext.
def encrypt_text(key: bytes, plaintext: str) -> tuple[str, str]:
    # Create AES-GCM cipher object
    aesgcm = AESGCM(key)

    # Generate a random 12-byte nonce
    nonce = urandom(12)

    # Encrypt plaintext (AES-GCM)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Encode both to Base64 for safe storage (text-safe)
    nonce_b64 = b64encode(nonce).decode("utf-8")
    ciphertext_b64 = b64encode(ciphertext).decode("utf-8")

    # Return as strings
    return nonce_b64, ciphertext_b64


# Return the original plaintext string
# Reverses encryption to get plaintext.
def decrypt_text(key: bytes, nonce_b64: str, ciphertext_b64: str) -> str:
    # Create AES-GCM cipher object with the same key
    aesgcm = AESGCM(key)

    # Decode Base64 nonce and ciphertext back to bytes
    nonce = b64decode(nonce_b64)
    ciphertext = b64decode(ciphertext_b64)
    # Decrypt the ciphertext
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    plaintext_bytes = plaintext_bytes.decode('utf-8')
    return plaintext_bytes



# Generates random salt using os.urandom().
def generate_salt(length: int = 16) -> bytes:
    return urandom(length)
    






