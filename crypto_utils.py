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
from base64 import b64encode, b64decode
from os import urandom
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib



# TODO: Derive a 32-byte AES key from the master password using PBKDF2
# Uses PBKDF2 with SHA256.
# Returns 32-byte key.
# Output should be  32 bytes for AES-256.
def derive_key(master_password: str, salt: bytes, iterations: int = 200000) -> bytes:
    # Why 200,000 iterations?
    # Price to Performance ratio
    # Increases the time it takes to derive the key, making brute-force attacks more difficult
    # 200k iterations are fast enough for you but slow for attackers.

    # Generates Salt if none is provided
    salt = urandom(16) if salt is None else b64decode(salt) # Decode Base64 text → original bytes


    # What is hashlib.pbkdf2_hmac()?
    # Used to turn a password (string) into a secure cryptographic key (bytes). 
    #   Adding a random salt (to prevent rainbow table attacks).
    #   Running many iterations (to slow brute-force attempts).
    #   Producing a fixed-length binary key for encryption.

    key = hashlib.pbkdf2_hmac(
        "sha256",                           # Hash algorithm
        master_password.encode('utf-8'),    # Password → bytes
        salt,                               # Random salt
        iterations,                         # Number of iterations
        dklen=32                            # 32 bytes = AES-256
    )

    return key


# TODO: Encrypt plaintext with AES-GCM
# Return base64-encoded nonce and ciphertext
# Uses AES-GCM to encrypt text.
# Returns Base64 nonce and ciphertext.
def encrypt_text(key: bytes, plaintext: str) -> tuple[str, str]:
    # Create AES-GCM cipher object
    aesgcm = AESGCM(key)
    # Generate a random 12-byte nonce
    # 12 bytes is standard for AES-GCM
    nonce = urandom(12) 
    # Encrypt the plaintext
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None) 
    return nonce, ciphertext
    


# TODO: Decrypt ciphertext with AES-GCM
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


# TODO: Generate a secure random salt (default 16 bytes)
# Generates random salt using os.urandom().
def generate_salt(length: int = 16) -> bytes:
    return urandom(length)
    






