# High level operations: add entry, get entry, delete entry, list entries.
# This module does not know about bcrypt. It receives a ready AES key.

# crypto_utils
# Imports your custom encryption and decryption functions.
# Keeps manager.py focused on logic like “add entry” or “get entry” without knowing encryption details.

# It doesn’t use external libraries directly because encryption work is delegated to crypto_utils.py.

# manager.py
from typing import Dict, Any
from crypto_utils import encrypt_text, decrypt_text

# Encrypts password.
# Saves encrypted data to entries.
def add_entry(entries: Dict[str, Any], key: bytes, service: str, username: str, password: str) -> None:
    # 1. Encrypt the password
    nonce_b64, cipher_b64 = encrypt_text(key, password)

    # 2. Store everything in the entries dictionary
    entries[service] = {
        "username": username,
        "password": cipher_b64,
        "nonce": nonce_b64
    }


# Decrypts and returns username/password.
def get_entry(entries: Dict[str, Any], key: bytes, service: str) -> dict | None:
    # 1. Look up the service name in the entries
    data = entries.get(service)
    if data is None:
        return None  # The service doesn’t exist

    # 2. Decrypt the stored password
    plaintext_password = decrypt_text(key, data["nonce"], data["password"])

    # 3. Return the complete decrypted entry
    return {
        "service": service,
        "username": data["username"],
        "password": plaintext_password
    }


# Removes a service from entries.
def delete_entry(entries: Dict[str, Any], service: str) -> bool:
    if service in entries: # 1. Check if the service exists in the vault
        del entries[service]  # 2. Remove the entry
        return True  # Deletion successful
    else:
        return False  # Service not found


# Returns all service names.
def list_services(entries: Dict[str, Any]) -> list[str]:
    return sorted(list(entries.keys()))




