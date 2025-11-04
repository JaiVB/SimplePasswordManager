# High level operations: add entry, get entry, delete entry, list entries.
# This module does not know about bcrypt. It receives a ready AES key.

# crypto_utils
# Imports your custom encryption and decryption functions.
# Keeps manager.py focused on logic like “add entry” or “get entry” without knowing encryption details.

# It doesn’t use external libraries directly because encryption work is delegated to crypto_utils.py.

# manager.py
from typing import Dict, Any
from crypto_utils import encrypt_text, decrypt_text

# TODO: Encrypt password and store entry under given service
# Encrypts password.
# Saves encrypted data to entries.
def add_entry(entries: Dict[str, Any], key: bytes, service: str, username: str, password: str) -> None:
    pass


# TODO: Decrypt and return stored username/password for given service
# Decrypts and returns username/password.
def get_entry(entries: Dict[str, Any], key: bytes, service: str) -> dict | None:
    pass


# TODO: Delete entry from vault if it exists
# Removes a service from entries.
def delete_entry(entries: Dict[str, Any], service: str) -> bool:
    pass


# TODO: Return a sorted list of stored service names
# Returns all service names.
def list_services(entries: Dict[str, Any]) -> list[str]:
    pass




