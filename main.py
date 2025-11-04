# Test Cases
# First run → prompts to set master password.
# Add a password → confirm vault.json is created.
# Retrieve password → correct decryption.
# Wrong master password → fails to decrypt.

# Delete and list commands → update correctly.
# Purpose
# Handles user interaction and ties everything together. It’s the “controller.”


# main.py
import argparse
import getpass
from base64 import b64encode, b64decode
import bcrypt
import storage
import manager
from crypto_utils import derive_key, generate_salt

# TODO: Prompt user to create a master password on first run
def init_master(vault: dict) -> None:
    pass


# TODO: Prompt user to enter master password, verify with bcrypt
# If valid, derive AES key using PBKDF2
def get_master_key(vault: dict) -> bytes:
    pass


# TODO: Parse command-line arguments and route actions
def main():
    # Parse commands (add, get, list, delete)
    # Load vault
    # Verify or initialize master password
    # Run the appropriate manager function
    pass


if __name__ == "__main__":
    main()
