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

def init_master(vault: dict) -> None:
    config = storage.get_config(vault)

    while True:
        # 1. Ask user to create and confirm master password
        pwd1 = getpass.getpass("Set master password: ")
        pwd2 = getpass.getpass("Confirm master password: ")

        if pwd1 != pwd2:
            print("Passwords do not match. Try again.")
            continue

        # 2. Hash master password with bcrypt for login verification
        master_hash = bcrypt.hashpw(pwd1.encode("utf-8"), bcrypt.gensalt())

        # 3. Generate random salt for PBKDF2 key derivation
        kdf_salt = generate_salt()

        # 4. Store bcrypt hash and Base64-encoded salt in config
        config["master_hash"] = master_hash.decode("utf-8", errors="ignore")
        config["kdf_salt"] = b64encode(kdf_salt).decode("utf-8")
        config["kdf_iterations"] = 200000

        # 5. Save vault to file
        storage.save_vault(vault)

        print("Master password set successfully.")
        break


# If valid, derive AES key using PBKDF2
def get_master_key(vault: dict) -> bytes:
    config = storage.get_config(vault)

    # 1. Check if a master password is already set
    if "master_hash" not in config:
        print("No master password found. Initializing new vault.")
        from main import init_master  # Import inside to avoid circular import
        init_master(vault)
        config = storage.get_config(vault)

    stored_hash = config["master_hash"].encode("utf-8")

    while True:
        # 2. Prompt for master password
        master_pwd = getpass.getpass("Enter master password: ")

        # 3. Verify password against stored bcrypt hash
        if bcrypt.checkpw(master_pwd.encode("utf-8"), stored_hash):
            # 4. Derive AES key using PBKDF2
            salt = b64decode(config["kdf_salt"])
            iterations = config["kdf_iterations"]
            key = derive_key(master_pwd, salt, iterations)
            return key
        else:
            print("Incorrect password. Try again.")



def main():
    # 1. Define CLI commands
    parser = argparse.ArgumentParser(description="Simple CLI Password Manager")
    subparsers = parser.add_subparsers(dest="command")

    add_p = subparsers.add_parser("add", help="Add a new entry")
    add_p.add_argument("service")
    add_p.add_argument("username")
    add_p.add_argument("password")

    get_p = subparsers.add_parser("get", help="Retrieve an entry")
    get_p.add_argument("service")

    del_p = subparsers.add_parser("delete", help="Delete an entry")
    del_p.add_argument("service")

    subparsers.add_parser("list", help="List all stored services")

    args = parser.parse_args()

    # 2. Load or create vault
    if not storage.vault_exists():
        vault = {"config": {}, "entries": {}}
        storage.save_vault(vault)
        print("Created new vault file.")
    else:
        vault = storage.load_vault()

    # 3. Verify master password and derive encryption key
    key = get_master_key(vault)
    entries = storage.get_entries(vault)

    # 4. Handle each command
    if args.command == "add":
        manager.add_entry(entries, key, args.service, args.username, args.password)
        storage.save_vault(vault)
        print(f"Added entry for {args.service}.")

    elif args.command == "get":
        entry = manager.get_entry(entries, key, args.service)
        if entry:
            print("Service:", entry["service"])
            print("Username:", entry["username"])
            print("Password:", entry["password"])
        else:
            print("Service not found.")

    elif args.command == "delete":
        if manager.delete_entry(entries, args.service):
            storage.save_vault(vault)
            print(f"Deleted entry for {args.service}.")
        else:
            print("Service not found.")

    elif args.command == "list":
        services = manager.list_services(entries)
        if services:
            print("Stored services:")
            for s in services:
                print(" -", s)
        else:
            print("No entries found.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()# Checks if vault.json exists.
