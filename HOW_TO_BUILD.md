# HOW TO BUILD: Python CLI Password Manager

This document outlines everything you need to know, research, and implement to build your secure command-line password manager in Python.

---

## 1. crypto_utils.py  
Handles all **encryption and key derivation** logic.

### What to Research
- **PBKDF2** (Password-Based Key Derivation Function 2)  
  - Strengthens passwords using salt and iterations.  
  - Docs: `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`
- **AES-GCM** (Advanced Encryption Standard - Galois/Counter Mode)  
  - Provides encryption and integrity protection.  
  - Research how nonces and tags work.
- **Base64 Encoding**
  - Used to safely store binary data as text.

### What to Implement
1. **derive_key(master_password, salt, iterations)**  
   - Use PBKDF2HMAC with SHA256.  
   - Output: 32-byte AES key.
2. **encrypt_text(key, plaintext)**  
   - Generate 12-byte nonce using `os.urandom(12)`.  
   - Encrypt with `AESGCM`.  
   - Return base64-encoded nonce and ciphertext.
3. **decrypt_text(key, nonce_b64, ciphertext_b64)**  
   - Base64-decode inputs.  
   - Decrypt using `AESGCM`.
4. **generate_salt(length=16)**  
   - Use `os.urandom()` for secure randomness.

---

## 2. storage.py  
Handles reading and writing your **vault.json** file.

### What to Research
- Reading/writing JSON in Python (`json.load`, `json.dump`).  
- File existence checks (`os.path.exists`).  
- File overwriting and working directory management.

### What to Implement
1. **vault_exists()**  
   - Returns True if `vault.json` exists.
2. **load_vault()**  
   - If no file exists, return:  
     ```python
     {"config": {}, "entries": {}}
     ```
3. **save_vault(vault)**  
   - Save the vault using `json.dump(vault, f, indent=2)`.
4. **get_config(vault)**  
   - Return or create the `"config"` section.
5. **get_entries(vault)**  
   - Return or create the `"entries"` section.

---

## 3. manager.py  
Controls how passwords are added, retrieved, and deleted.

### What to Research
- Dictionary manipulation (add, delete, lookups).  
- Function imports and modular design.

### What to Implement
1. **add_entry(entries, key, service, username, password)**  
   - Encrypt the password.  
   - Store:
     ```python
     entries[service] = {
         "username": username,
         "password": cipher_b64,
         "nonce": nonce_b64
     }
     ```
2. **get_entry(entries, key, service)**  
   - Decrypt stored data and return plaintext password.
3. **delete_entry(entries, service)**  
   - Remove an entry if it exists. Return True or False.
4. **list_services(entries)**  
   - Return a sorted list of all stored service names.

---

## 4. main.py  
Main entry point for the program. Manages the CLI and user authentication.

### What to Research
- **argparse** (for command-line arguments).  
- **getpass.getpass()** (for secure password input).  
- **bcrypt** (for hashing and verifying passwords).  
- **base64** (for encoding salt in config).

### What to Implement
1. **init_master(vault)**  
   - Ask the user to create a master password.  
   - Confirm twice.  
   - Hash using `bcrypt.hashpw()`.  
   - Generate a random salt with `generate_salt()`.  
   - Store in config:
     ```python
     {
       "master_hash": "<bcrypt_hash>",
       "kdf_salt": "<base64_salt>",
       "kdf_iterations": 200000
     }
     ```
2. **get_master_key(vault)**  
   - Prompt for the master password.  
   - Verify with `bcrypt.checkpw()`.  
   - If correct, use PBKDF2 to derive AES key.
3. **main()**  
   - Use `argparse` to handle commands:
     - `add <service> <username> <password>`
     - `get <service>`
     - `list`
     - `delete <service>`
   - Load vault → verify or initialize master password → execute action → save vault.

---

## 5. Testing and Security

### What to Research
- AES-GCM authentication failure handling.  
- Bcrypt’s computational cost (rounds).  
- File permissions for sensitive data.

### What to Implement
- **Test each command:**
  - Add → creates encrypted vault.json.  
  - Get → decrypts and displays password.  
  - Delete → removes entry.  
  - List → displays stored services.  
- **Negative tests:**
  - Wrong master password → reject access.  
  - Tampered ciphertext → decryption fails.  
- **Verify encryption:**
  - Open vault.json → confirm passwords are unreadable.

---

## 6. Optional Future Upgrades

- Random password generator using `secrets.choice()`.  
- Switch to SQLite instead of JSON.  
- Encrypted backups.  
- Add two-factor authentication.

---

## 7. File Build Order

1. Write **crypto_utils.py** → test key derivation and encryption.  
2. Write **storage.py** → test saving and loading.  
3. Write **manager.py** → integrate encryption and storage.  
4. Write **main.py** → connect everything with CLI.  
5. Test all commands and add `.gitignore`.

---

## 8. Recommended .gitignore

```
__pycache__/
*.py[cod]
venv/
.env/
.vscode/
.idea/
vault.json
*.key
*.enc
```

---

**Goal:**  
After completing each section, you’ll have a fully functional, local, encrypted password manager built with modern cryptographic practices.
