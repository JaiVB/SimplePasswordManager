# SimplePasswordManager (Python Password Manager CLI)

A secure, local, command-line password manager written in Python.  
It encrypts credentials using AES-256-GCM and stores them safely in a local vault file.

---

## Features

- AES-256-GCM encryption for strong data protection  
- Master password hashed with bcrypt  
- PBKDF2 key derivation for AES keys  
- Local encrypted storage (`vault.json`)  
- Simple CLI commands: add, get, list, delete  
- No frontend or internet connection required  

---

## Requirements

- **Python** 3.10 or higher  
- Install dependencies:

```bash
pip install cryptography bcrypt
