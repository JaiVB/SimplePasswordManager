# Load vault file into a Python dict.
# Save vault dict back to disk.
# Handle first-time setup.

# json
# Converts between Python dictionaries and the JSON vault file.
# Lets you easily save and load structured data.

# os
# Checks if the vault file exists (os.path.exists).

# typing
# Provides type hints (Dict, Any) for code clarity and autocomplete support.

# No cryptography code is here. It only deals with safe file I/O.


# storage.py
import json
import os
from typing import Any, Dict

VAULT_PATH = "vault.json"

# Checks if vault.json exists.
def vault_exists() -> bool:
    return os.path.exists(VAULT_PATH)   

# If missing, return default structure {"config": {}, "entries": {}}
# Loads JSON into a Python dict.
def load_vault() -> Dict[str, Any]:
    if not os.path.exists(VAULT_PATH):
        return {"config": {}, "entries": {}}
    with open(VAULT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# Saves updated dict to file.
def save_vault(vault: Dict[str, Any]) -> None:
    with open(VAULT_PATH, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2)


# Returns or creates a "config" section.
def get_config(vault: Dict[str, Any]) -> Dict[str, Any]:
    return vault.setdefault("config", {})


# Returns or creates an "entries" section.
def get_entries(vault: Dict[str, Any]) -> Dict[str, Any]:
    return vault.setdefault("entries", {})






