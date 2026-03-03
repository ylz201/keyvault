"""
Fernet-based encryption utilities for KeyVault.

Uses Fernet (AES-128-CBC + HMAC-SHA256) for symmetric encryption.
The master key is stored at ~/.keyvault/master.key.
"""

import os
from pathlib import Path
from cryptography.fernet import Fernet


KEYVAULT_DIR = Path.home() / ".keyvault"
MASTER_KEY_FILE = KEYVAULT_DIR / "master.key"


def ensure_keyvault_dir() -> Path:
    """Create the ~/.keyvault directory if it doesn't exist."""
    KEYVAULT_DIR.mkdir(parents=True, exist_ok=True)
    # Restrict permissions to owner only
    os.chmod(KEYVAULT_DIR, 0o700)
    return KEYVAULT_DIR


def generate_master_key() -> bytes:
    """Generate a new Fernet master key and save it."""
    ensure_keyvault_dir()
    key = Fernet.generate_key()
    MASTER_KEY_FILE.write_bytes(key)
    os.chmod(MASTER_KEY_FILE, 0o600)
    return key


# ── Cached Fernet instance ──────────────────────────────
# We cache the Fernet instance to avoid re-reading the master key
# from disk on every encrypt/decrypt call. The tradeoff is that
# the key stays in Python process memory until the process exits.
# This is acceptable for a local CLI tool.

_fernet_instance: Fernet | None = None


def _get_fernet() -> Fernet:
    """Get or create the cached Fernet instance."""
    global _fernet_instance
    if _fernet_instance is None:
        key = _load_master_key()
        _fernet_instance = Fernet(key)
    return _fernet_instance


def _load_master_key() -> bytes:
    """Load the master key, generating one if it doesn't exist."""
    if not MASTER_KEY_FILE.exists():
        return generate_master_key()
    return MASTER_KEY_FILE.read_bytes().strip()


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns base64-encoded ciphertext."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext string."""
    f = _get_fernet()
    return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
