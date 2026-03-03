"""
Fernet-based encryption utilities for KeyVault.

Uses Fernet (AES-128-CBC + HMAC-SHA256) for symmetric encryption.
The master key is stored in the OS keyring when available, or at ~/.keyvault/master.key.
"""

from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet


try:
    import keyring  # type: ignore
except Exception:  # pragma: no cover
    keyring = None


def get_keyvault_dir() -> Path:
    """
    Get the KeyVault directory path.

    Can be overridden with KEYVAULT_DIR or KEYVAULT_HOME for testing or
    custom setups. Defaults to ~/.keyvault
    """
    override = os.environ.get("KEYVAULT_DIR") or os.environ.get("KEYVAULT_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".keyvault"


def get_master_key_file() -> Path:
    return get_keyvault_dir() / "master.key"


def _keyring_service() -> str:
    return os.environ.get("KEYVAULT_KEYRING_SERVICE", "keyvault-ai")


def _keyring_username() -> str:
    return os.environ.get("KEYVAULT_KEYRING_USERNAME", "master-key")


MasterKeyBackend = Literal["auto", "file", "keyring"]


def get_master_key_backend() -> MasterKeyBackend:
    backend = (os.environ.get("KEYVAULT_MASTER_KEY_BACKEND") or "auto").strip().lower()
    if backend in {"auto", "file", "keyring"}:
        return backend  # type: ignore[return-value]
    return "auto"


def _keyring_supported() -> bool:
    if keyring is None:
        return False
    try:
        # Some backends raise if not available; treat as unsupported.
        keyring.get_password(_keyring_service(), _keyring_username())
        return True
    except Exception:
        return False


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}


def _allow_unsafe_master_key_regen() -> bool:
    return _env_bool("KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN", False)


def _vault_contains_data() -> bool:
    """
    Best-effort check for existing vault rows.

    Used to prevent silently generating a new master key when encrypted data
    already exists, which would make existing secrets unreadable.
    """
    db_file = get_keyvault_dir() / "vault.db"
    if not db_file.exists():
        return False

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(str(db_file))
        for table in ("secrets", "secrets_v1", "secrets_new"):
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
                (table,),
            ).fetchone()
            if not exists:
                continue
            row_count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            if row_count and int(row_count[0]) > 0:
                return True
        return False
    except Exception:
        # Conservative fallback: if we cannot inspect an existing DB, assume it
        # may contain important data.
        return True
    finally:
        if conn is not None:
            conn.close()


def _ensure_safe_to_generate_master_key() -> None:
    if _allow_unsafe_master_key_regen():
        return
    if _vault_contains_data():
        raise RuntimeError(
            "Refusing to generate a new master key because existing vault data was detected. "
            "Restore the original keyring/key file, or set "
            "KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN=1 to force regeneration "
            "(existing secrets may become unreadable)."
        )


def _keyring_get_master_key() -> bytes | None:
    if not _keyring_supported():
        return None
    try:
        val = keyring.get_password(_keyring_service(), _keyring_username())
    except Exception:
        return None
    if not val:
        return None
    try:
        raw = val.strip().encode("utf-8")
        # Fernet keys are urlsafe-base64; validate shape to avoid surprises.
        base64.urlsafe_b64decode(raw)
        return raw
    except Exception:
        return None


def _keyring_set_master_key(key: bytes) -> None:
    if not _keyring_supported():
        raise RuntimeError("Keyring backend not available")
    keyring.set_password(_keyring_service(), _keyring_username(), key.decode("utf-8"))


def ensure_keyvault_dir() -> Path:
    """Create the ~/.keyvault directory if it doesn't exist."""
    keyvault_dir = get_keyvault_dir()
    keyvault_dir.mkdir(parents=True, exist_ok=True)
    # Restrict permissions to owner only
    try:
        os.chmod(keyvault_dir, 0o700)
    except OSError:
        pass
    return keyvault_dir


def generate_master_key() -> bytes:
    """Generate a new Fernet master key and save it."""
    ensure_keyvault_dir()
    key = Fernet.generate_key()
    master_key_file = get_master_key_file()
    master_key_file.write_bytes(key)
    try:
        os.chmod(master_key_file, 0o600)
    except OSError:
        pass
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
    backend = get_master_key_backend()
    master_key_file = get_master_key_file()

    # Auto: prefer keyring only if key already exists there, otherwise preserve
    # existing file-based vaults for backward compatibility. For new setups
    # (no master.key yet), default to keyring when available.
    if backend in {"auto", "keyring"}:
        key = _keyring_get_master_key()
        if key is not None:
            return key

        if backend == "auto" and not master_key_file.exists() and _keyring_supported():
            key = Fernet.generate_key()
            _keyring_set_master_key(key)
            return key

        if backend == "keyring":
            if master_key_file.exists():
                # Explicit keyring requested: migrate existing file key to keyring.
                key = master_key_file.read_bytes().strip()
                _keyring_set_master_key(key)
                return key

            # No existing key anywhere → create in keyring.
            _ensure_safe_to_generate_master_key()
            key = Fernet.generate_key()
            _keyring_set_master_key(key)
            return key

    # File backend (or auto fallback)
    if not master_key_file.exists():
        # If keyring already holds a key and file backend is forced, keep
        # compatibility by materializing the same key into the file.
        key = _keyring_get_master_key()
        if key is not None and backend == "file":
            ensure_keyvault_dir()
            master_key_file.write_bytes(key)
            try:
                os.chmod(master_key_file, 0o600)
            except OSError:
                pass
            return key
        _ensure_safe_to_generate_master_key()
        return generate_master_key()

    return master_key_file.read_bytes().strip()


def master_key_location() -> str:
    """
    Human-readable current master key location.

    NOTE: This does not reveal the master key itself.
    """
    backend = get_master_key_backend()
    master_key_file = get_master_key_file()
    if backend in {"auto", "keyring"} and _keyring_get_master_key() is not None:
        return "keyring"
    return str(master_key_file)


def master_key_exists() -> bool:
    if _keyring_get_master_key() is not None:
        return True
    return get_master_key_file().exists()


def harden_master_key_to_keyring(delete_file: bool = False) -> bool:
    """
    Migrate an existing file-based master key into the OS keyring.

    Returns True if a key is present in keyring after the operation.
    """
    master_key_file = get_master_key_file()
    key = _keyring_get_master_key()
    if key is None:
        if not master_key_file.exists():
            key = Fernet.generate_key()
        else:
            key = master_key_file.read_bytes().strip()
        _keyring_set_master_key(key)

    if delete_file and master_key_file.exists():
        try:
            master_key_file.unlink()
        except OSError:
            pass

    return _keyring_get_master_key() is not None


def master_key_material() -> bytes:
    """Raw master key material (32 bytes) suitable for HMAC/keyed hashing."""
    return base64.urlsafe_b64decode(_load_master_key())


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns base64-encoded ciphertext."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext string."""
    f = _get_fernet()
    return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
