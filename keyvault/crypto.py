"""Fernet storage with guarded master-key creation and verified keyring migration."""
from __future__ import annotations
import base64
from contextlib import contextmanager
import hmac
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import Literal
from cryptography.fernet import Fernet
try:
    import keyring
except ImportError:
    keyring = None

MasterKeyBackend = Literal["auto", "file", "keyring"]
_thread_lock = threading.RLock()
_fernet_instance: Fernet | None = None
_fernet_key: bytes | None = None

def get_keyvault_dir() -> Path:
    return Path(os.environ.get("KEYVAULT_DIR") or os.environ.get("KEYVAULT_HOME") or Path.home() / ".keyvault").expanduser()

def get_master_key_file() -> Path:
    return get_keyvault_dir() / "master.key"

def _keyring_service():
    return os.environ.get("KEYVAULT_KEYRING_SERVICE", "keyvault-ai")

def _keyring_username():
    return os.environ.get("KEYVAULT_KEYRING_USERNAME", "master-key")

def get_master_key_backend() -> MasterKeyBackend:
    value = os.environ.get("KEYVAULT_MASTER_KEY_BACKEND", "auto").strip().lower()
    if value not in {"auto", "file", "keyring"}:
        raise RuntimeError("Invalid master key backend")
    return value

def _keyring_supported():
    if keyring is None:
        return False
    try:
        keyring.get_password(_keyring_service(), _keyring_username())
        return True
    except Exception:
        return False

def _env_bool(name, default=False):
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "y", "on"}

def _allow_unsafe_master_key_regen():
    return _env_bool("KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN")

def _vault_contains_data():
    path = get_keyvault_dir() / "vault.db"
    if not path.exists():
        return False
    try:
        with sqlite3.connect(str(path)) as db:
            for table in ("secrets", "secrets_v1", "secrets_new"):
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    if db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                        return True
        return False
    except Exception:
        return True

def _ensure_safe_to_generate_master_key():
    if _vault_contains_data() and not _allow_unsafe_master_key_regen():
        raise RuntimeError("Refusing to generate a new master key because existing vault data was detected. Restore the original key.")

def _valid_key(raw):
    try:
        Fernet(raw)
        return raw
    except Exception:
        raise RuntimeError("Invalid master key; restore the original key") from None

def _keyring_get_master_key():
    if not _keyring_supported():
        return None
    value = keyring.get_password(_keyring_service(), _keyring_username())
    return _valid_key(value.strip().encode()) if value else None

def _keyring_set_master_key(key):
    if not _keyring_supported():
        raise RuntimeError("Keyring backend not available")
    _valid_key(key)
    keyring.set_password(_keyring_service(), _keyring_username(), key.decode())
    saved = _keyring_get_master_key()
    if saved is None or not hmac.compare_digest(saved, key):
        raise RuntimeError("Keyring write verification failed")

def ensure_keyvault_dir():
    path = get_keyvault_dir()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("Vault directory cannot be a symlink")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise RuntimeError("Vault directory must be owned by the current user")
    os.chmod(path, 0o700)
    return path

@contextmanager
def _locked():
    with _thread_lock:
        path = ensure_keyvault_dir() / ".master-key.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RuntimeError("Invalid key lock")
            if os.name == "posix":
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            elif os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                raise RuntimeError("Unsupported master-key locking platform")
            yield
        finally:
            os.close(fd)

def _read_file_key():
    fd = os.open(get_master_key_file(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("Invalid master key file")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise RuntimeError("Foreign master key owner")
        if hasattr(os, "fchmod"):
            os.fchmod(f.fileno(), 0o600)
        return _valid_key(f.read(256).strip())

def _write_new_file_key(key):
    fd = os.open(get_master_key_file(), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(_valid_key(key)); f.flush(); os.fsync(f.fileno())
    return key

def _verify_existing_values(key):
    """Before deleting a recovery key, prove the chosen key decrypts existing values."""
    path = get_keyvault_dir() / "vault.db"
    if not path.exists():
        return
    try:
        cipher = Fernet(key)
        with sqlite3.connect(str(path)) as db:
            for table in ("secrets", "secrets_v1", "secrets_new"):
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    for row in db.execute(f"SELECT value FROM {table}"):
                        cipher.decrypt(row[0].encode())
    except Exception:
        raise RuntimeError("Master key does not decrypt existing vault data; no recovery key was removed") from None

def generate_master_key():
    """Initialize, never rotate or overwrite an existing key."""
    with _locked():
        if get_master_key_file().exists():
            return _read_file_key()
        _ensure_safe_to_generate_master_key()
        return _write_new_file_key(Fernet.generate_key())

def _load_master_key():
    with _locked():
        backend = get_master_key_backend()
        if get_master_key_file().is_symlink():
            raise RuntimeError("Master key path cannot be a symlink")
        file_key = _read_file_key() if get_master_key_file().exists() else None
        if backend == "file" and file_key is not None:
            return file_key
        ring_key = _keyring_get_master_key()
        if ring_key is not None:
            _verify_existing_values(ring_key)
            if file_key is not None and not hmac.compare_digest(ring_key, file_key):
                raise RuntimeError("Conflicting file and keyring master keys; refusing automatic selection")
            if backend == "file":
                return _write_new_file_key(ring_key)
            return ring_key
        if backend == "keyring":
            if file_key is not None:
                _verify_existing_values(file_key)
                _keyring_set_master_key(file_key)
                return file_key
            _ensure_safe_to_generate_master_key()
            key = Fernet.generate_key()
            _keyring_set_master_key(key)
            return key
        if file_key is not None:
            return file_key
        # All initialization paths use the same existing-data guard.
        _ensure_safe_to_generate_master_key()
        key = Fernet.generate_key()
        if backend == "auto" and _keyring_supported():
            _keyring_set_master_key(key)
            return key
        return _write_new_file_key(key)

def harden_master_key_to_keyring(delete_file=False):
    with _locked():
        if get_master_key_file().is_symlink():
            raise RuntimeError("Master key path cannot be a symlink")
        file_key = _read_file_key() if get_master_key_file().exists() else None
        ring_key = _keyring_get_master_key()
        if file_key is not None and ring_key is not None and not hmac.compare_digest(file_key, ring_key):
            raise RuntimeError("Conflicting master keys; refusing to remove the file key")
        key = file_key or ring_key
        if key is None:
            _ensure_safe_to_generate_master_key()
            key = Fernet.generate_key()
        _verify_existing_values(key)
        _keyring_set_master_key(key)
        if delete_file and get_master_key_file().exists():
            get_master_key_file().unlink()
        return True

def master_key_location():
    backend = get_master_key_backend()
    if backend != "file" and _keyring_get_master_key() is not None:
        return "keyring"
    return str(get_master_key_file())

def master_key_exists():
    return get_master_key_file().exists() or _keyring_get_master_key() is not None

def master_key_material():
    return base64.urlsafe_b64decode(_load_master_key())

def _get_fernet():
    global _fernet_instance, _fernet_key
    # Key changes / vault directory changes must not reuse a stale cipher instance.
    key = _load_master_key()
    if _fernet_instance is None or _fernet_key != key:
        _fernet_instance, _fernet_key = Fernet(key), key
    return _fernet_instance

def encrypt(plaintext):
    return _get_fernet().encrypt(plaintext.encode()).decode()

def decrypt(ciphertext):
    return _get_fernet().decrypt(ciphertext.encode()).decode()
