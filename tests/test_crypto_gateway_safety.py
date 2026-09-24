from __future__ import annotations
import importlib
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from cryptography.fernet import Fernet
import pytest
from keyvault.process_env import injection_environment

class Ring:
    value = None
    fail_write = False
    def get_password(self, *args):
        return self.value
    def set_password(self, service, user, value):
        if self.fail_write:
            raise RuntimeError("simulated write failure")
        self.value = value

@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYVAULT_DIR", str(tmp_path / "vault"))
    monkeypatch.setenv("KEYVAULT_MASTER_KEY_BACKEND", "file")
    monkeypatch.delenv("KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN", raising=False)
    import keyvault.crypto as crypto
    importlib.reload(crypto)
    ring = Ring(); monkeypatch.setattr(crypto, "keyring", ring)
    crypto.ensure_keyvault_dir()
    return crypto, ring

def write_data(crypto, key):
    with sqlite3.connect(str(crypto.get_keyvault_dir() / "vault.db")) as db:
        db.execute("CREATE TABLE secrets(value TEXT)")
        db.execute("INSERT INTO secrets VALUES(?)", (Fernet(key).encrypt(b"only-test-secret").decode(),))

@pytest.mark.parametrize("backend", ["auto", "keyring", "file"])
def test_all_missing_key_paths_fail_closed(vault, monkeypatch, backend):
    crypto, ring = vault
    write_data(crypto, Fernet.generate_key())
    monkeypatch.setenv("KEYVAULT_MASTER_KEY_BACKEND", backend)
    with pytest.raises(RuntimeError, match="Refusing to generate"):
        crypto._load_master_key()
    assert ring.value is None and not crypto.get_master_key_file().exists()

def test_harden_missing_key_with_data_fails(vault):
    crypto, ring = vault
    write_data(crypto, Fernet.generate_key())
    with pytest.raises(RuntimeError, match="Refusing to generate"):
        crypto.harden_master_key_to_keyring(delete_file=True)
    assert ring.value is None

def test_conflicting_keys_preserve_recovery_file(vault):
    crypto, ring = vault
    original = crypto.generate_master_key(); write_data(crypto, original)
    ring.value = Fernet.generate_key().decode()
    with pytest.raises(RuntimeError, match="Conflicting"):
        crypto.harden_master_key_to_keyring(delete_file=True)
    assert crypto.get_master_key_file().read_bytes() == original

def test_keyring_write_failure_keeps_file(vault):
    crypto, ring = vault
    original = crypto.generate_master_key(); ring.fail_write = True
    with pytest.raises(RuntimeError):
        crypto.harden_master_key_to_keyring(delete_file=True)
    assert crypto.get_master_key_file().read_bytes() == original

def test_verified_harden_preserves_readability(vault, monkeypatch):
    crypto, ring = vault
    original = crypto.generate_master_key(); write_data(crypto, original)
    assert crypto.harden_master_key_to_keyring(delete_file=True)
    assert not crypto.get_master_key_file().exists() and ring.value == original.decode()
    monkeypatch.setenv("KEYVAULT_MASTER_KEY_BACKEND", "keyring")
    assert crypto._load_master_key() == original

def test_corrupt_data_prevents_recovery_key_deletion(vault):
    crypto, ring = vault
    original = crypto.generate_master_key(); write_data(crypto, Fernet.generate_key())
    with pytest.raises(RuntimeError, match="does not decrypt"):
        crypto.harden_master_key_to_keyring(delete_file=True)
    assert crypto.get_master_key_file().exists() and ring.value is None

def test_concurrent_initializers_share_one_key(vault):
    crypto, _ = vault
    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda _: crypto._load_master_key(), range(20)))
    assert len(set(keys)) == 1

def test_changing_vault_directory_does_not_reuse_cipher(vault, tmp_path, monkeypatch):
    crypto, _ = vault
    old = crypto._get_fernet()
    monkeypatch.setenv("KEYVAULT_DIR", str(tmp_path / "other-vault"))
    new = crypto._get_fernet()
    assert old is not new
    with pytest.raises(Exception):
        new.decrypt(old.encrypt(b"test"))

def test_invalid_keyring_key_does_not_trigger_regeneration(vault, monkeypatch):
    crypto, ring = vault; ring.value = "invalid-base64-key"
    monkeypatch.setenv("KEYVAULT_MASTER_KEY_BACKEND", "auto")
    with pytest.raises(RuntimeError, match="Invalid master key"):
        crypto._load_master_key()
    assert ring.value == "invalid-base64-key" and not crypto.get_master_key_file().exists()

def test_parent_environment_not_inherited(monkeypatch):
    monkeypatch.setenv("PARENT_SECRET", "must-not-leak")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.example")
    monkeypatch.setenv("PYTHONPATH", "/attacker/code")
    class Store:
        def get(self, key, project=None):
            return "chosen-test-key" if project == "p" else "global-key"
    env = injection_environment(Store(), ["API_KEY"], "p")
    assert env["API_KEY"] == "chosen-test-key"
    assert not {"PARENT_SECRET", "HTTPS_PROXY", "PYTHONPATH"} & env.keys()

def test_missing_key_does_not_fallback_to_global_or_env(monkeypatch):
    monkeypatch.setenv("API_KEY", "must-not-use")
    class Store:
        def get(self, key, project=None):
            return "global-key" if project is None else None
    with pytest.raises(ValueError):
        injection_environment(Store(), ["API_KEY"], "missing")
    assert injection_environment(Store(), ["API_KEY"], "missing", include_global=True)["API_KEY"] == "global-key"
