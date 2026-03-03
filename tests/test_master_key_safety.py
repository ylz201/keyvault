from __future__ import annotations

import importlib

import pytest


def test_auto_backend_refuses_silent_regen_with_existing_data(isolated_keyvault, monkeypatch):
    crypto = isolated_keyvault["crypto"]
    store_mod = isolated_keyvault["store"]

    store = store_mod.SecretStore()
    store.set("OPENAI_API_KEY", "sk-old", project="proj")

    master_key_file = crypto.get_master_key_file()
    assert master_key_file.exists()
    master_key_file.unlink()

    monkeypatch.setenv("KEYVAULT_MASTER_KEY_BACKEND", "auto")

    import keyvault.crypto as crypto_mod
    import keyvault.store as store_mod_reloaded

    importlib.reload(crypto_mod)
    importlib.reload(store_mod_reloaded)
    monkeypatch.setattr(crypto_mod, "keyring", None)

    with pytest.raises(RuntimeError, match="Refusing to generate a new master key"):
        store_mod_reloaded.SecretStore()


def test_can_force_master_key_regen_with_explicit_override(isolated_keyvault, monkeypatch):
    crypto = isolated_keyvault["crypto"]
    store_mod = isolated_keyvault["store"]

    store = store_mod.SecretStore()
    store.set("OPENAI_API_KEY", "sk-old", project="proj")

    master_key_file = crypto.get_master_key_file()
    assert master_key_file.exists()
    master_key_file.unlink()

    monkeypatch.setenv("KEYVAULT_MASTER_KEY_BACKEND", "auto")
    monkeypatch.setenv("KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN", "1")

    import keyvault.crypto as crypto_mod
    import keyvault.store as store_mod_reloaded

    importlib.reload(crypto_mod)
    importlib.reload(store_mod_reloaded)
    monkeypatch.setattr(crypto_mod, "keyring", None)

    store_mod_reloaded.SecretStore()
    assert crypto_mod.get_master_key_file().exists()
