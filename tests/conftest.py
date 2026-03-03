from __future__ import annotations

import importlib
import uuid

import pytest


@pytest.fixture()
def isolated_keyvault(tmp_path, monkeypatch):
    """
    Isolate KeyVault state from the user's real machine.

    - Uses a temp KEYVAULT_DIR
    - Forces master key backend to file (avoid touching OS keyring in tests)
    - Resets module-level caches via reload
    """
    kv_dir = tmp_path / "keyvault-home"
    monkeypatch.setenv("KEYVAULT_DIR", str(kv_dir))
    monkeypatch.setenv("KEYVAULT_MASTER_KEY_BACKEND", "file")
    monkeypatch.setenv("KEYVAULT_KEYRING_SERVICE", f"keyvault-ai-test-{uuid.uuid4()}")

    import keyvault.crypto as crypto
    import keyvault.store as store
    import keyvault as kv
    import keyvault.cli as cli

    importlib.reload(crypto)
    importlib.reload(store)
    importlib.reload(kv)
    importlib.reload(cli)

    return {
        "dir": kv_dir,
        "crypto": crypto,
        "store": store,
        "kv": kv,
        "cli": cli,
    }

