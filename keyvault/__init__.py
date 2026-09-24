"""KeyVault: administrator SDK and agent credential gateway.

The legacy plaintext SDK is for trusted applications, NOT an agent tool surface.
Importing the package does not open a vault, keyring, or gateway database.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from keyvault.store import SecretStore
__version__ = "0.2.0"
_default_store: SecretStore | None = None

def _get_store():
    global _default_store
    if _default_store is None:
        from keyvault.store import SecretStore
        _default_store = SecretStore()
    return _default_store

def get_secret(key: str, project: str | None = None, fallback_env: bool = True) -> str | None:
    """Legacy administrator SDK: project, then global, then optional environment."""
    import os
    store = _get_store()
    if project:
        value = store.get(key, project=project)
        if value is not None:
            return value
    value = store.get(key, project=None)
    return value if value is not None else (os.environ.get(key) if fallback_env else None)

def set_secret(key: str, value: str, project: str | None = None, description: str | None = None) -> None:
    _get_store().set(key, value, project=project, description=description)

def list_secrets(project: str | None = None) -> list:
    return _get_store().list(project=project)

def delete_secret(key: str, project: str | None = None) -> bool:
    return _get_store().delete(key, project=project)
