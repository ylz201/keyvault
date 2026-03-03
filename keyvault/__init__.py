"""
KeyVault — Lightweight secrets manager for LLM Agents.

Usage as SDK:
    from keyvault import get_secret, set_secret, list_secrets, delete_secret
"""

from keyvault.store import SecretStore

__version__ = "0.1.0"

# Lazy-initialized default store
_default_store: SecretStore | None = None


def _get_store() -> SecretStore:
    """Get or create the default store instance."""
    global _default_store
    if _default_store is None:
        _default_store = SecretStore()
    return _default_store


def get_secret(key: str, project: str | None = None, fallback_env: bool = True) -> str | None:
    """
    Get a secret value by key.
    
    Priority: project-specific → global → os.environ (if fallback_env=True)
    """
    import os
    store = _get_store()
    
    # Try project-specific first
    if project:
        val = store.get(key, project=project)
        if val is not None:
            return val
    
    # Try global
    val = store.get(key, project=None)
    if val is not None:
        return val
    
    # Fallback to env
    if fallback_env:
        return os.environ.get(key)
    
    return None


def set_secret(key: str, value: str, project: str | None = None, description: str | None = None) -> None:
    """Set a secret value."""
    store = _get_store()
    store.set(key, value, project=project, description=description)


def list_secrets(project: str | None = None) -> list[dict]:
    """List all secret keys (values are masked)."""
    store = _get_store()
    return store.list(project=project)


def delete_secret(key: str, project: str | None = None) -> bool:
    """Delete a secret. Returns True if deleted."""
    store = _get_store()
    return store.delete(key, project=project)
