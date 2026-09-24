"""Real legacy encrypted store integration; no OS keyring or network."""
from __future__ import annotations
import pytest
from keyvault.gateway.protocol import GatewayError
from keyvault.gateway.provider import LocalKeyVaultProvider

def test_exact_project_lookup_and_rotation(isolated_keyvault, monkeypatch):
    store = isolated_keyvault["store"].SecretStore()
    store.set("API_KEY", "global-not-authorized")
    monkeypatch.setenv("API_KEY", "environment-not-authorized")
    provider = LocalKeyVaultProvider()
    locator = {"ref": "account", "project": "one", "key": "API_KEY"}
    with pytest.raises(GatewayError, match="CREDENTIAL_UNAVAILABLE"):
        provider.resolve(locator)
    store.set("API_KEY", "project-authorized-key-v1", project="one")
    old = provider.resolve(locator)
    assert old.value == "project-authorized-key-v1"
    store.set("API_KEY", "project-authorized-key-v2", project="one")
    new = provider.resolve(locator)
    assert new.revision != old.revision
    assert new.value not in repr(new)

def test_gateway_refuses_unsafe_recovery_override(monkeypatch):
    monkeypatch.setenv("KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN", "1")
    with pytest.raises(GatewayError, match="UNSAFE_CONFIGURATION"):
        LocalKeyVaultProvider().resolve({"project": "one", "key": "API_KEY"})
