"""Trusted-side SPI. Never expose resolve() as an agent tool."""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import hmac
import os
from typing import Protocol
from .protocol import GatewayError

@dataclass(frozen=True)
class SecretValue:
    value: str = field(repr=False)
    revision: str

class CredentialProvider(Protocol):
    def resolve(self, locator: dict) -> SecretValue: ...

class LocalKeyVaultProvider:
    """Exact project/key lookup; no SDK/global/environment fallback."""
    def resolve(self, locator: dict) -> SecretValue:
        if os.environ.get("KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN", "0").lower() in {"1", "true", "yes", "on", "y"}:
            raise GatewayError("UNSAFE_CONFIGURATION")
        if not locator.get("project"):
            raise GatewayError("INVALID_INPUT")
        from keyvault.store import SecretStore
        from keyvault.crypto import master_key_material
        try:
            value = SecretStore().get(locator["key"], project=locator["project"])
            if value is None:
                raise GatewayError("CREDENTIAL_UNAVAILABLE")
            validate_secret(value)
            revision = hmac.new(master_key_material(), b"keyvault-gateway-revision-v1\0" + value.encode(), hashlib.sha256).hexdigest()
            return SecretValue(value, revision)
        except GatewayError:
            raise
        except Exception:
            raise GatewayError("CREDENTIAL_UNAVAILABLE") from None

def validate_secret(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise GatewayError("INVALID_CREDENTIAL")
