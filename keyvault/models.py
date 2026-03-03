"""
Data models for KeyVault.
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Secret:
    """Represents a stored secret."""
    key: str
    value: str  # plaintext (decrypted)
    project: str | None = None  # None = global
    description: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def masked_value(self) -> str:
        """Return a masked version of the value for display."""
        v = self.value
        if len(v) <= 8:
            return "••••••••"
        return f"{v[:4]}••••••••{v[-4:]}"

    def scope_label(self) -> str:
        """Human-readable scope label."""
        return f"project:{self.project}" if self.project else "global"


@dataclass
class SecretMetadata:
    """Non-sensitive metadata for a stored secret (value not included)."""
    key: str
    project: str | None = None  # None = global
    description: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def scope_label(self) -> str:
        """Human-readable scope label."""
        return f"project:{self.project}" if self.project else "global"
