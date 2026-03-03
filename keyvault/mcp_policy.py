from __future__ import annotations

import os
from dataclasses import dataclass

from keyvault.validation import parse_csv, validate_key_name, validate_project_name


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class MCPPolicy:
    allow_list: bool
    allow_get: bool
    allow_set: bool
    allow_delete: bool
    allow_global: bool
    allow_all_scopes: bool
    allow_all_keys: bool
    include_descriptions: bool
    allowed_keys: set[str] | None


def load_mcp_policy() -> MCPPolicy:
    allowed_keys_list = [validate_key_name(k) for k in parse_csv(os.environ.get("KEYVAULT_MCP_ALLOWED_KEYS"))]
    allowed_keys = set(allowed_keys_list) if allowed_keys_list else None

    return MCPPolicy(
        allow_list=_env_bool("KEYVAULT_MCP_ALLOW_LIST", False),
        allow_get=_env_bool("KEYVAULT_MCP_ALLOW_GET", False),
        allow_set=_env_bool("KEYVAULT_MCP_ALLOW_SET", False),
        allow_delete=_env_bool("KEYVAULT_MCP_ALLOW_DELETE", False),
        allow_global=_env_bool("KEYVAULT_MCP_ALLOW_GLOBAL", False),
        allow_all_scopes=_env_bool("KEYVAULT_MCP_ALLOW_ALL_SCOPES", False),
        allow_all_keys=_env_bool("KEYVAULT_MCP_ALLOW_ALL_KEYS", False),
        include_descriptions=_env_bool("KEYVAULT_MCP_INCLUDE_DESCRIPTIONS", False),
        allowed_keys=allowed_keys,
    )


def require_project_if_needed(project: str | None, policy: MCPPolicy) -> str | None:
    if project is None:
        if policy.allow_global:
            return None
        raise ValueError("Project scope is required for MCP operations (set KEYVAULT_MCP_ALLOW_GLOBAL=1 to allow global).")
    return validate_project_name(project)


def require_key_allowed(key: str, policy: MCPPolicy) -> str:
    key = validate_key_name(key)
    if policy.allowed_keys is not None and key not in policy.allowed_keys:
        raise ValueError("Key is not allowed by KEYVAULT_MCP_ALLOWED_KEYS policy.")
    if policy.allowed_keys is None and not policy.allow_all_keys:
        raise ValueError(
            "Refusing to operate on arbitrary keys. Set KEYVAULT_MCP_ALLOWED_KEYS to an allowlist, "
            "or set KEYVAULT_MCP_ALLOW_ALL_KEYS=1 to allow all keys."
        )
    return key


def filter_allowed_keys(keys: list[str], policy: MCPPolicy) -> list[str]:
    if policy.allowed_keys is not None:
        return [k for k in keys if k in policy.allowed_keys]
    if policy.allow_all_keys:
        return keys
    return []
