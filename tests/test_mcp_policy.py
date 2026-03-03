from __future__ import annotations

import pytest


def test_mcp_policy_defaults(monkeypatch):
    monkeypatch.delenv("KEYVAULT_MCP_ALLOW_LIST", raising=False)
    monkeypatch.delenv("KEYVAULT_MCP_ALLOW_GET", raising=False)
    monkeypatch.delenv("KEYVAULT_MCP_ALLOW_SET", raising=False)
    monkeypatch.delenv("KEYVAULT_MCP_ALLOW_DELETE", raising=False)
    monkeypatch.delenv("KEYVAULT_MCP_ALLOWED_KEYS", raising=False)
    monkeypatch.delenv("KEYVAULT_MCP_ALLOW_ALL_KEYS", raising=False)
    monkeypatch.delenv("KEYVAULT_MCP_ALLOW_GLOBAL", raising=False)

    from keyvault.mcp_policy import load_mcp_policy, require_key_allowed, require_project_if_needed

    policy = load_mcp_policy()
    assert policy.allow_list is False
    assert policy.allow_get is False
    assert policy.allow_set is False
    assert policy.allow_delete is False

    with pytest.raises(ValueError):
        require_project_if_needed(None, policy)

    with pytest.raises(ValueError):
        require_key_allowed("OPENAI_API_KEY", policy)


def test_mcp_policy_list_filters_to_none_by_default(monkeypatch):
    monkeypatch.delenv("KEYVAULT_MCP_ALLOWED_KEYS", raising=False)
    monkeypatch.delenv("KEYVAULT_MCP_ALLOW_ALL_KEYS", raising=False)

    from keyvault.mcp_policy import filter_allowed_keys, load_mcp_policy

    policy = load_mcp_policy()
    assert filter_allowed_keys(["OPENAI_API_KEY", "DEEPSEEK_API_KEY"], policy) == []


def test_mcp_policy_allowlisted_key(monkeypatch):
    monkeypatch.setenv("KEYVAULT_MCP_ALLOWED_KEYS", "OPENAI_API_KEY")

    from keyvault.mcp_policy import load_mcp_policy, require_key_allowed

    policy = load_mcp_policy()
    assert require_key_allowed("OPENAI_API_KEY", policy) == "OPENAI_API_KEY"
    with pytest.raises(ValueError):
        require_key_allowed("NOT_ALLOWED", policy)
