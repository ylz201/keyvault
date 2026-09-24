# KeyVault — Agent Credential Gateway

**让 Agent 使用账号，而不是领取密码。** An independent, self-hosted credential-use gateway; ABO is a prospective client, not a dependency.

Version **0.2.0, alpha / POSIX reference deployment**. This repository does not claim a production security certification, complete OAuth support, or compatibility with Muse's internal credential store. Installing from source does not publish a new PyPI release.

## What is implemented

- A separate local gateway daemon with authenticated clients, workspace-scoped grants, expiry, finite use limits and revocation.
- Immutable administrator-registered **HTTPS GET** profiles. Agents cannot provide a URL, headers, request body, shell command, project or identity.
- Exact-scope local KeyVault provider; keyed credential revisions invalidate use after a stored key changes. No global/environment fallback.
- Durable SQLite reservation, request-ID deduplication, restart-safe non-resubmission and secret-free usage audit. A successful HTTP projection is **not** business completion.
- Pinned public DNS destinations, verified TLS hostname, no redirects, no environment proxies, bounded response processing.
- Closed response projections: integers, booleans and administrator-defined string enums. No unrestricted upstream JSON, headers or cookies.
- Agent JSON CLI, local Unix RPC and a thin MCP stdio bridge sharing the same broker.
- Existing local encrypted secrets backend and human administrator SDK/CLI, with safer key initialization and subprocess injection.

## Quick test — no real account or network

```bash
python -m pip install -e '.[mcp,dev]'
python -m pytest -q
keyvault-gateway demo
```

The demo uses an isolated temporary database and fake credentials. It proves successful projection, repeat-request reuse, cross-client denial and revocation without contacting a real service. See [QUICKSTART.md](QUICKSTART.md) for real local setup.

## The security boundary

```text
ABO / another agent client
    -> JSON CLI or MCP bridge (client token only)
    -> authenticated Unix RPC
    -> KeyVault gateway (grants + immutable operations + audit)
    -> trusted provider + fixed HTTPS executor
    -> allowed external API
```

**Separate OS users/containers are necessary to isolate an untrusted shell.** A same-user demo does not prevent that user from opening the vault database or keyring. Never give an agent shell access to the gateway's state, upstream credentials, administrator token provisioning or executable code.

The gateway retains only hashed client tokens. Client tokens themselves are sensitive, scoped authorization credentials; they are not upstream API keys. Keep them out of model prompts and traces too.

## Agent interface

```bash
# Environment contains paths only, not upstream keys.
export KEYVAULT_GATEWAY_SOCKET=/run/keyvault/rpc.sock
export KEYVAULT_GATEWAY_TOKEN_FILE=/private/agent/keyvault-client.token

keyvault-gateway list
keyvault-gateway use quota-grant --request-id 11111111-1111-4111-8111-111111111111
keyvault-gateway status 11111111-1111-4111-8111-111111111111
```

Use a fresh UUID for a genuinely new request; reuse it to inspect/replay an earlier request. Never automatically change the UUID to retry an unknown result.

MCP configuration, for clients supporting local stdio servers:

```json
{
  "mcpServers": {
    "keyvault": {
      "command": "python",
      "args": ["-m", "keyvault.mcp_server"],
      "env": {
        "KEYVAULT_GATEWAY_SOCKET": "/run/keyvault/rpc.sock",
        "KEYVAULT_GATEWAY_TOKEN_FILE": "/private/agent/keyvault-client.token"
      }
    }
  }
}
```

Tools: `credentials_list`, `credential_use`, `credential_status`. The bridge does not open the vault. **`secrets_get/set/delete` are removed from MCP**, even if old `KEYVAULT_MCP_ALLOW_*` variables are set. Vendor applications still require their own installation/connection validation; a tested MCP subprocess is not a claim of end-to-end deployment in every client.

## Administrator tools remain separate

```bash
# Run as the trusted vault administrator, never through the agent tool surface.
keyvault set SERVICE_API_KEY_V1 --project gateway-dev
keyvault info
keyvault harden --delete-file

# Legacy trusted-process injection: explicit keys and no parent environment inheritance.
keyvault inject --project gateway-dev --no-global --key SERVICE_API_KEY_V1 -- /absolute/path/to/python trusted_app.py
```

`get --unmask`, export and the Python `get_secret` SDK deliberately remain plaintext **administrator** features. They are not agent-safe. The legacy Python SDK retains its documented fallback for compatibility; the gateway does not use that fallback.

## Explicitly not implemented yet

Public/remote HTTP serving, OAuth registration/refresh, passwords/passkeys/MFA UI, browser sessions, external Vault backends, arbitrary request parameters, external writes, business approval attestations, managed multitenant hosting and automatic upstream token revocation. Do not put a generic TCP tunnel in front of this Unix service and call it secure remote deployment.

## Documentation

- [Quick start](QUICKSTART.md)
- [Architecture and boundaries](docs/ARCHITECTURE.md)
- [Protocol](docs/PROTOCOL.md)
- [Threat model and deployment](SECURITY.md)
- [Migration from 0.1](docs/MIGRATION.md)
- [Roadmap](docs/ROADMAP.md)

MIT. No original xvisa or ABO repository is changed by this project.
