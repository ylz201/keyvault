---
name: secrets-manager
description: Guides AI agents on how to securely manage API keys using KeyVault. Includes installation, CLI usage, Python SDK, and MCP Server setup.
---

# KeyVault Secrets Manager - Complete Usage

Use this guide when an agent needs to read, write, rotate, inject, or expose credentials safely through KeyVault.

## Core Rules

- Do not store secrets in plaintext files unless export is explicitly requested.
- Do not print full secret values unless the user explicitly asks.
- Prefer project scope over global scope.
- Prefer allowlisted key injection over injecting everything.
- For MCP, keep restrictive policy defaults unless user asks to open access.

## Install and Verify

```bash
pip install git+https://github.com/ylz201/keyvault.git
pip install "keyvault-ai[mcp] @ git+https://github.com/ylz201/keyvault.git"
keyvault info
```

## Full CLI Usage

### Set secret

```bash
keyvault set KEY [VALUE] [--project PROJECT] [--desc TEXT] [--stdin]
```

```bash
keyvault set OPENAI_API_KEY
keyvault set OPENAI_API_KEY sk-xxx --project myapp
printf 'sk-xxx' | keyvault set OPENAI_API_KEY --stdin --project myapp
```

### Get secret

```bash
keyvault get KEY [--project PROJECT] [--unmask]
```

### List secrets

```bash
keyvault list [--project PROJECT] [--all]
```

### Delete secret

```bash
keyvault delete KEY [--project PROJECT] [--force]
```

### Import/Export dotenv

```bash
keyvault import FILEPATH [--project PROJECT]
keyvault export [--project PROJECT] [--output FILE]
```

```bash
keyvault import .env --project myapp
keyvault export --project myapp --output .env.myapp
```

### Inject into subprocess

```bash
keyvault inject [--project PROJECT] [--global/--no-global] [--key KEY ...] -- CMD [ARGS...]
```

```bash
# recommended least privilege mode
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python app.py
```

### Info and hardening

```bash
keyvault info
keyvault harden [--delete-file] [--force]
```

## Typical Agent Flows

### Create project secrets

```bash
keyvault set OPENAI_API_KEY --project myapp
keyvault set DEEPSEEK_API_KEY --project myapp
```

### Run script with scoped credentials

```bash
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python run.py
```

### Rotate and verify

```bash
keyvault set OPENAI_API_KEY sk-new --project myapp
keyvault get OPENAI_API_KEY --project myapp
```

## Python SDK

```python
from keyvault import get_secret, set_secret, list_secrets, delete_secret

set_secret("OPENAI_API_KEY", "sk-xxx", project="myapp")
value = get_secret("OPENAI_API_KEY", project="myapp", fallback_env=False)
items = list_secrets(project="myapp")
ok = delete_secret("OPENAI_API_KEY", project="myapp")
```

`get_secret` lookup order:

1. project scope
2. global scope
3. `os.environ` (if `fallback_env=True`)

## MCP Setup

```bash
python -m keyvault.mcp_server
```

Claude Desktop config:

```json
{
  "mcpServers": {
    "keyvault": {
      "command": "python",
      "args": ["-m", "keyvault.mcp_server"]
    }
  }
}
```

Tools:

- `secrets_list`
- `secrets_get`
- `secrets_set`
- `secrets_delete`

## MCP Policy Variables

| Variable | Default | Effect |
|---|---|---|
| `KEYVAULT_MCP_ALLOW_LIST` | `0` | enable `secrets_list` |
| `KEYVAULT_MCP_ALLOW_GET` | `0` | enable `secrets_get` |
| `KEYVAULT_MCP_ALLOW_SET` | `0` | enable `secrets_set` |
| `KEYVAULT_MCP_ALLOW_DELETE` | `0` | enable `secrets_delete` |
| `KEYVAULT_MCP_ALLOW_GLOBAL` | `0` | allow global scope (else project required) |
| `KEYVAULT_MCP_ALLOW_ALL_SCOPES` | `0` | allow list across all scopes |
| `KEYVAULT_MCP_ALLOW_ALL_KEYS` | `0` | allow arbitrary key names |
| `KEYVAULT_MCP_ALLOWED_KEYS` | unset | comma-separated allowed key names |
| `KEYVAULT_MCP_INCLUDE_DESCRIPTIONS` | `0` | show descriptions in list output |

Safe MCP baseline:

```bash
export KEYVAULT_MCP_ALLOW_LIST=1
export KEYVAULT_MCP_ALLOW_GET=1
export KEYVAULT_MCP_ALLOW_GLOBAL=0
export KEYVAULT_MCP_ALLOWED_KEYS=OPENAI_API_KEY
python -m keyvault.mcp_server
```

## Runtime Variables

| Variable | Default | Purpose |
|---|---|---|
| `KEYVAULT_DIR` | unset | override vault directory |
| `KEYVAULT_HOME` | unset | alternative vault dir override |
| `KEYVAULT_MASTER_KEY_BACKEND` | `auto` | `auto` / `keyring` / `file` |
| `KEYVAULT_KEYRING_SERVICE` | `keyvault-ai` | keyring service namespace |
| `KEYVAULT_KEYRING_USERNAME` | `master-key` | keyring account key |
| `KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN` | `0` | force master key regeneration when old key is unavailable (unsafe) |

## Missing Key Prompt

Use this prompt:

`This operation requires OPENAI_API_KEY. Please run: keyvault set OPENAI_API_KEY <your-key> --project <project-name> and retry.`
