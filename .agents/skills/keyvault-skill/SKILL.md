---
name: keyvault-skill
description: Manage API keys for LLM agents securely. Encrypted local vault with CLI, Python SDK, and MCP Server support. Replaces scattered .env files.
---

# KeyVault - Complete Usage for Agents

When you (an AI agent) need to handle API keys, tokens, or credentials, use KeyVault instead of plaintext `.env` files or hardcoded values.

## Mandatory Rules

- NEVER create plaintext secret files unless user explicitly requests export.
- NEVER hardcode API keys in source code.
- NEVER commit exported secret files to git.
- ALWAYS prefer project-scoped secrets (`--project`) over global secrets.
- ALWAYS use least-privilege injection (`inject --no-global --key ...`) for command execution.

## Installation

```bash
# Core package
pip install git+https://github.com/ylz201/keyvault.git

# With MCP support
pip install "keyvault-ai[mcp] @ git+https://github.com/ylz201/keyvault.git"

# Verify environment and storage backend
keyvault info
```

## Complete CLI Reference

### `set` - create/update a secret

```bash
keyvault set KEY [VALUE] [--project PROJECT] [--desc TEXT] [--stdin]
```

Examples:

```bash
# hidden prompt (recommended)
keyvault set OPENAI_API_KEY

# value via argument
keyvault set OPENAI_API_KEY sk-xxx

# value from stdin (safe for scripts)
printf 'sk-xxx' | keyvault set OPENAI_API_KEY --stdin

# project-scoped override
keyvault set OPENAI_API_KEY sk-proj --project myapp --desc "OpenAI for myapp"
```

### `get` - read a secret

```bash
keyvault get KEY [--project PROJECT] [--unmask]
```

Examples:

```bash
keyvault get OPENAI_API_KEY
keyvault get OPENAI_API_KEY --project myapp
keyvault get OPENAI_API_KEY --project myapp --unmask
```

### `list` - list stored secrets (metadata only)

```bash
keyvault list [--project PROJECT] [--all]
```

Examples:

```bash
keyvault list
keyvault list --project myapp
keyvault list --all
```

### `delete` - remove a secret

```bash
keyvault delete KEY [--project PROJECT] [--force]
```

Examples:

```bash
keyvault delete OPENAI_API_KEY --project myapp
keyvault delete OPENAI_API_KEY --force
```

### `import` and `export` - dotenv compatibility

```bash
keyvault import FILEPATH [--project PROJECT]
keyvault export [--project PROJECT] [--output FILE]
```

Examples:

```bash
keyvault import .env --project myapp
keyvault export --project myapp --output .env.myapp

# stdout export is possible but handle permissions yourself
keyvault export > .env && chmod 600 .env
```

### `scan-env` - intelligent dotenv scanning and import

```bash
keyvault scan-env [--project PROJECT] [--file FILE ...] [--root DIR] [--recursive] [--all] [--apply/--dry-run] [--force]
```

Examples:

```bash
# preview only (recommended first)
keyvault scan-env --project myapp --dry-run

# import high-confidence secret-like keys from discovered .env files
keyvault scan-env --project myapp --apply
```

### `inject` - run subprocess with env secrets

```bash
keyvault inject [--project PROJECT] [--global/--no-global] [--key KEY ...] -- CMD [ARGS...]
```

Examples:

```bash
# inject global + project scope (default behavior)
keyvault inject --project myapp -- python app.py

# least-privilege injection (recommended)
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python app.py
```

### `info` and `harden` - inspect and harden key storage

```bash
keyvault info
keyvault harden [--delete-file] [--force]
```

Examples:

```bash
# migrate master key to OS keyring and delete legacy key file
keyvault harden --delete-file
```

## Recommended Workflows

### New project setup

```bash
keyvault set OPENAI_API_KEY --project myapp
keyvault set DEEPSEEK_API_KEY --project myapp
keyvault list --project myapp
```

### Rotate a key safely

```bash
keyvault set OPENAI_API_KEY sk-new --project myapp
keyvault get OPENAI_API_KEY --project myapp
```

### Execute app with minimal exposure

```bash
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python run.py
```

### Migrate legacy dotenv safely

```bash
# preview what would be imported
keyvault scan-env --project myapp --dry-run

# apply import
keyvault scan-env --project myapp --apply
```

## Python SDK

```python
from keyvault import get_secret, set_secret, list_secrets, delete_secret

set_secret("OPENAI_API_KEY", "sk-xxx", project="myapp", description="OpenAI key")
value = get_secret("OPENAI_API_KEY", project="myapp", fallback_env=False)
items = list_secrets(project="myapp")
deleted = delete_secret("OPENAI_API_KEY", project="myapp")
```

SDK resolution order for `get_secret`:

1. project scope
2. global scope
3. `os.environ` (only if `fallback_env=True`)

## MCP Server Setup

Start server:

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

Available tools:

- `secrets_list`
- `secrets_get`
- `secrets_set`
- `secrets_delete`

## MCP Policy Variables (Important)

Defaults are restrictive. Configure explicitly before starting MCP server.

| Variable | Default | Purpose |
|---|---|---|
| `KEYVAULT_MCP_ALLOW_LIST` | `0` | Enable `secrets_list` |
| `KEYVAULT_MCP_ALLOW_GET` | `0` | Enable `secrets_get` |
| `KEYVAULT_MCP_ALLOW_SET` | `0` | Enable `secrets_set` |
| `KEYVAULT_MCP_ALLOW_DELETE` | `0` | Enable `secrets_delete` |
| `KEYVAULT_MCP_ALLOW_GLOBAL` | `0` | Allow global scope (otherwise project required) |
| `KEYVAULT_MCP_ALLOW_ALL_SCOPES` | `0` | Allow list across all scopes |
| `KEYVAULT_MCP_ALLOW_ALL_KEYS` | `0` | Allow arbitrary key names for get/set/delete |
| `KEYVAULT_MCP_ALLOWED_KEYS` | unset | Comma-separated key allowlist |
| `KEYVAULT_MCP_INCLUDE_DESCRIPTIONS` | `0` | Include descriptions in list output |

Recommended safe MCP profile:

```bash
export KEYVAULT_MCP_ALLOW_LIST=1
export KEYVAULT_MCP_ALLOW_GET=1
export KEYVAULT_MCP_ALLOW_GLOBAL=0
export KEYVAULT_MCP_ALLOWED_KEYS=OPENAI_API_KEY
python -m keyvault.mcp_server
```

## Runtime/Storage Variables

| Variable | Default | Purpose |
|---|---|---|
| `KEYVAULT_DIR` | unset | Override vault directory |
| `KEYVAULT_HOME` | unset | Alternative vault directory override |
| `KEYVAULT_MASTER_KEY_BACKEND` | `auto` | `auto` / `keyring` / `file` |
| `KEYVAULT_KEYRING_SERVICE` | `keyvault-ai` | Keyring service name |
| `KEYVAULT_KEYRING_USERNAME` | `master-key` | Keyring account key |
| `KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN` | `0` | Force master key regeneration when old key is unavailable (unsafe) |

## Missing Key Prompt Template

If a required key is missing, prompt user with:

`This operation requires OPENAI_API_KEY. Please run: keyvault set OPENAI_API_KEY <your-key> --project <project-name> and then retry.`
