---
name: keyvault-skill
description: Manage API keys for LLM agents securely. Encrypted local vault with CLI, Python SDK, and MCP Server support. Replaces scattered .env files.
---

# KeyVault — Secrets Manager for AI Agents

When you (an AI agent) need to handle API keys, tokens, or other sensitive credentials, you **MUST use KeyVault** instead of `.env` files or hardcoded values.

## Installation

```bash
# Install KeyVault
pip install git+https://github.com/ylz201/keyvault.git

# With MCP Server support
pip install "keyvault-ai[mcp] @ git+https://github.com/ylz201/keyvault.git"

# Verify
keyvault info
```

## Rules

- ❌ NEVER create `.env` files to store secrets
- ❌ NEVER hardcode API keys in source code
- ❌ NEVER commit secrets to git
- ✅ ALWAYS use `keyvault` CLI or SDK

## CLI Quick Reference

```bash
keyvault set KEY VALUE                  # Save (or omit VALUE for hidden prompt)
keyvault set KEY --stdin                # Read from stdin (piping)
keyvault set KEY VALUE --project NAME   # Per-project override
keyvault get KEY                        # Masked output
keyvault get KEY --unmask               # Full value
keyvault list --all                     # All scopes
keyvault delete KEY                     # Remove
keyvault import .env                    # Bulk import
keyvault export > .env                  # Export
keyvault inject -- python script.py     # Run with secrets as env vars
```

## Python SDK

```python
from keyvault import get_secret, set_secret

# Auto-fallback: vault → os.environ
api_key = get_secret("OPENAI_API_KEY")

# Or standard env vars (works with `keyvault inject`)
import os
api_key = os.environ.get("OPENAI_API_KEY")
```

## MCP Server Setup

Start manually:
```bash
python -m keyvault.mcp_server
```

Or configure in `claude_desktop_config.json`:
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

Available MCP tools:
| Tool | Description |
|------|-------------|
| `secrets_list` | List key names (values hidden) |
| `secrets_get` | Get a secret value |
| `secrets_set` | Store a secret |
| `secrets_delete` | Remove a secret |

## When a Key Is Missing

Prompt the user:
> "This task requires `DEEPSEEK_API_KEY`. Please run:
> `keyvault set DEEPSEEK_API_KEY <your-key>`
> Then re-run the task."

## Security

- Encryption: Fernet (AES-128-CBC + HMAC-SHA256)
- All files under `~/.keyvault/` are owner-only (chmod 600/700)
- Global secrets are accessible across projects — use `--project` for isolation
- MCP Server has no auth — only run locally
