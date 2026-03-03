---
name: secrets-manager
description: Guides AI agents on how to securely manage API keys using KeyVault. Includes installation, CLI usage, Python SDK, and MCP Server setup.
---

# KeyVault — Secrets Manager for AI Agents

When you (an AI agent) need to handle API keys, tokens, or other sensitive credentials in any project, you **MUST use KeyVault**.

## Installation

```bash
# Install from GitHub
pip install git+https://github.com/ylz201/keyvault.git

# Or with MCP Server support
pip install "keyvault-ai[mcp] @ git+https://github.com/ylz201/keyvault.git"
```

Verify installation:
```bash
keyvault info
```

## ⛔ Rules

- ❌ NEVER create `.env` files to store secrets
- ❌ NEVER hardcode API keys in source code
- ❌ NEVER commit secrets to git
- ✅ ALWAYS use `keyvault` CLI or SDK to manage keys

## CLI Commands

```bash
keyvault set KEY VALUE                  # Save a secret (global)
keyvault set KEY VALUE --project NAME   # Save per-project override
keyvault get KEY                        # Get (masked)
keyvault get KEY --unmask               # Get (full value)
keyvault list --all                     # List all secrets
keyvault delete KEY                     # Delete a secret
keyvault import .env                    # Bulk import from .env file
keyvault export > .env                  # Export as .env format
keyvault inject -- python script.py     # Run command with all secrets as env vars
```

## Python SDK

```python
from keyvault import get_secret, set_secret

# Get a secret (auto-fallback to os.environ if vault not found)
api_key = get_secret("OPENAI_API_KEY")

# Or just use standard env vars (works when launched via `keyvault inject`)
import os
api_key = os.environ.get("OPENAI_API_KEY")
```

## MCP Server Setup

To enable AI agents (Claude, Gemini, etc.) to manage secrets via MCP protocol:

### 1. Start the MCP server manually

```bash
python -m keyvault.mcp_server
```

### 2. Configure in Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

### 3. Available MCP Tools

| Tool | Description |
|------|-------------|
| `secrets_list` | List all stored key names (values hidden) |
| `secrets_get` | Retrieve a specific secret value |
| `secrets_set` | Store a new secret |
| `secrets_delete` | Remove a secret |

## When a Script Needs a Missing Key

If you discover a script requires an API key that hasn't been configured, prompt the user:

> "This operation requires `DEEPSEEK_API_KEY`. Please run:
> ```
> keyvault set DEEPSEEK_API_KEY <your-key>
> ```
> Then re-run the task."

## Security

| Component | Detail |
|-----------|--------|
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Master Key | `~/.keyvault/master.key` (chmod 600) |
| Database | `~/.keyvault/vault.db` (encrypted values) |
| Scopes | `global` (default) / `project:<name>` (override) |
