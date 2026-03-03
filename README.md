# 🔐 KeyVault

> Lightweight secrets manager for LLM Agents.  
> Manage API keys across **Skills**, **MCP Servers**, and **CLI tools** — securely and effortlessly.

[English](#-quickstart) | [中文](#-快速开始)

## ✨ Features

- **🔒 Encrypted Storage** — All secrets encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
- **⌨️ CLI Tool** — `keyvault set / get / list / delete / import / export / inject`
- **🤖 MCP Server** — Let AI Agents (Claude, Gemini) query and manage keys via MCP protocol
- **🐍 Python SDK** — `from keyvault import get_secret` with env var fallback
- **📁 Multi-Scope** — Global keys + per-project overrides
- **📥 .env Compatible** — Import from / export to `.env` files

## 🚀 Quickstart

### Install

```bash
pip install keyvault-ai

# With MCP Server support:
pip install keyvault-ai[mcp]
```

### CLI Usage

```bash
# Set a secret
keyvault set OPENAI_API_KEY sk-xxxxxxxxxxxxx

# Set with project scope
keyvault set OPENAI_API_KEY sk-yyy --project my-video

# Get a secret
keyvault get OPENAI_API_KEY

# List all secrets
keyvault list --all

# Import from .env
keyvault import .env

# Export to .env format
keyvault export > .env

# Run a command with ALL secrets injected as env vars
keyvault inject -- python my_script.py

# Show vault info
keyvault info
```

### Python SDK

```python
from keyvault import get_secret, set_secret, list_secrets

# Get a secret (auto-fallback to os.environ)
api_key = get_secret("OPENAI_API_KEY")

# Set a secret
set_secret("DEEPSEEK_API_KEY", "sk-xxx", description="DeepSeek v3")

# List all secrets
for s in list_secrets():
    print(f"{s.key} = {s.masked_value()}")
```

### MCP Server (for AI Agents)

Add to your `claude_desktop_config.json`:

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

The MCP server exposes these tools to AI agents:
- `secrets_list` — List available key names
- `secrets_get` — Get a secret value
- `secrets_set` — Save a new key
- `secrets_delete` — Remove a key

---

## 🇨🇳 快速开始

### 安装

```bash
pip install keyvault-ai

# 带 MCP Server 支持:
pip install keyvault-ai[mcp]
```

### CLI 使用

```bash
# 设置密钥
keyvault set OPENAI_API_KEY sk-xxxxxxxxxxxxx

# 按项目隔离密钥
keyvault set OPENAI_API_KEY sk-yyy --project my-video

# 获取密钥
keyvault get OPENAI_API_KEY

# 列出所有密钥
keyvault list --all

# 从 .env 文件导入
keyvault import .env

# 导出为 .env 格式
keyvault export > .env

# 注入所有密钥为环境变量后执行命令
keyvault inject -- python my_script.py
```

### Python SDK

```python
from keyvault import get_secret, set_secret

# 获取密钥（自动降级到 os.environ）
api_key = get_secret("OPENAI_API_KEY")

# 设置密钥
set_secret("DEEPSEEK_API_KEY", "sk-xxx", description="DeepSeek v3 密钥")
```

### MCP Server（给 AI Agent 用）

在 `claude_desktop_config.json` 中添加：

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

---

## 🛡️ Security Design

| Layer | Detail |
|-------|--------|
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Master Key | `~/.keyvault/master.key` (chmod 600) |
| Database | `~/.keyvault/vault.db` (encrypted values) |
| Vault Dir | `~/.keyvault/` (chmod 700) |

## 📄 License

MIT
