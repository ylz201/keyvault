<p align="center">
  <h1 align="center">🔐 KeyVault</h1>
  <p align="center">
    Lightweight secrets manager for LLM Agents.<br/>
    轻量级 LLM Agent 密钥管理工具。
  </p>
  <p align="center">
    <a href="#-quickstart">English</a> · <a href="#-快速开始">中文</a>
  </p>
</p>

---

**KeyVault** manages API keys for AI agents, CLI tools, and automation scripts — replacing scattered `.env` files with a single encrypted vault.

**KeyVault** 为 AI 智能体、CLI 工具和自动化脚本提供统一的密钥管理，替代散落各处的 `.env` 文件。

### Why KeyVault? / 为什么用 KeyVault？

| Problem | Solution |
|---------|----------|
| `.env` files scattered across projects | One encrypted vault at `~/.keyvault/` |
| AI agents can't discover which keys exist | MCP Server exposes `secrets_list` / `secrets_get` |
| No encryption — keys stored as plaintext | Fernet (AES-128-CBC + HMAC-SHA256) |
| Manual `export KEY=val` before running scripts | `keyvault inject -- python script.py` |

## ✨ Features

- **🔒 Encrypted** — AES encryption at rest, master key protected (chmod 600)
- **⌨️ CLI** — `set / get / list / delete / import / export / inject`
- **🤖 MCP Server** — AI agents (Claude, Gemini) manage keys via MCP protocol
- **🐍 Python SDK** — `from keyvault import get_secret` with `os.environ` fallback
- **📁 Scoped** — Global keys + per-project overrides
- **📥 .env Compatible** — Import / export `.env` files

---

## 🚀 Quickstart

### Install

```bash
pip install keyvault-ai

# With MCP support:
pip install keyvault-ai[mcp]
```

### CLI

```bash
# Store a key
keyvault set OPENAI_API_KEY sk-xxxxxxxxxxxxx

# Store with project scope (overrides global for that project)
keyvault set OPENAI_API_KEY sk-yyy --project my-video

# Retrieve
keyvault get OPENAI_API_KEY
keyvault get OPENAI_API_KEY --unmask    # show full value

# List all
keyvault list --all

# Import from existing .env
keyvault import .env

# Export
keyvault export > .env

# Run any command with secrets injected as env vars
keyvault inject -- python my_script.py

# Vault info
keyvault info
```

### Python SDK

```python
from keyvault import get_secret, set_secret, list_secrets

# Automatically checks vault → falls back to os.environ
api_key = get_secret("OPENAI_API_KEY")

# Save a key programmatically
set_secret("DEEPSEEK_API_KEY", "sk-xxx", description="DeepSeek v3")
```

### MCP Server (for AI Agents)

Add to `claude_desktop_config.json`:

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

Available tools: `secrets_list` · `secrets_get` · `secrets_set` · `secrets_delete`

---

## 🛡️ Security

| Layer | Detail |
|-------|--------|
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Master Key | `~/.keyvault/master.key` (chmod 600) |
| Database | `~/.keyvault/vault.db` (values encrypted) |
| Vault Dir | `~/.keyvault/` (chmod 700) |

> ⚠️ KeyVault is designed for **local development use**. For production secrets, use Hashicorp Vault, AWS Secrets Manager, etc.

> **Known limitations:**
> - Global secrets are accessible across all projects and by all connected AI agents (MCP). Use `--project` scoping to limit exposure.
> - Secret key names and descriptions are stored unencrypted (values are encrypted). An attacker with file access can see which services you use.
> - The MCP Server has no authentication — any connected agent can read secrets. Only run it locally.

---

## 🇨🇳 快速开始

### 安装

```bash
pip install keyvault-ai

# 含 MCP Server：
pip install keyvault-ai[mcp]
```

### CLI 命令

```bash
# 保存密钥
keyvault set OPENAI_API_KEY sk-xxxxxxxxxxxxx

# 按项目隔离（覆盖该项目的全局配置）
keyvault set OPENAI_API_KEY sk-yyy --project my-video

# 查看密钥
keyvault get OPENAI_API_KEY
keyvault get OPENAI_API_KEY --unmask    # 显示完整值

# 列出所有
keyvault list --all

# 从 .env 导入
keyvault import .env

# 导出为 .env
keyvault export > .env

# 注入所有密钥后执行命令
keyvault inject -- python my_script.py
```

### Python SDK

```python
from keyvault import get_secret, set_secret

# 自动查 vault → 降级到 os.environ
api_key = get_secret("OPENAI_API_KEY")

# 编程设置密钥
set_secret("DEEPSEEK_API_KEY", "sk-xxx", description="DeepSeek v3")
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

可用工具：`secrets_list` · `secrets_get` · `secrets_set` · `secrets_delete`

### 安全设计

- 所有密钥值使用 **Fernet (AES-128-CBC)** 加密后存储
- Master Key 文件权限 600，仅所有者可读
- 数据库存储在 `~/.keyvault/vault.db`，内容为密文

> ⚠️ KeyVault 仅适用于**本地开发环境**。生产环境请使用 HashiCorp Vault、AWS Secrets Manager 等。

---

## 📄 License

MIT
