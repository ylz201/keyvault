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

- **🔒 Encrypted** — AES encryption at rest, master key in OS keyring (when available) or protected on disk (chmod 600)
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

### 30-Second Fast Path

```bash
# 1) install
pip install keyvault-ai

# 2) save one key (hidden prompt)
keyvault set OPENAI_API_KEY

# 3) run your app with only this key injected
keyvault inject --no-global --key OPENAI_API_KEY -- python app.py
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
keyvault export --output .env

# (stdout export is supported, but be careful with file permissions)
# keyvault export > .env && chmod 600 .env

# Run any command with secrets injected as env vars
keyvault inject -- python my_script.py

# Inject only specific keys (recommended)
keyvault inject --key OPENAI_API_KEY -- python my_script.py

# Vault info
keyvault info

# Harden master key storage (move into OS keyring)
keyvault harden --delete-file
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

## 📚 Complete Usage (Detailed)

### CLI Command Reference

| Command | Syntax | Notes |
|---|---|---|
| Set secret | `keyvault set KEY [VALUE] [--project PROJECT] [--desc TEXT] [--stdin]` | If `VALUE` is omitted, KeyVault prompts securely (hidden input). |
| Get secret | `keyvault get KEY [--project PROJECT] [--unmask]` | Default output is masked; `--unmask` prints full value. |
| List secrets | `keyvault list [--project PROJECT] [--all]` | Metadata-only list (does not print plaintext secret values). |
| Delete secret | `keyvault delete KEY [--project PROJECT] [--force]` | `--force` skips confirmation. |
| Import `.env` | `keyvault import FILEPATH [--project PROJECT]` | Bulk import `KEY=VALUE` lines into vault. |
| Export `.env` | `keyvault export [--project PROJECT] [--output FILE]` | `--output` writes owner-only file (`0600`). |
| Inject env | `keyvault inject [--project PROJECT] [--global/--no-global] [--key KEY ...] -- CMD [ARGS...]` | Prefer `--no-global` + repeated `--key` for least privilege. |
| Show info | `keyvault info` | Shows paths, permissions, key backend, and existence checks. |
| Harden key storage | `keyvault harden [--delete-file] [--force]` | Migrates master key into OS keyring; optionally removes `master.key`. |

### Input Validation Rules

- `KEY` must be env-style: `[A-Za-z_][A-Za-z0-9_]*`
- `PROJECT` must match: `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
- Invalid values are rejected before write/read operations.

### Common Workflows

#### 1. First-time setup (safe default)

```bash
# 1) Save secret via hidden prompt
keyvault set OPENAI_API_KEY

# 2) Verify status and key backend
keyvault info

# 3) If you have legacy file-based key, migrate to keyring
keyvault harden --delete-file
```

#### 2. Global + project override

```bash
# Global default
keyvault set OPENAI_API_KEY sk-global

# Project override
keyvault set OPENAI_API_KEY sk-myapp --project myapp

# Resolve from project scope first
keyvault get OPENAI_API_KEY --project myapp --unmask
```

#### 3. Safe command injection (least privilege)

```bash
# Only inject exactly one key, and skip global scope
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python app.py
```

#### 4. Export and import securely

```bash
# Export to owner-only file
keyvault export --project myapp --output .env.myapp

# Import existing dotenv into project scope
keyvault import .env --project myapp
```

### Python SDK Reference

| Function | Signature | Behavior |
|---|---|---|
| Get | `get_secret(key, project=None, fallback_env=True) -> str | None` | Resolution order: project -> global -> `os.environ` (optional). |
| Set | `set_secret(key, value, project=None, description=None) -> None` | Creates/updates secret. |
| List | `list_secrets(project=None) -> list[Secret]` | Returns decrypted `Secret` objects. |
| Delete | `delete_secret(key, project=None) -> bool` | Returns `True` if record was deleted. |

```python
from keyvault import get_secret, set_secret, list_secrets, delete_secret

set_secret("OPENAI_API_KEY", "sk-xxx", project="myapp", description="OpenAI prod")
token = get_secret("OPENAI_API_KEY", project="myapp", fallback_env=False)
items = list_secrets(project="myapp")
deleted = delete_secret("OPENAI_API_KEY", project="myapp")
```

### Environment Variables

#### Runtime and storage

| Variable | Default | Purpose |
|---|---|---|
| `KEYVAULT_DIR` | unset | Override vault directory path (`~/.keyvault` fallback). |
| `KEYVAULT_HOME` | unset | Alternative override for vault directory. |
| `KEYVAULT_MASTER_KEY_BACKEND` | `auto` | Master key backend: `auto` / `keyring` / `file`. |
| `KEYVAULT_KEYRING_SERVICE` | `keyvault-ai` | Keyring service namespace. |
| `KEYVAULT_KEYRING_USERNAME` | `master-key` | Keyring account key name. |
| `KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN` | `0` | Allow forced master-key regeneration when data exists (unsafe, may orphan old secrets). |

#### MCP policy (all optional)

| Variable | Default | Effect |
|---|---|---|
| `KEYVAULT_MCP_ALLOW_LIST` | `0` | Enable/disable `secrets_list`. |
| `KEYVAULT_MCP_ALLOW_GET` | `0` | Enable `secrets_get`. |
| `KEYVAULT_MCP_ALLOW_SET` | `0` | Enable `secrets_set`. |
| `KEYVAULT_MCP_ALLOW_DELETE` | `0` | Enable `secrets_delete`. |
| `KEYVAULT_MCP_ALLOW_GLOBAL` | `0` | Allow global scope; otherwise project is required. |
| `KEYVAULT_MCP_ALLOW_ALL_SCOPES` | `0` | Allow `secrets_list(all_scopes=true)`. |
| `KEYVAULT_MCP_ALLOW_ALL_KEYS` | `0` | Allow arbitrary key names for get/set/delete. |
| `KEYVAULT_MCP_ALLOWED_KEYS` | unset | Comma-separated key allowlist, e.g. `OPENAI_API_KEY,DEEPSEEK_API_KEY`. |
| `KEYVAULT_MCP_INCLUDE_DESCRIPTIONS` | `0` | Include secret descriptions in list output. |

#### Hardened MCP example

```bash
export KEYVAULT_MCP_ALLOW_LIST=1
export KEYVAULT_MCP_ALLOW_GET=1
export KEYVAULT_MCP_ALLOW_GLOBAL=0
export KEYVAULT_MCP_ALLOWED_KEYS=OPENAI_API_KEY
python -m keyvault.mcp_server
```

---

## 🛡️ Security

| Layer | Detail |
|-------|--------|
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Master Key | OS keyring (default if available) or `~/.keyvault/master.key` (chmod 600) |
| Database | `~/.keyvault/vault.db` (values + metadata encrypted) |
| Vault Dir | `~/.keyvault/` (chmod 700) or `KEYVAULT_DIR` / `KEYVAULT_HOME` override |

> ⚠️ KeyVault is designed for **local development use**. For production secrets, use Hashicorp Vault, AWS Secrets Manager, etc.

> **Known limitations:**
> - Global secrets are accessible across all projects. For MCP, project scope is required by default; avoid enabling global scope unless needed.
> - Secret metadata is encrypted at rest, but anyone who can access your master key (same user account / keychain access / `master.key`) can decrypt it.
> - The MCP Server has no authentication. Use MCP policy env vars to restrict access (defaults are restrictive), and only run it locally.
>   - `KEYVAULT_MCP_ALLOW_GET=1` to enable `secrets_get`
>   - `KEYVAULT_MCP_ALLOWED_KEYS=OPENAI_API_KEY,...` or `KEYVAULT_MCP_ALLOW_ALL_KEYS=1`
>   - `KEYVAULT_MCP_ALLOW_GLOBAL=1` to allow global scope (otherwise project scope is required)
> - If vault data exists but the original master key is unavailable, KeyVault now fails closed (won't silently regenerate a new key). You can override with `KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN=1` (unsafe).

> Tip: control master key storage with `KEYVAULT_MASTER_KEY_BACKEND=auto|keyring|file` (default: `auto`). Use `keyvault info` to confirm.

---

## 快速开始

### 安装

```bash
pip install keyvault-ai

# 含 MCP Server：
pip install keyvault-ai[mcp]
```

### 30 秒最快方案

```bash
# 1) 安装
pip install keyvault-ai

# 2) 写入 1 个密钥（隐藏输入）
keyvault set OPENAI_API_KEY

# 3) 只注入该密钥运行程序
keyvault inject --no-global --key OPENAI_API_KEY -- python app.py
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
keyvault export --output .env

# （也支持输出到 stdout，但请注意文件权限）
# keyvault export > .env && chmod 600 .env

# 注入所有密钥后执行命令
keyvault inject -- python my_script.py

# 仅注入指定 key（推荐）
keyvault inject --key OPENAI_API_KEY -- python my_script.py
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

## 📚 完整用法（详细）

### CLI 命令总览

| 命令 | 语法 | 说明 |
|---|---|---|
| 写入密钥 | `keyvault set KEY [VALUE] [--project PROJECT] [--desc TEXT] [--stdin]` | 不传 `VALUE` 会进入隐藏输入；`--stdin` 适合管道。 |
| 读取密钥 | `keyvault get KEY [--project PROJECT] [--unmask]` | 默认脱敏显示，`--unmask` 显示完整值。 |
| 列表 | `keyvault list [--project PROJECT] [--all]` | 仅显示元数据，不输出明文值。 |
| 删除 | `keyvault delete KEY [--project PROJECT] [--force]` | `--force` 跳过确认。 |
| 导入 | `keyvault import FILEPATH [--project PROJECT]` | 从 `.env` 批量导入。 |
| 导出 | `keyvault export [--project PROJECT] [--output FILE]` | `--output` 会按 `0600` 权限写文件。 |
| 注入执行 | `keyvault inject [--project PROJECT] [--global/--no-global] [--key KEY ...] -- CMD [ARGS...]` | 建议 `--no-global` + `--key` 最小权限注入。 |
| 查看状态 | `keyvault info` | 查看路径、权限、密钥后端。 |
| 强化密钥存储 | `keyvault harden [--delete-file] [--force]` | 迁移 master key 到系统 Keyring。 |

### 常用流程

```bash
# 1) 首次配置：隐藏输入写入 key
keyvault set OPENAI_API_KEY

# 2) 项目隔离：同名 key 在项目内覆盖全局
keyvault set OPENAI_API_KEY sk-global
keyvault set OPENAI_API_KEY sk-myapp --project myapp
keyvault get OPENAI_API_KEY --project myapp --unmask

# 3) 最小权限注入（推荐）
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python app.py

# 4) 文件导出（安全权限）
keyvault export --project myapp --output .env.myapp
```

### Python SDK（详细）

| 函数 | 签名 | 行为 |
|---|---|---|
| `get_secret` | `get_secret(key, project=None, fallback_env=True)` | 查找顺序：项目 -> 全局 -> `os.environ`（可关闭回退）。 |
| `set_secret` | `set_secret(key, value, project=None, description=None)` | 新建或更新密钥。 |
| `list_secrets` | `list_secrets(project=None)` | 返回解密后的 `Secret` 列表。 |
| `delete_secret` | `delete_secret(key, project=None)` | 删除成功返回 `True`。 |

### 关键环境变量

- 存储相关：`KEYVAULT_DIR`、`KEYVAULT_HOME`、`KEYVAULT_MASTER_KEY_BACKEND`、`KEYVAULT_KEYRING_SERVICE`、`KEYVAULT_KEYRING_USERNAME`、`KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN`
- MCP 策略相关：`KEYVAULT_MCP_ALLOW_LIST`、`KEYVAULT_MCP_ALLOW_GET`、`KEYVAULT_MCP_ALLOW_SET`、`KEYVAULT_MCP_ALLOW_DELETE`、`KEYVAULT_MCP_ALLOW_GLOBAL`、`KEYVAULT_MCP_ALLOW_ALL_SCOPES`、`KEYVAULT_MCP_ALLOW_ALL_KEYS`、`KEYVAULT_MCP_ALLOWED_KEYS`、`KEYVAULT_MCP_INCLUDE_DESCRIPTIONS`

```bash
# MCP 推荐最小权限示例
export KEYVAULT_MCP_ALLOW_LIST=1
export KEYVAULT_MCP_ALLOW_GET=1
export KEYVAULT_MCP_ALLOW_GLOBAL=0
export KEYVAULT_MCP_ALLOWED_KEYS=OPENAI_API_KEY
python -m keyvault.mcp_server
```

### 安全设计

- 所有密钥值使用 **Fernet (AES-128-CBC)** 加密后存储
- Master Key 默认存入系统 Keyring（可用时），或落盘 `~/.keyvault/master.key`（权限 600）
- 数据库存储在 `~/.keyvault/vault.db`，值和元数据均为密文

> MCP Server 默认策略更严格：`secrets_list / secrets_get / secrets_set / secrets_delete` 默认关闭；按需通过环境变量开启，并建议使用 `KEYVAULT_MCP_ALLOWED_KEYS` 做 key 白名单。

> 若检测到 vault 里已有数据但 master key 丢失/不可用，系统会拒绝自动重建新 key（fail-closed）。仅在确认旧数据可丢弃时，才设置 `KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN=1`。

> ⚠️ KeyVault 仅适用于**本地开发环境**。生产环境请使用 HashiCorp Vault、AWS Secrets Manager 等。

---

## 📄 License

MIT
