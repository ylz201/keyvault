# KeyVault Quick Start

Get KeyVault running in under 1 minute.

## 1) Install

```bash
pip install keyvault-ai
```

> Need MCP server too?
>
> ```bash
> pip install keyvault-ai[mcp]
> ```

## 2) Save your first key

```bash
keyvault set OPENAI_API_KEY
```

This uses hidden input (won’t show your key on screen).

## 3) Run your app with injected env

```bash
keyvault inject --no-global --key OPENAI_API_KEY -- python app.py
```

## 4) Verify setup

```bash
keyvault list
keyvault info
```

## 5) Security Confidence Check (recommended)

```bash
# Move master key into OS keyring and remove local key file
keyvault harden --delete-file

# Use project scope + least-privilege injection
keyvault set OPENAI_API_KEY --project myapp
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python app.py
```

Security signals to confirm:
- `keyvault info` shows vault dir mode `0o700` and DB/file mode `0o600` (when present).
- MCP policy remains deny-by-default unless you explicitly enable required operations.
- You avoid `keyvault get --unmask` in shared terminals.

---

## Common Next Steps

### Project-scoped secret (recommended)

```bash
keyvault set OPENAI_API_KEY --project myapp
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python app.py
```

### Import existing `.env`

```bash
keyvault import .env --project myapp
```

### Smart scan and auto-import likely secrets from `.env*`

```bash
# Preview only (recommended first)
keyvault scan-env --project myapp --dry-run

# Import high-confidence secret-like keys
keyvault scan-env --project myapp --apply
```

### Export with safe permissions

```bash
keyvault export --project myapp --output .env.myapp
```

---

## MCP (for AI agents)

`claude_desktop_config.json`:

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

Recommended minimal policy:

```bash
export KEYVAULT_MCP_ALLOW_LIST=1
export KEYVAULT_MCP_ALLOW_GET=1
export KEYVAULT_MCP_ALLOW_GLOBAL=0
export KEYVAULT_MCP_ALLOWED_KEYS=OPENAI_API_KEY
python -m keyvault.mcp_server
```

---

## 中文版（超简版）

### 1）安装

```bash
pip install keyvault-ai
```

### 2）保存第一个密钥

```bash
keyvault set OPENAI_API_KEY
```

### 3）注入运行（最小权限）

```bash
keyvault inject --no-global --key OPENAI_API_KEY -- python app.py
```

### 4）检查状态

```bash
keyvault list
keyvault info
```

### 5）安全感检查（建议）

```bash
# 将主密钥迁移到系统 Keyring，并删除本地 key 文件
keyvault harden --delete-file

# 使用项目作用域 + 最小权限注入
keyvault set OPENAI_API_KEY --project myapp
keyvault inject --project myapp --no-global --key OPENAI_API_KEY -- python app.py
```

可感知的安全信号：
- `keyvault info` 里目录权限应为 `0o700`，数据库/密钥文件为 `0o600`（存在时）。
- MCP 默认拒绝，只有你显式开放的操作才可用。
- 在共享终端避免使用 `keyvault get --unmask`。

### 6）智能扫描并自动导入 `.env*` 密钥（推荐）

```bash
# 先预览，不写入
keyvault scan-env --project myapp --dry-run

# 再执行导入（默认仅导入高置信度疑似密钥）
keyvault scan-env --project myapp --apply
```

更多完整用法请看：`README.md`。
