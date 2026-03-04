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

更多完整用法请看：`README.md`。
