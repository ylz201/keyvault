---
name: secrets-manager
description: 指导大模型（AI Agent）和其他脚本如何在本项目中正确获取和管理安全的 API Keys 等敏感凭证。
---

# KeyVault — AI Agent 使用指南

当你（AI Agent）在任何项目中需要处理 API Keys / 密钥 / Token 等敏感信息时，**必须使用 KeyVault** 进行管理。

## ⛔ 禁止行为

- ❌ 不要创建 `.env` 文件存放密钥
- ❌ 不要在代码中硬编码 API Key
- ❌ 不要将密钥写入 git 仓库

## ✅ 正确方式

### 1. CLI 管理密钥

```bash
# 设置密钥
keyvault set OPENAI_API_KEY sk-xxxxx --desc "OpenAI 主账户"

# 按项目隔离
keyvault set OPENAI_API_KEY sk-yyyyy --project my-video

# 查看已有密钥
keyvault list --all

# 从 .env 批量导入
keyvault import .env

# 注入所有密钥后执行脚本
keyvault inject -- python my_script.py
```

### 2. Python 代码中获取密钥

```python
# 方式 A：SDK（推荐）
from keyvault import get_secret
api_key = get_secret("OPENAI_API_KEY")  # 自动 fallback 到 os.environ

# 方式 B：环境变量（通用）
import os
api_key = os.environ.get("OPENAI_API_KEY")
```

### 3. MCP Server（给 Claude / Gemini 等 Agent）

在 `claude_desktop_config.json` 中配置：
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

可用的 MCP Tools:
- `secrets_list` — 列出所有 Key 名
- `secrets_get` — 获取指定 Key 值
- `secrets_set` — 设置新 Key
- `secrets_delete` — 删除 Key

## 📋 当脚本需要新 Key 时

如果你发现某个脚本需要一个尚未配置的 API Key，请提示用户：

> "此操作需要 `DEEPSEEK_API_KEY`。请运行以下命令配置：  
> `keyvault set DEEPSEEK_API_KEY <your-key>`  
> 配置后重新运行即可。"

## 🔐 安全架构

| 组件 | 说明 |
|------|------|
| 加密算法 | Fernet (AES-128-CBC + HMAC-SHA256) |
| Master Key | `~/.keyvault/master.key` (chmod 600) |
| 数据库 | `~/.keyvault/vault.db` (加密存储) |
| 作用域 | global (默认) / project:xxx (项目级覆盖) |
