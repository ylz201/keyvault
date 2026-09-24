---
name: keyvault-skill
description: Use pre-authorized operations through the KeyVault credential gateway without retrieving upstream secrets.
---

# KeyVault agent interface (0.2)

Use `credentials_list`, `credential_use`, `credential_status` through MCP, or the matching `keyvault-gateway list/use/status` JSON CLI commands.

Request an existing grant using a canonical UUID. Reuse the UUID to inspect/replay an earlier invocation; never automatically replace it to retry an unknown effect. The gateway chooses identity, secret scope, URL, headers and projection from trusted registration, not from your prompt.

Do NOT call old `secrets_get/set/delete`, turn on legacy MCP flags, read `master.key`, call the administrator SDK, print environment variables, or pass upstream secrets into shell/model context. Do not grant yourself access. If credentials, MFA or permissions are missing, ask the human administrator to connect or authorize through the independent trusted management path.

A same-user shell with direct vault access is not isolated. This skill is guidance, not the security mechanism; enforcement is in the separately privileged gateway service. See `SECURITY.md` and `QUICKSTART.md`.
