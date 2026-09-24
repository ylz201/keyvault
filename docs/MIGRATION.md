# Migrating 0.1 -> 0.2

No automatic upstream account changes, data migration to ABO, or secret export is performed.

1. Back up the encrypted vault AND its recovery key through an approved private process. Verify recoverability; do not upload backups to GitHub.
2. Upgrade source in an isolated test environment. Existing encrypted database formats and the administrator Python SDK are retained.
3. MCP is a deliberately breaking change: `secrets_list/get/set/delete` are no longer served. Setting `KEYVAULT_MCP_ALLOW_*` does not restore raw access. Provision a gateway client, immutable operation and grant; configure socket/token-file paths in the MCP bridge.
4. CLI `get --project` is now exact-scope. `inject` requires explicit `--key` values, excludes global secrets unless `--global` is supplied, rejects missing keys, and no longer inherits the parent environment. It remains a privileged arbitrary-program administrator command, not an agent-safe executor.
5. `scan-env` defaults to preview. Use `--apply` deliberately. Interactive secret entry is preferred to argv. Secret display/export writes plain text without Rich interpreting the credential as markup.
6. Key initialization paths share the existing-data check. Keyring migration verifies stored values and the saved key before removing the file key; conflicts/failures preserve the recovery file. Initialization is serialized; cipher caching does not follow the wrong vault directory.
7. Deploy the broker separately from untrusted agent runtimes. Create different client credentials/grants for different applications. Do not reuse the administrator identity as an agent identity.
8. Initially use the bundled no-network demo and test accounts. OAuth, cloud backend adapters, browser logins and external business approval proofs are future work, not implicit migration features.

The old `keyvault.mcp_policy` module remains for source compatibility/testing but is not consulted by the 0.2 MCP bridge.
