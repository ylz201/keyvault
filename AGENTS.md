# Engineering instructions

KeyVault is an independent credential-use gateway. Do not add ABO/xvisa domain dependencies.

The model-facing interface is CLI/MCP -> authenticated gateway -> immutable trusted executor. Do not expose raw secrets, generic execution callbacks, shell commands, arbitrary URL/headers/body, administrative grant creation, or self-approved identity through agent tools.

Never inspect real local vaults or use production credentials to test. Use `keyvault-gateway demo` and pytest fixtures. Keep client tokens out of tool results and logs. Raw administrator CLI/SDK are privileged compatibility surfaces, not agent tools.

Run `python -m pytest -q`, `python -m compileall -q keyvault`, and `keyvault-gateway demo`. Include MCP wire tests with `.[mcp,dev]` installed. Changes to authentication, grants, targets, projection, master-key handling or deduplication require negative and failure-injection tests. Do not weaken an assertion to make a security test pass.

Document unimplemented features and the OS isolation assumptions. Never label a same-UID demo production-secure. Preserve unknown-result semantics; never retry by silently generating a new request UUID.
