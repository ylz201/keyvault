# Credential-use protocol v1

Protocol ID: `keyvault.gateway/v1`.

## Transport and authentication

The first server accepts newline-delimited JSON over a Unix-domain socket. Requests are bounded to 16 KiB; responses to 256 KiB. There is no TCP listener. Client authentication is mandatory even though the transport is local. Unknown fields and duplicate JSON keys are rejected.

Envelope fields are exactly `protocol`, `token`, `method`, `arguments`. The token identifies the client; never supply a workspace/principal in arguments. Do not log the envelope. Responses use `{protocol, ok, result}` or `{protocol, ok:false, error:{code}}`.

## Operations

| Method | Arguments | Response |
|---|---|---|
| `credentials_list` | `{}` | Currently usable grant IDs, operation IDs, credential references, expiry, remaining uses; no backend locators or secret values |
| `credential_use` | `{grant_id, request_id}` | Sanitized result for an immutable GET profile; request_id is a canonical UUID |
| `credential_status` | `{request_id}` | Own request status only, without replaying its output or resending |

There are no admin, registration, approve, get-secret, arbitrary URL, cookie-export or shell methods. All four legacy `secrets_*` MCP tools are retired in 0.2; legacy policy environment variables cannot re-enable them.

## Result semantics

`SUCCEEDED` means the registered HTTPS request returned an accepted JSON projection. It does not prove a business workflow completed.

`COMMITTED` is internal durable reservation; client inspection represents an unfinished reservation as `EFFECT_UNKNOWN`. `OUTPUT_REJECTED`, `REDIRECT_DENIED`, `UPSTREAM_REJECTED`, `DESTINATION_DENIED`, `DESTINATION_UNAVAILABLE` and `EFFECT_UNKNOWN` are terminal observations for that request UUID. No result authorizes automatic resubmission under a new UUID. Status inspection requires a valid client token; reading cached result data also requires the current grant to remain valid.

Authentication/authorization failures are errors such as `UNAUTHENTICATED`, `FORBIDDEN`, `GRANT_EXHAUSTED`, `CREDENTIAL_CHANGED`, `REQUEST_CONFLICT`. Error text is never an upstream exception/response. Audit entries use controlled codes and identifiers.

## Profile contract

See `examples/quota.operation.json`. The administrator owns the profile. Only HTTPS/443 fixed DNS destinations and GET are implemented. No runtime parameters, wildcard destinations or user-defined headers. Only `Authorization` and `X-API-Key` injection are available, with registered prefixes. A credential must match exact project/key and the registered revision.

Output fields select bounded-depth object pointers; numeric values must be safe integers, booleans must be actual booleans, strings must belong to an administrator-declared enum. Arrays and unrestricted strings/objects are not supported. Upstream cookies/headers are never returned. The allowlist is primary; simple canary/secret reflection rejection is defense in depth, not a proof against malicious upstream encoding.

## Compatibility

CLI and MCP bridge call the same RPC methods. The MCP wire-format is supplied by the official Python SDK; local gateway RPC is a separate protocol and is not advertised as streamable-HTTP MCP. Windows gateway deployment and remote authenticated HTTP are out of scope in this version.
