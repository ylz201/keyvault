# Scope and roadmap

## Implemented foundation (0.2 alpha)

Independent gateway package; local encrypted provider; trusted administrator onboarding; hashed authenticated client identities; workspace/grant binding; immutable fixed HTTPS GET operations; finite quotas and expiry/revocation; durable request reservation and audit; exact-scope secret lookup and revision binding; closed response projection; local Unix RPC; JSON CLI; MCP stdio bridge; fake-credential demo and regression tests.

## Next: validate deployment and integration, not a CRM

Add isolated OS/container deployment tests, secret-safe operational metrics, explicit retention and backup/restore drills, credential-provider contract tests for one external storage backend, and integration of ABO authorization via a trusted adapter. Maintain two unrelated client examples to avoid ABO coupling. Validate actual vendor clients separately from generic MCP wire tests.

## Later, separately reviewed increments

- Authenticated remote HTTP transport with OAuth audience validation / workload identity, not a public wrapper around the Unix socket.
- OAuth account connect/refresh/revoke with independent human consent UI.
- Browser login/session broker with account/operation restrictions, MFA pause/resume and its own threat model.
- External business-approval attestations and side-effectful request profiles with reconciliation. Do not enable generic POST until the semantic and authorization contracts exist.
- Cloud Vault provider adapters and least-privilege service identities.

## Non-goals

A new cryptographic algorithm, general KMS/HSM, universal password manager UI, personal-data/PII database, persistent-agent scheduler, business workflow engine, CRM, or guaranteed compatibility with proprietary internal credential stores.
