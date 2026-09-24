# Security model and limitations

## Status

0.2 is an alpha, locally deployable reference implementation. Automated regression tests are not an independent security audit. Do not entrust important production credentials until isolation, operational recovery and the required authentication backend have been assessed for the actual deployment.

## Protected boundary

An agent with a valid scoped client token may request ONLY administrator-registered operations allowed by its unexpired, unrevoked grant. It may not choose URL/headers/body, impersonate another workspace, retrieve upstream secrets, change grants or submit arbitrary executable code. Prompt injection does not acquire a new operation or credential through this interface.

This assumes the gateway process, administrator, installed code, secret backend, OS and explicitly allowed upstream are trusted. A compromised gateway owner/root can read its secrets. A same-UID agent shell can use owner privileges to bypass the application interface: same-user setup is **not** a security boundary.

## Deployment requirements

- Use a dedicated Unix service user and root-owned, read-only installed gateway code. No agent-writeable Python modules, `PYTHONPATH`, startup scripts or service environment.
- Vault/state directories: owner only (`0700`); state, master-key and client token files: `0600`. Registry metadata is sensitive too. File encryption does not protect a stolen database together with its file-based master key.
- Socket parent: service-owned, non-group/world-writable; grant client group traverse permission. Socket: `0660`, service/client group. Keep vault and state outside that shared directory.
- Provision client token files through a trusted administrative path; ownership should match the client OS identity, with mode `0600`. They authorize limited gateway actions and must also stay out of model context and logs.
- Do not expose the Unix protocol through an unauthenticated network tunnel. Deploy network authentication/TLS only after that transport is designed and tested.
- Use least-privilege test keys. No broker plaintext API, no raw MCP access, no arbitrary-shell injection. Administrator CLI/SDK remain intentionally privileged and must not be reachable by untrusted shells with vault access.
- Maintain tested database/key backups and a disk quota/retention plan. Audit is append-only by the application interface, NOT tamper-proof against its administrator. OS-level resource limits and monitoring are required.

A possible Linux service layout is `/var/lib/keyvault/vault` (0700), `/var/lib/keyvault/control` (0700), `/run/keyvault` (service-owned, client group, 0750), and one private token file per client. Systemd hardening should include a dedicated User/Group, `NoNewPrivileges=yes`, `ProtectSystem=strict`, explicit `ReadWritePaths`, `ProtectHome=yes`, `PrivateTmp=yes` and `LimitCORE=0`. Service installation, user creation and filesystem isolation are operator steps, not silently performed by this package.

## Network control

All resolved addresses must be public; loopback, private, shared, link-local, multicast and known IPv4-translation ranges are refused. The chosen numeric address is connected directly and TLS validates the original hostname. Environment proxies and redirects are not used. Response content-type, size and projection are restricted. DNS uses the OS resolver; its resolution timeout is OS-dependent. Connection/read bounds and a finite worker count do not replace full service-level resource control.

An allowed upstream can still be malicious or compromised. Returning only enums/integers/booleans limits output but does not prove absence of a covert channel. Do not register echo/debug APIs, endpoints that return session credentials, or GET endpoints with unintended effects. Browser session delegation is not implemented and cannot be inferred from API-key injection.

## Lifecycle and failure

Grant revocation stops new reservations. A committed/in-flight request may still reach the upstream. Gateway revocation does not revoke a static API key at the service provider. Rotating the stored secret invalidates old profile registrations; new registration and grants are required. No arbitrary automatic password change or token-refresh flow is implemented.

Client request UUIDs and finite quotas are persisted before external use. If the process dies afterward, the result is unknown; repeating the UUID does not retransmit. This trades availability for avoiding an uncontrolled duplicate. It is not distributed exactly-once execution. The business client must decide whether a truly new invocation is appropriate.

`KEYVAULT_ALLOW_UNSAFE_MASTER_KEY_REGEN` remains a dangerous legacy administrator recovery override; the gateway provider rejects it. Keyring storage must use an appropriate OS-backed backend; installing an arbitrary plaintext third-party keyring backend does not make it secure.

## Reporting

Do not open a public issue containing passwords, real tokens, vault databases or customer data. Contact the repository owner privately through GitHub's available private security-reporting channel, or agree on a private channel without including the sensitive material first.

## Design references

- https://docs.python.org/3/library/http.client.html
- https://modelcontextprotocol.io/docs/develop/build-server
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

No claim is made that this replaces a vendor's internal auth service or a mature production secrets platform.
