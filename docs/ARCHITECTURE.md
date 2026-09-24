# Agent Credential Gateway — architecture

## Ownership

KeyVault owns credential registration/use, caller authentication, bounded grants and usage audit. ABO or another business system owns the business goal, case, approval semantics, executor outcome and completion evidence. There is no import of ABO, xvisa, orders, passports or CRM models.

Two different extensibility seams are maintained:

1. `CredentialProvider.resolve(locator)` is a **trusted-side** SPI. It may return a secret to the fixed executor, never to an agent. The local implementation uses exact project/key lookup and a keyed revision. Cloud providers are future adapters, not pretend implementations.
2. `FixedHTTPSTransport` performs one immutable GET profile. It validates the public destination, pins the resolved address, verifies the original TLS hostname, injects authentication and refuses redirects. A future browser executor requires its own threat model and must not be an arbitrary callback receiving passwords.

## Processes and privilege

Administrator: owner-only local CRUD/provisioning. Can manage secrets and control state. This is intentionally privileged.

Gateway service: holds backend access; reads immutable profiles and grants from private SQLite; executes fixed code; has no model or planner.

Agent CLI/MCP bridge: holds only its scoped gateway client token; talks to Unix RPC; does not load a SecretStore or upstream credential. A trusted model host can consume the result, but external response data is never an instruction or authorization source.

Real shell isolation requires separate OS users or containers. Naming a class `Broker`, replacing `get` with `use`, or adding Python callbacks does not create isolation. The administrator and installed gateway code must not be writable by the agent.

## Data

The existing encrypted vault stores upstream values. Control SQLite stores client token hashes, workspace membership, credential locators, keyed revisions, operation digests, grants, request reservations and audit events. Raw credentials, raw HTTP responses, headers and client bearer tokens are not persisted in this database. Control metadata is sensitive even without secrets and is owner-only.

A workspace is an authorization namespace, not cryptographic per-tenant isolation from the gateway administrator. Separate high-trust tenants into separate service/storage deployments. Every request is bound to the identity recovered from a random client token; the agent cannot submit a principal or tenant field.

## Authorization and execution

Admin registration freezes URL, account reference, exact secret scope, authentication mechanism and output projection. The operation digest also binds the credential revision. Profiles are immutable; revoke and register a new ID to change behavior.

A grant binds a client to one profile, its digest, an expiry and a finite use count. Broker acceptance and quota reservation occur in one `BEGIN IMMEDIATE` transaction with the request row and audit entry. Only then may the external request start. Revocation stops later reservations, not requests already committed.

A `(client, request UUID)` identifies one invocation. Repeating it with a different grant is rejected. Repeating it with the same still-authorized grant returns the stored sanitized result, or `EFFECT_UNKNOWN` after an unfinished reservation. There is no automatic network retry. This is not an exactly-once guarantee for the remote system.

The first implementation deliberately exposes no external writes, arbitrary URL/body parameters, unrestricted strings/objects, raw tokens, credential mutations or admin RPC methods. GET alone does not prove an endpoint is semantically read-only; administrators must review the actual endpoint.

## Integration boundary

ABO may map its own action IDs to request UUIDs and issue client/grant provisioning through a separate trusted administrative integration. An agent-supplied `approved: true` is never sufficient. Signed or authenticated business approval attestations are a future versioned extension, not implemented here.

A tested local MCP stdio bridge and JSON CLI provide client-independent access. Remote HTTP transport, OAuth client enrollment, vendor-specific installation verification and Muse internal vault replacement are not included.
