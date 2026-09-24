# 0.2 Gateway quick start

## 1. Install and exercise the offline demo

Use Python 3.10+ on Linux/macOS. Install this source checkout rather than assuming PyPI has this version:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[mcp,dev]'
python -m pytest -q
keyvault-gateway demo
```

## 2. Functional local setup (same-user development ONLY)

This setup proves functionality, NOT isolation from an agent with the same user's shell access. Use a disposable, least-privilege **test API key**.

```bash
mkdir -m 700 -p "$HOME/.keyvault-gateway" "$HOME/.keyvault-client"
keyvault set SERVICE_API_KEY_V1 --project gateway-dev
keyvault-gateway init
keyvault-gateway create-client local-agent --workspace personal-dev   --token-file "$HOME/.keyvault-client/client.token" --ttl 86400
keyvault-gateway register examples/quota.operation.json
keyvault-gateway grant quota-grant --client local-agent   --operation quota-read-v1 --ttl 600 --uses 3
```

The example profile targets GitHub's API rate-limit endpoint and projects only its integer quota fields. Save an appropriate GitHub test token under `SERVICE_API_KEY_V1`, or replace the administrator-owned profile with an endpoint you control before registration. Do not replace it with an echo endpoint or accept arbitrary destinations from model output.

In a separate trusted terminal, keep the service in the foreground:

```bash
keyvault-gateway serve --socket "$HOME/.keyvault-gateway/rpc.sock"
```

In the client terminal:

```bash
export KEYVAULT_GATEWAY_SOCKET="$HOME/.keyvault-gateway/rpc.sock"
export KEYVAULT_GATEWAY_TOKEN_FILE="$HOME/.keyvault-client/client.token"
keyvault-gateway list
keyvault-gateway use quota-grant --request-id 11111111-1111-4111-8111-111111111111
keyvault-gateway status 11111111-1111-4111-8111-111111111111
```

Reusing the UUID never sends the same request again. Expired or revoked grants cannot be used to replay data; `status` returns only the client's own request metadata. A crash after reservation leaves an unknown result rather than silently retrying.

## 3. Revoke and inspect

Run as the administrator:

```bash
keyvault-gateway revoke grant quota-grant
keyvault-gateway audit
```

This stops **new gateway uses**, not the upstream API key itself. Rotate/revoke the upstream credential separately when necessary.

## 4. Credential changes

Changing `SERVICE_API_KEY_V1` makes old registrations fail with `CREDENTIAL_CHANGED`. Register a new immutable operation ID and issue new grants. Never update a credential and assume earlier approvals automatically authorize the replacement.

## 5. Isolate before connecting an untrusted agent

Use the deployment model in `SECURITY.md`: separate service identity, root-owned installed code, a private state/vault directory, a group-accessible Unix socket in a non-group-writable directory, and separate client-token files. The admin CLI and gateway state must not be accessible to the agent.

If a service crashes and leaves a socket path behind, startup refuses to overwrite it. An administrator must verify the previous service has stopped before removing that stale socket. Do not blindly delete a socket on every startup.
