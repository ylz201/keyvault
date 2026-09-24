"""Local administrator commands and an agent-safe client CLI."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
from .protocol import GatewayError, canonical, parse_json

def main():
    parser = argparse.ArgumentParser(description="KeyVault credential gateway (POSIX reference deployment)")
    parser.add_argument("--state", type=Path, default=Path.home() / ".keyvault-gateway" / "state.db")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="ADMIN: initialize private control database")
    client = commands.add_parser("create-client", help="ADMIN: provision scoped gateway client, token written only to file")
    client.add_argument("id"); client.add_argument("--workspace", required=True)
    client.add_argument("--token-file", required=True, type=Path)
    client.add_argument("--ttl", type=int, default=86400)
    register = commands.add_parser("register", help="ADMIN: register an immutable fixed HTTPS GET operation")
    register.add_argument("file", type=Path)
    grant = commands.add_parser("grant", help="ADMIN: authorize a client for one registered operation")
    grant.add_argument("id"); grant.add_argument("--client", required=True); grant.add_argument("--operation", required=True)
    grant.add_argument("--ttl", type=int, default=3600); grant.add_argument("--uses", type=int, default=10)
    revoke = commands.add_parser("revoke", help="ADMIN: stop new uses; does not revoke upstream static keys")
    revoke.add_argument("kind", choices=("client", "grant", "operation")); revoke.add_argument("id")
    commands.add_parser("audit", help="ADMIN: last 100 secret-free audit events")
    serve = commands.add_parser("serve", help="ADMIN: serve local authenticated Unix RPC")
    serve.add_argument("--socket", required=True, type=Path)
    commands.add_parser("list", help="AGENT: list authorized operations")
    use = commands.add_parser("use", help="AGENT: use an existing grant; no URL, headers, shell or secret arguments")
    use.add_argument("grant_id"); use.add_argument("--request-id", required=True)
    status = commands.add_parser("status", help="AGENT: inspect own request metadata")
    status.add_argument("request_id")
    commands.add_parser("demo", help="Run isolated fake-credential demo; no external requests")
    args = parser.parse_args()
    try:
        if args.command == "demo":
            from .demo import run
            result = run()
        elif args.command in ("list", "use", "status"):
            from .rpc import Client
            client = Client.from_environment()
            if args.command == "list":
                result = client.call("credentials_list", {})
            elif args.command == "use":
                result = client.call("credential_use", {"grant_id": args.grant_id, "request_id": args.request_id})
            else:
                result = client.call("credential_status", {"request_id": args.request_id})
        else:
            from .state import State
            state = State(args.state)
            if args.command == "init":
                result = {"initialized": True}
            elif args.command == "create-client":
                # Refuse overwriting an existing token file. Never print the token.
                fd = os.open(args.token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    token = state.create_client(args.id, args.workspace, args.ttl)
                    with os.fdopen(fd, "w") as f:
                        fd = -1
                        f.write(token + "\n"); f.flush(); os.fsync(f.fileno())
                except BaseException:
                    if fd != -1:
                        os.close(fd)
                    args.token_file.unlink(missing_ok=True)
                    raise
                result = {"client_id": args.id, "token_written": True}
            elif args.command == "register":
                from .provider import LocalKeyVaultProvider
                raw = args.file.read_bytes()
                if len(raw) > 32768:
                    raise GatewayError("INVALID_INPUT")
                state.register_operation(parse_json(raw), LocalKeyVaultProvider())
                result = {"registered": True}
            elif args.command == "grant":
                state.grant(args.id, args.client, args.operation, args.ttl, args.uses)
                result = {"grant_id": args.id, "authorized": True}
            elif args.command == "revoke":
                state.revoke(args.kind, args.id)
                result = {"revoked": True, "upstream_revocation": "NOT_ATTEMPTED"}
            elif args.command == "audit":
                with state.transaction() as db:
                    result = {"events": [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 100")]}
            else:
                from .provider import LocalKeyVaultProvider
                from .transport import FixedHTTPSTransport
                from .broker import Broker
                from .rpc import Server
                with Server(args.socket, Broker(state, LocalKeyVaultProvider(), FixedHTTPSTransport())) as server:
                    print("KeyVault local gateway ready", file=sys.stderr)
                    try:
                        server.serve_forever()
                    except KeyboardInterrupt:
                        pass
                return
        print(canonical({"ok": True, "result": result}))
    except GatewayError as exc:
        print(canonical({"ok": False, "error": {"code": exc.code}}))
        raise SystemExit(1)
    except Exception:
        print(canonical({"ok": False, "error": {"code": "ADMIN_OR_TRANSPORT_ERROR"}}))
        raise SystemExit(1)

if __name__ == "__main__":
    main()
