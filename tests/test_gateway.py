from __future__ import annotations
import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import sqlite3
import threading
import time
from uuid import uuid4
import pytest
from keyvault.gateway.broker import Broker
from keyvault.gateway.protocol import GatewayError, canonical, parse_json, project_output, target, validate_operation
from keyvault.gateway.provider import SecretValue
from keyvault.gateway.state import State
from keyvault.gateway.rpc import Client, Server

FAKE_SECRET = "canary-credential-test-only-184673"
class Provider:
    revision = "v1"
    calls = 0
    def resolve(self, locator):
        self.calls += 1
        return SecretValue(FAKE_SECRET, self.revision)
class Transport:
    def __init__(self):
        self.calls = 0
        self.error = None
        self.payload = {"remaining": 42, "password": FAKE_SECRET, "headers": {"Authorization": FAKE_SECRET}}
    def get(self, op, value):
        assert value == FAKE_SECRET
        self.calls += 1
        if self.error:
            raise self.error
        return self.payload

def operation(workspace="one", ident="read-v1"):
    return {"id": ident, "workspace": workspace, "credential": {"ref": "account-one", "project": "one", "key": "TEST_API_KEY"},
            "url": "https://api.example.com/quota", "auth": {"header": "Authorization", "prefix": "Bearer "},
            "output": {"remaining": {"pointer": "/remaining", "type": "integer"}}}

@pytest.fixture
def world(tmp_path):
    state = State(tmp_path / "private" / "state.db")
    provider, transport = Provider(), Transport()
    token = state.create_client("alice", "one")
    bob = state.create_client("bob", "two")
    state.register_operation(operation(), provider)
    state.grant("g1", "alice", "read-v1", max_uses=2)
    return state, provider, transport, Broker(state, provider, transport), token, bob

def use(broker, token, grant="g1", rid=None):
    return broker.dispatch(token, "credential_use", {"grant_id": grant, "request_id": rid or str(uuid4())})

def test_no_secret_in_projection_discovery_audit_or_repr(world):
    state, p, t, b, token, _ = world
    result = use(b, token)
    assert result["data"] == {"remaining": 42}
    assert result["status"] == "SUCCEEDED"
    listed = b.dispatch(token, "credentials_list", {})
    assert listed["credentials"][0]["credential_ref"] == "account-one"
    assert FAKE_SECRET not in canonical(result) + canonical(listed) + repr(p.resolve({}))
    assert FAKE_SECRET.encode() not in state.path.read_bytes()
    assert token.encode() not in state.path.read_bytes()

def test_discovery_does_not_resolve_credentials(world):
    _, p, _, b, token, _ = world
    before = p.calls
    b.dispatch(token, "credentials_list", {})
    assert p.calls == before

@pytest.mark.parametrize("method", ["secrets_get", "secrets_set", "secrets_delete", "get_password", "admin.grant"])
def test_no_plaintext_or_administration_rpc(world, method):
    _, _, t, b, token, _ = world
    with pytest.raises(GatewayError, match="UNKNOWN_METHOD"):
        b.dispatch(token, method, {})
    assert t.calls == 0

def test_cross_client_and_workspace_denied(world):
    state, _, t, b, token, bob = world
    with pytest.raises(GatewayError, match="FORBIDDEN"):
        use(b, bob)
    with pytest.raises(GatewayError, match="GRANT_DENIED"):
        state.grant("wrong", "bob", "read-v1")
    assert b.dispatch(bob, "credentials_list", {}) == {"credentials": []}
    assert t.calls == 0

@pytest.mark.parametrize("extra", ["url", "headers", "body", "project", "principal_id", "workspace", "approved", "command"])
def test_agent_cannot_supply_target_identity_or_code(world, extra):
    _, _, t, b, token, _ = world
    with pytest.raises(GatewayError, match="INVALID_INPUT"):
        b.dispatch(token, "credential_use", {"grant_id": "g1", "request_id": str(uuid4()), extra: "attacker"})
    assert t.calls == 0

@pytest.mark.parametrize("kind", ["client", "grant", "operation"])
def test_revocation_blocks_new_requests(world, kind):
    state, _, t, b, token, _ = world
    state.revoke(kind, {"client": "alice", "grant": "g1", "operation": "read-v1"}[kind])
    with pytest.raises(GatewayError):
        use(b, token)
    assert t.calls == 0

@pytest.mark.parametrize("table,ref", [("clients", "alice"), ("grants", "g1")])
def test_expiry(world, table, ref):
    state, _, t, b, token, _ = world
    with state.transaction() as db:
        db.execute(f"UPDATE {table} SET expires=0 WHERE id=?", (ref,))
    with pytest.raises(GatewayError):
        use(b, token)
    assert t.calls == 0

def test_exhaustion_and_cached_replay(world):
    _, _, t, b, token, _ = world
    rid = str(uuid4())
    use(b, token, rid=rid); use(b, token)
    with pytest.raises(GatewayError, match="GRANT_EXHAUSTED"):
        use(b, token)
    assert use(b, token, rid=rid)["replayed"] is True
    assert t.calls == 2

def test_rotation_invalidates_before_sending(world):
    _, p, t, b, token, _ = world
    p.revision = "new-key"
    with pytest.raises(GatewayError, match="CREDENTIAL_CHANGED"):
        use(b, token)
    assert t.calls == 0

def test_duplicate_request_concurrent_and_after_restart(world):
    state, p, t, b, token, _ = world
    rid = str(uuid4())
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: use(b, token, rid=rid), range(8)))
    assert t.calls == 1
    again = use(Broker(State(state.path), p, t), token, rid=rid)
    assert again["replayed"] and t.calls == 1
    assert sum(not r["replayed"] for r in results) == 1

def test_concurrent_use_limit(world):
    state, _, t, b, token, _ = world
    state.grant("once", "alice", "read-v1", max_uses=1)
    def call(_):
        try:
            return use(b, token, grant="once")["status"]
        except GatewayError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(call, range(8)))
    assert results.count("SUCCEEDED") == 1 and results.count("GRANT_EXHAUSTED") == 7
    assert t.calls == 1

def test_request_id_cannot_be_repurposed(world):
    state, _, t, b, token, _ = world
    state.grant("g2", "alice", "read-v1")
    rid = str(uuid4()); use(b, token, rid=rid)
    with pytest.raises(GatewayError, match="REQUEST_CONFLICT"):
        use(b, token, grant="g2", rid=rid)
    assert t.calls == 1

def test_timeout_is_unknown_and_never_retried(world):
    state, p, t, b, token, _ = world
    t.error = RuntimeError(FAKE_SECRET)
    rid = str(uuid4())
    first = use(b, token, rid=rid)
    assert first["status"] == "EFFECT_UNKNOWN" and not first["retry_allowed"]
    assert use(Broker(State(state.path), p, t), token, rid=rid)["status"] == "EFFECT_UNKNOWN"
    assert t.calls == 1 and FAKE_SECRET not in canonical(first)

def test_crash_before_receipt_is_not_resubmitted(world):
    state, p, t, b, token, _ = world
    def die(*args):
        t.calls += 1
        raise SystemExit("simulated process death")
    t.get = die
    rid = str(uuid4())
    with pytest.raises(SystemExit):
        use(b, token, rid=rid)
    result = use(Broker(State(state.path), p, t), token, rid=rid)
    assert result["status"] == "EFFECT_UNKNOWN" and t.calls == 1

def test_no_audit_commit_no_network(world, monkeypatch):
    state, _, t, b, token, _ = world
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("disk full")
    monkeypatch.setattr(state, "event", fail)
    with pytest.raises(sqlite3.OperationalError):
        use(b, token)
    assert t.calls == 0
    with state.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0

def test_status_is_client_scoped(world):
    _, _, _, b, token, bob = world
    rid = str(uuid4()); use(b, token, rid=rid)
    with pytest.raises(GatewayError, match="NOT_FOUND"):
        b.dispatch(bob, "credential_status", {"request_id": rid})
    assert "data" not in b.dispatch(token, "credential_status", {"request_id": rid})

@pytest.mark.parametrize("value", [True, FAKE_SECRET, {"token": FAKE_SECRET}, [42], 2**60, None])
def test_closed_response_projection(world, value):
    _, _, t, b, token, _ = world
    t.payload = {"remaining": value}
    result = use(b, token)
    assert result["status"] == "OUTPUT_REJECTED" and "data" not in result
    assert FAKE_SECRET not in canonical(result)

@pytest.mark.parametrize("bad", ["http://example.com/", "https://127.0.0.1/", "https://[::1]/", "https://user:pass@example.com/", "https://api.example.com:8443/", "https://example.com/#fragment", "https://example.com/\r\nX:a", "https://api.example.com./", "https://api..example.com/"])
def test_unsafe_urls_rejected_at_registration(bad):
    with pytest.raises(GatewayError):
        target(bad)

def test_unbounded_string_output_not_registerable():
    op = operation(); op["output"] = {"value": {"pointer": "/value", "type": "string"}}
    with pytest.raises(GatewayError):
        validate_operation(op)

def test_duplicate_json_and_nonfinite_numbers_rejected():
    for raw in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
        with pytest.raises(GatewayError):
            parse_json(raw)

def test_public_dns_entire_answer_set_must_be_safe(monkeypatch):
    from keyvault.gateway.transport import public_addresses
    def answer(host, port, type):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    monkeypatch.setattr(socket, "getaddrinfo", answer)
    with pytest.raises(GatewayError, match="DESTINATION_DENIED"):
        public_addresses("api.example.com")

@pytest.mark.parametrize("ip", ["10.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::ffff:8.8.8.8", "2002:0808:0808::1"])
def test_denied_dns_addresses(monkeypatch, ip):
    from keyvault.gateway.transport import public_addresses
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(family, socket.SOCK_STREAM, 6, "", (ip, 443))])
    with pytest.raises(GatewayError, match="DESTINATION_DENIED"):
        public_addresses("api.example.com")

def test_local_rpc_enforces_same_boundary(world, tmp_path):
    _, _, t, b, token, bob = world
    # /tmp keeps Unix socket paths below platform limits.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="kv-rpc-") as root:
        server = Server(Path(root) / "rpc.sock", b)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            good = Client(server.socket_path, token)
            assert good.call("credentials_list", {})["credentials"]
            rid = str(uuid4())
            assert good.call("credential_use", {"grant_id": "g1", "request_id": rid})["data"] == {"remaining": 42}
            with pytest.raises(GatewayError, match="FORBIDDEN"):
                Client(server.socket_path, bob).call("credential_use", {"grant_id": "g1", "request_id": str(uuid4())})
            with pytest.raises(GatewayError, match="UNAUTHENTICATED"):
                Client(server.socket_path, "invalid").call("credentials_list", {})
            assert t.calls == 1
        finally:
            server.shutdown(); server.server_close(); thread.join()

def test_mcp_removed_raw_tools_even_with_legacy_env(monkeypatch):
    from keyvault.mcp_server import TOOLS, invoke
    monkeypatch.setenv("KEYVAULT_MCP_ALLOW_GET", "1")
    assert "secrets_get" not in [entry[0] for entry in TOOLS]
    with pytest.raises(GatewayError, match="UNKNOWN_METHOD"):
        invoke("secrets_get", {"key": "TEST_API_KEY"})

def test_state_permissions_and_symlink(tmp_path):
    directory = tmp_path / "private"; directory.mkdir(mode=0o700)
    original = directory / "original"; original.write_text("untouched"); original.chmod(0o600)
    link = directory / "state.db"; link.symlink_to(original)
    with pytest.raises(GatewayError, match="UNSAFE_STATE_PERMISSIONS"):
        State(link)
    assert original.read_text() == "untouched"
