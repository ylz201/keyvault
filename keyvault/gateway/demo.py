"""No-network demonstration. Only this module uses fake credentials."""
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4
from .broker import Broker
from .provider import SecretValue
from .protocol import GatewayError
from .state import State

class DemoProvider:
    def resolve(self, locator):
        return SecretValue("DEMO-NOT-A-REAL-CREDENTIAL", "demo-v1")

class DemoTransport:
    def __init__(self):
        self.calls = 0
    def get(self, operation, secret):
        self.calls += 1
        return {"quota": {"remaining": 42}, "untrusted_extra": secret}

def run():
    with TemporaryDirectory(prefix="keyvault-demo-") as root:
        state = State(Path(root) / "private" / "state.db")
        provider, transport = DemoProvider(), DemoTransport()
        alice = state.create_client("abo-demo", "demo")
        bob = state.create_client("other-agent", "other-workspace")
        state.register_operation({"id": "quota-read-v1", "workspace": "demo",
            "credential": {"ref": "account-demo", "project": "demo", "key": "DEMO_KEY"},
            "url": "https://api.example.com/quota", "auth": {"header": "Authorization", "prefix": "Bearer "},
            "output": {"remaining": {"pointer": "/quota/remaining", "type": "integer"}}}, provider)
        state.grant("quota-grant", "abo-demo", "quota-read-v1", max_uses=1)
        broker = Broker(state, provider, transport)
        request = {"grant_id": "quota-grant", "request_id": str(uuid4())}
        result = broker.dispatch(alice, "credential_use", request)
        replay = Broker(state, provider, transport).dispatch(alice, "credential_use", request)
        try:
            broker.dispatch(bob, "credential_use", request)
        except GatewayError as exc:
            denied = exc.code
        state.revoke("grant", "quota-grant")
        try:
            broker.dispatch(alice, "credential_use", {**request, "request_id": str(uuid4())})
        except GatewayError as exc:
            revoked = exc.code
        return {"demo_only": True, "result": result, "replayed": replay["replayed"],
                "upstream_calls": transport.calls, "cross_client": denied, "after_revocation": revoked}
