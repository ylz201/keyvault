"""Test the production transport boundaries without real internet credentials."""
import socket
from unittest.mock import Mock
import pytest
from keyvault.gateway.protocol import GatewayError
from keyvault.gateway.transport import FixedHTTPSTransport

@pytest.fixture
def wire(monkeypatch):
    import keyvault.gateway.transport as mod
    raw = Mock(); secured = Mock()
    context = Mock(); context.wrap_socket.return_value = secured
    conn = Mock()
    response = Mock(); response.status = 200
    response.getheader.side_effect = lambda name, default=None: {"Content-Type": "application/json"}.get(name, default)
    response.read1.side_effect = [b'{"remaining":7}', b'']
    conn.getresponse.return_value = response
    resolve = Mock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, ("8.8.8.8", 443))])
    monkeypatch.setattr(mod, "public_addresses", resolve)
    monkeypatch.setattr(mod.socket, "socket", Mock(return_value=raw))
    monkeypatch.setattr(mod.ssl, "create_default_context", Mock(return_value=context))
    monkeypatch.setattr(mod.http.client, "HTTPConnection", Mock(return_value=conn))
    op = {"url": "https://api.example.com/quota", "auth": {"header": "Authorization", "prefix": "Bearer "}}
    return raw, secured, context, conn, response, resolve, op

def test_pinned_address_hostname_tls_and_no_proxy_env(wire, monkeypatch):
    raw, secured, context, conn, _, resolve, op = wire
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.example")
    assert FixedHTTPSTransport().get(op, "test-only-key") == {"remaining": 7}
    resolve.assert_called_once_with("api.example.com")
    raw.connect.assert_called_once_with(("8.8.8.8", 443))
    context.wrap_socket.assert_called_once_with(raw, server_hostname="api.example.com")
    assert conn.request.call_args.args == ("GET", "/quota")
    assert conn.request.call_args.kwargs["headers"]["Authorization"] == "Bearer test-only-key"
    conn.set_tunnel.assert_not_called()
    conn.close.assert_called_once()

@pytest.mark.parametrize("status,code", [(301,"REDIRECT_DENIED"), (302,"REDIRECT_DENIED"), (307,"REDIRECT_DENIED"), (308,"REDIRECT_DENIED"), (401,"UPSTREAM_REJECTED"), (500,"UPSTREAM_REJECTED")])
def test_no_redirect_follow_or_upstream_retry(wire, status, code):
    _, _, _, conn, response, _, op = wire; response.status = status
    with pytest.raises(GatewayError, match=code):
        FixedHTTPSTransport().get(op, "test-only-key")
    assert conn.request.call_count == 1
    response.read1.assert_not_called()

def test_oversize_response_denied(wire):
    _, _, _, _, response, _, op = wire
    response.read1.side_effect = None; response.read1.return_value = b'x' * 8192
    with pytest.raises(GatewayError, match="OUTPUT_REJECTED"):
        FixedHTTPSTransport().get(op, "test-only-key")

def test_network_exception_does_not_echo_header(wire):
    _, _, _, conn, _, _, op = wire
    conn.getresponse.side_effect = RuntimeError("test-only-key")
    with pytest.raises(GatewayError) as raised:
        FixedHTTPSTransport().get(op, "test-only-key")
    assert str(raised.value) == "EFFECT_UNKNOWN"
