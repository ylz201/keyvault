"""Exercise a real MCP subprocess, not only a mocked tool handler."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from uuid import uuid4
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from keyvault.gateway.broker import Broker
from keyvault.gateway.demo import DemoProvider, DemoTransport
from keyvault.gateway.rpc import Server
from keyvault.gateway.state import State

@pytest.mark.asyncio
async def test_real_mcp_stdio_roundtrip():
    with tempfile.TemporaryDirectory(prefix="kv-mcp-") as root:
        root = Path(root)
        state = State(root / "private" / "state.db")
        token = state.create_client("mcp-client", "demo")
        token_file = root / "token"; token_file.write_text(token); token_file.chmod(0o600)
        provider, transport = DemoProvider(), DemoTransport()
        state.register_operation({"id": "read", "workspace": "demo",
            "credential": {"ref": "test", "project": "demo", "key": "TEST_API_KEY"},
            "url": "https://api.example.com/quota", "auth": {"header": "Authorization", "prefix": "Bearer "},
            "output": {"remaining": {"pointer": "/quota/remaining", "type": "integer"}}}, provider)
        state.grant("grant", "mcp-client", "read")
        server = Server(root / "rpc.sock", Broker(state, provider, transport))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        env = {**os.environ, "KEYVAULT_GATEWAY_SOCKET": str(server.socket_path), "KEYVAULT_GATEWAY_TOKEN_FILE": str(token_file)}
        try:
            params = StdioServerParameters(command=sys.executable, args=["-m", "keyvault.mcp_server"], env=env)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    assert {tool.name for tool in tools.tools} == {"credentials_list", "credential_use", "credential_status"}
                    rid = str(uuid4())
                    output = await session.call_tool("credential_use", {"grant_id": "grant", "request_id": rid})
                    text = output.content[0].text
                    assert json.loads(text)["result"]["data"] == {"remaining": 42}
                    assert "DEMO-NOT-A-REAL-CREDENTIAL" not in text
                    assert transport.calls == 1
        finally:
            server.shutdown(); server.server_close(); thread.join()
