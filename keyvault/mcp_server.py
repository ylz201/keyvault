"""Agent-safe MCP bridge. Raw secret CRUD was removed in 0.2.

This process is a CLIENT of the separately isolated credential gateway.
It must not run with access to the administrator vault, keyring or state DB.
Legacy KEYVAULT_MCP_ALLOW_GET/SET/etc variables cannot re-enable raw access.
"""
from __future__ import annotations
import asyncio
from keyvault.gateway.protocol import GatewayError
from keyvault.gateway.rpc import Client

TOOLS = (
    ("credentials_list", "List only currently authorized credential-use operations.", {}),
    ("credential_use", "Execute a pre-authorized fixed operation without receiving the credential. Reuse request_id to inspect/replay, never blindly retry with a new ID.",
     {"grant_id": {"type": "string", "maxLength": 64}, "request_id": {"type": "string", "format": "uuid"}}),
    ("credential_status", "Inspect this client's request state without resubmitting it.",
     {"request_id": {"type": "string", "format": "uuid"}}),
)

def invoke(name, arguments):
    if name not in {tool[0] for tool in TOOLS}:
        raise GatewayError("UNKNOWN_METHOD")
    return Client.from_environment().call(name, arguments)

async def main():
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    from keyvault.gateway.protocol import canonical
    server = Server("keyvault-credential-gateway")

    @server.list_tools()
    async def list_tools():
        return [Tool(name=name, description=description, inputSchema={
            "type": "object", "properties": properties, "required": list(properties), "additionalProperties": False
        }) for name, description, properties in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        try:
            result = await asyncio.to_thread(invoke, name, arguments)
            output = {"ok": True, "result": result}
        except GatewayError as exc:
            output = {"ok": False, "error": {"code": exc.code}}
        except Exception:
            output = {"ok": False, "error": {"code": "GATEWAY_UNAVAILABLE"}}
        return [TextContent(type="text", text=canonical(output))]

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
