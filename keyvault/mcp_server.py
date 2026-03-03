"""
KeyVault MCP Server — Expose secrets management to AI Agents via MCP protocol.

Usage:
    python -m keyvault.mcp_server

Configure in claude_desktop_config.json:
    {
        "mcpServers": {
            "keyvault": {
                "command": "python",
                "args": ["-m", "keyvault.mcp_server"]
            }
        }
    }
"""

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    raise ImportError(
        "MCP SDK not installed. Install with: pip install keyvault-ai[mcp]"
    )

import json
import asyncio
from keyvault.store import SecretStore


server = Server("keyvault")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="secrets_list",
            description="List all available secret key names (values are masked for security).",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {
                        "type": "string",
                        "description": "Optional project scope filter. Omit for global secrets.",
                    },
                    "all_scopes": {
                        "type": "boolean",
                        "description": "If true, list all secrets across all scopes.",
                        "default": False,
                    },
                },
            },
        ),
        Tool(
            name="secrets_get",
            description="Get the value of a specific secret by key name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "The secret key name (e.g. OPENAI_API_KEY)",
                    },
                    "project": {
                        "type": "string",
                        "description": "Optional project scope. Omit for global.",
                    },
                },
                "required": ["key"],
            },
        ),
        Tool(
            name="secrets_set",
            description="Set (create or update) a secret. Use this to help the user configure API keys.",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Secret key name (e.g. OPENAI_API_KEY)",
                    },
                    "value": {
                        "type": "string",
                        "description": "The secret value / API key",
                    },
                    "project": {
                        "type": "string",
                        "description": "Optional project scope. Omit for global.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional description / notes",
                    },
                },
                "required": ["key", "value"],
            },
        ),
        Tool(
            name="secrets_delete",
            description="Delete a secret by key name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Secret key name to delete.",
                    },
                    "project": {
                        "type": "string",
                        "description": "Optional project scope. Omit for global.",
                    },
                },
                "required": ["key"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    store = SecretStore()

    if name == "secrets_list":
        project = arguments.get("project")
        all_scopes = arguments.get("all_scopes", False)
        secrets = store.list(project=project, all_scopes=all_scopes)

        if not secrets:
            return [TextContent(type="text", text="No secrets found. Use secrets_set to add API keys.")]

        lines = []
        for s in secrets:
            scope = s.scope_label()
            desc = f" — {s.description}" if s.description else ""
            lines.append(f"• {s.key} ({scope}){desc}")

        return [TextContent(type="text", text="\n".join(lines))]

    elif name == "secrets_get":
        key = arguments["key"]
        project = arguments.get("project")

        value = store.get(key, project=project)
        if value is None and project:
            value = store.get(key, project=None)  # fallback to global

        if value is None:
            return [TextContent(type="text", text=f"Secret '{key}' not found. Please ask the user to configure it.")]

        return [TextContent(type="text", text=value)]

    elif name == "secrets_set":
        key = arguments["key"]
        value = arguments["value"]
        project = arguments.get("project")
        description = arguments.get("description")

        store.set(key, value, project=project, description=description)
        scope = f"project:{project}" if project else "global"
        return [TextContent(type="text", text=f"✅ Secret '{key}' saved ({scope}).")]

    elif name == "secrets_delete":
        key = arguments["key"]
        project = arguments.get("project")

        deleted = store.delete(key, project=project)
        if deleted:
            return [TextContent(type="text", text=f"🗑️ Secret '{key}' deleted.")]
        else:
            return [TextContent(type="text", text=f"❌ Secret '{key}' not found.")]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
