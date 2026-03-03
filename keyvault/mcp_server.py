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

import asyncio
from keyvault.store import SecretStore
from keyvault.mcp_policy import (
    filter_allowed_keys,
    load_mcp_policy,
    require_key_allowed,
    require_project_if_needed,
)


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
                        "description": "Project scope (required by default). Set KEYVAULT_MCP_ALLOW_GLOBAL=1 to allow global scope.",
                    },
                    "all_scopes": {
                        "type": "boolean",
                        "description": "If true, list all secrets across all scopes (requires KEYVAULT_MCP_ALLOW_ALL_SCOPES=1).",
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
                        "description": "Project scope (required by default). Set KEYVAULT_MCP_ALLOW_GLOBAL=1 to allow global scope.",
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
                        "description": "Project scope (required by default). Set KEYVAULT_MCP_ALLOW_GLOBAL=1 to allow global scope.",
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
                        "description": "Project scope (required by default). Set KEYVAULT_MCP_ALLOW_GLOBAL=1 to allow global scope.",
                    },
                },
                "required": ["key"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        policy = load_mcp_policy()
    except Exception as e:
        return [TextContent(type="text", text=f"Invalid MCP policy configuration: {e}")]
    store = SecretStore()

    if name == "secrets_list":
        if not policy.allow_list:
            return [TextContent(type="text", text="secrets_list is disabled by policy (set KEYVAULT_MCP_ALLOW_LIST=1).")]

        project = arguments.get("project")
        all_scopes = bool(arguments.get("all_scopes", False))
        if all_scopes and not policy.allow_all_scopes:
            return [
                TextContent(
                    type="text",
                    text="Listing across all scopes is disabled (set KEYVAULT_MCP_ALLOW_ALL_SCOPES=1 to enable).",
                )
            ]

        try:
            if all_scopes:
                secrets = store.list_metadata(all_scopes=True)
            else:
                project = require_project_if_needed(project, policy)
                secrets = store.list_metadata(project=project, all_scopes=False)
        except ValueError as e:
            return [TextContent(type="text", text=str(e))]

        if not secrets:
            return [TextContent(type="text", text="No secrets found. Use secrets_set to add API keys.")]

        lines = []
        allowed_key_names = filter_allowed_keys([s.key for s in secrets], policy)
        allowed = {k for k in allowed_key_names}

        for s in secrets:
            if s.key not in allowed:
                continue
            scope = s.scope_label()
            desc = f" — {s.description}" if (policy.include_descriptions and s.description) else ""
            lines.append(f"• {s.key} ({scope}){desc}")

        if not lines:
            return [
                TextContent(
                    type="text",
                    text=(
                        "No keys visible under current MCP policy. "
                        "Set KEYVAULT_MCP_ALLOWED_KEYS, or set KEYVAULT_MCP_ALLOW_ALL_KEYS=1."
                    ),
                )
            ]

        return [TextContent(type="text", text="\n".join(lines))]

    elif name == "secrets_get":
        if not policy.allow_get:
            return [TextContent(type="text", text="secrets_get is disabled by policy (set KEYVAULT_MCP_ALLOW_GET=1).")]

        try:
            key = require_key_allowed(arguments["key"], policy)
            project = require_project_if_needed(arguments.get("project"), policy)
        except (KeyError, ValueError) as e:
            return [TextContent(type="text", text=str(e))]

        value = store.get(key, project=project)
        if value is None:
            return [
                TextContent(
                    type="text",
                    text=f"Secret '{key}' not found in project scope. Ask the user to configure it for this project.",
                )
            ]

        return [TextContent(type="text", text=value)]

    elif name == "secrets_set":
        if not policy.allow_set:
            return [TextContent(type="text", text="secrets_set is disabled by policy (set KEYVAULT_MCP_ALLOW_SET=1).")]

        try:
            key = require_key_allowed(arguments["key"], policy)
            value = arguments["value"]
            project = require_project_if_needed(arguments.get("project"), policy)
            description = arguments.get("description")
        except (KeyError, ValueError) as e:
            return [TextContent(type="text", text=str(e))]

        store.set(key, value, project=project, description=description)
        scope = f"project:{project}"
        return [TextContent(type="text", text=f"✅ Secret '{key}' saved ({scope}).")]

    elif name == "secrets_delete":
        if not policy.allow_delete:
            return [
                TextContent(type="text", text="secrets_delete is disabled by policy (set KEYVAULT_MCP_ALLOW_DELETE=1).")
            ]

        try:
            key = require_key_allowed(arguments["key"], policy)
            project = require_project_if_needed(arguments.get("project"), policy)
        except (KeyError, ValueError) as e:
            return [TextContent(type="text", text=str(e))]

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
