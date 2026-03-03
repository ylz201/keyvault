"""Allow running MCP server with: python -m keyvault.mcp_server"""
from keyvault.mcp_server import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main())
