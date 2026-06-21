"""chp-adapter-mcp — wrap MCP server tools as governed CHP capabilities.

This is the *inbound* MCP bridge: it connects to an external Model Context
Protocol server, discovers its tools, and registers each one as a CHP
capability (``chp.adapters.mcp.<server>.<tool>``) with full execution evidence.
It complements the TypeScript *outbound* bridges (which expose CHP capabilities
as MCP tools).

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_mcp import MCPAdapter, MCPServerConfig

    host = LocalCapabilityHost()
    adapter = MCPAdapter(MCPServerConfig(
        name="filesystem",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    ))
    register_adapter(host, adapter)
    # host now exposes chp.adapters.mcp.filesystem.<tool> capabilities
"""

from __future__ import annotations

from .adapter import MCPAdapter, MCPServerConfig

__all__ = ["MCPAdapter", "MCPServerConfig"]
