#!/usr/bin/env python3
"""A tiny MCP stdio server so the MCP adapter is testable with zero external setup.

Run indirectly via the MCP adapter (configured in mcp.json), not directly.
Requires the `mcp` package (a dependency of chp-adapter-mcp).
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def greet(name: str) -> str:
    """Return a friendly greeting."""
    return f"hello {name}"


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


if __name__ == "__main__":
    mcp.run()
