# MCP Bridge Demo

Status: experimental adapter prototype.

This prototype demonstrates both launch-relevant bridge directions without
requiring a live MCP server:

- MCP-style tool to CHP capability wrapper
- CHP capability to MCP-like tool surface

Run from the repository root:

```bash
python examples/mcp-bridge-demo/bridge.py
```

This demo is not a production MCP package and does not claim MCP replacement.
The production bridge should live in a separate package because it will need to
track MCP SDK versions and transport details independently from the protocol
core.
