# chp-adapter-mcp

The **inbound** MCP bridge for the Capability Host Protocol. Connects to an
external [Model Context Protocol](https://modelcontextprotocol.io) server,
discovers its tools, and registers each one as a governed CHP capability
(`chp.adapters.mcp.<server>.<tool>`) with full execution evidence.

This complements the TypeScript *outbound* bridges (`@auxo/chp-runtime-mcp`),
which expose CHP capabilities **as** MCP tools. Together they make CHP and MCP
interoperate in both directions:

- **outbound** (TS): CHP capability → MCP tool
- **inbound** (this package): MCP tool → CHP capability

## Install

```bash
pip install chp-adapter-mcp
```

## Usage

```python
from chp_core import LocalCapabilityHost, register_adapter
from chp_adapter_mcp import MCPAdapter, MCPServerConfig

host = LocalCapabilityHost()
adapter = MCPAdapter(MCPServerConfig(
    name="filesystem",
    command="npx",
    args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
))
register_adapter(host, adapter)

# Every tool the server exposes is now a CHP capability:
result = host.invoke("chp.adapters.mcp.filesystem.read_file", {"path": "/tmp/x"})
```

The MCP tool's own JSON Schema becomes the capability `input_schema`, so
chp-core validates arguments before the tool runs and emits a full evidence
chain (`execution_started → mcp_tool_called → mcp_tool_result →
execution_completed`, or `execution_failed`).

## Design notes

- Each `MCPAdapter` owns one MCP server connection on a dedicated background
  thread + event loop (`_ThreadedMCPSession`), because the host runs handlers
  via `asyncio.run` (a fresh loop per call) and an MCP session is loop-bound.
- The session is abstracted behind a small protocol so it can be faked in tests
  without spawning a subprocess.
- `MCPAdapter` requires a server config, so register it manually with
  `register_adapter(host, MCPAdapter(config))`. It is also declared under the
  `chp.adapters` entry-point group for discovery/introspection.
