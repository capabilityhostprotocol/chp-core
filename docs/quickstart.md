# CHP Quickstart

## 1. Install

From this repository:

```bash
pip install -e packages/python packages/chp-host
pip install -e packages/chp-adapter-http packages/chp-adapter-filesystem packages/chp-adapter-audit
```

Or use the bootstrap script for a full node setup:

```bash
bash scripts/bootstrap-mac.sh primary   # macOS — primary node
bash scripts/bootstrap-linux.sh         # Linux — auto-detects arch
```

## 2. Declare And Invoke A Capability

```python
from chp_core import LocalCapabilityHost, capability

host = LocalCapabilityHost("quickstart-host")

@capability(
    id="demo.greet",
    version="1.0.0",
    description="Return a greeting.",
)
def greet(ctx, name: str):
    ctx.emit("greeted", {"name": name})
    return {"message": f"Hello {name}"}

host.register(greet)

result = host.invoke(
    "demo.greet",
    {"name": "CHP"},
    correlation_id="quickstart-001",
)

print(result.data)          # {"message": "Hello CHP"}
print(result.evidence_ids)  # list of evidence event IDs
```

Use `await host.ainvoke(...)` inside an async event loop.

## 3. Serve A Host Over HTTP

```bash
# Profile mode (recommended)
chp-host serve --profile environments/profiles/mac-dev.json

# Adapter list mode
chp-host serve --adapters http,filesystem,audit --port 8803

# Check the host
curl http://localhost:8803/health
curl http://localhost:8803/capabilities | python3 -m json.tool | head -40
```

## 4. Use With Claude Desktop (MCP)

`chp-host mcp` exposes all CHP capabilities as MCP tools. Add to
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "chp": {
      "command": "chp-host",
      "args": ["mcp", "--profile", "/Users/YOU/.chp/config/primary.json"]
    }
  }
}
```

Restart Claude Desktop. Every tool call is wrapped in CHP evidence.

See `docs/claude-desktop-mcp.md` for the full setup guide including multi-host
mesh mode and persistent evidence stores.

## 5. Set Up A Persistent Node

```bash
# One command from zero to a boot-persistent service
chp-host init --role primary --yes

# Check it started
chp-host status
curl http://localhost:8803/health
```

## 6. Mesh Multiple Nodes

```bash
# On the primary — generate an invite key for a worker
chp-host mesh invite --role worker

# On the worker — run init with the key from the invite
chp-host secrets set CHP_HOST_API_KEY    # enter the key from above
chp-host init --role worker --yes

# Back on primary — register the worker
chp-host mesh add http://<worker-ip>:8803
chp-host mesh list                        # ✓ OK
chp-host gateway                          # zero-arg: reads ~/.chp/mesh.json
```

## 7. Query Evidence

```bash
# Via adapter (requires audit adapter)
chp-host mcp --adapters audit
# Then invoke: chp.adapters.audit.query {"capability_id": "chp.adapters.http.request"}

# Direct SQLite
sqlite3 ~/.chp/mac.sqlite \
  "SELECT capability_id, outcome, started_at FROM invocations ORDER BY started_at DESC LIMIT 10;"
```

## 8. Run Conformance

```bash
python -m pytest packages/python/tests/ packages/chp-host/tests/ -q --no-cov
```

## Read Next

- `docs/claude-desktop-mcp.md` — Claude Desktop / MCP integration guide
- `docs/wire-protocol.md` — HTTP wire protocol
- `docs/why-chp.md` — design philosophy
- `docs/comparisons/chp-vs-mcp.md` — CHP vs MCP
- `docs/design/capability-adapter-layer.md` — adapter architecture
- `docs/security/threat-model-v0.1.md` — security model
- `spec/chp-v0.1.md` — protocol specification
