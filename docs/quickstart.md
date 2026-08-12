# CHP Quickstart

Two ways in. Start with the first — it needs no application code.

## 1. Govern the agent you already use (2 minutes)

```bash
pip install chp-core
chp hooks install                     # Claude Code
chp hooks install --all-harnesses     # ...or Claude Code + Codex + Gemini CLI
```

Now use your agent exactly as you normally would. Every tool call it makes — `Bash`, `Read`,
`Edit`, `Write`, `WebFetch` — is captured as a typed evidence event, hash-chained,
stored locally in `~/.chp/evidence.sqlite`.

Then look at what it actually did:

```bash
chp session list                  # sessions CHP has recorded
chp session tree <session_id>     # every call in one, as a replayable tree
chp session autonomy-report <session_id>
```

The point is not the log. A denial is a first-class event with a reason code, not a
swallowed exception; the chain is tamper-evident, so an inspector who did not run
the agent can still tell whether the record is intact.

Nothing to configure, and nothing to change in your code.

## 2. Install

```bash
pip install chp-core
```

`chp-core` has **zero runtime dependencies**. Two extras are worth knowing:

```bash
pip install 'chp-core[schema]'    # enforce capabilities' declared input_schema
pip install 'chp-core[signing]'   # ed25519 — signed hosts, bundles, mandates
```

Without `[schema]`, a capability's declared `input_schema` is **not enforced** —
the host says so at registration and `chp host verify` reports it. Without
`[signing]` evidence stays at the hash-chain tier rather than the signed tier.
For anything beyond local experiments you want both.

TypeScript (second implementation, currently alpha):

```bash
npm install @capabilityhostprotocol/sdk
```

Check the install:

```bash
chp host verify     # smoke-tests the host and evidence store in under a second
```

Contributors working from this repository can use editable installs
(`pip install -e packages/python packages/chp-host`) or the full-node bootstrap
scripts (`scripts/bootstrap-mac.sh primary`, `scripts/bootstrap-linux.sh`).

## 3. Declare and invoke your own capability

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

print(result.outcome)       # "success"
print(result.data)          # {"message": "Hello CHP"}
print(result.evidence_ids)  # the evidence events this invocation emitted

for event in host.replay("quickstart-001"):
    print(event.event_type)  # execution_started, greeted, execution_completed
```

Use `await host.ainvoke(...)` inside an async event loop.

Or drive the same thing from the CLI against the built-in demo host:

```bash
chp serve-demo                                                    # a governed host on :8765
chp invoke demo.echo --payload '{"text":"hello"}' \
    --correlation-id first-run                                    # in another terminal
chp replay first-run                                              # its evidence chain
chp keygen                                                        # sign evidence (signed tier)
```

## 4. Serve a host over HTTP

```bash
# Expose your own host via a factory function
chp serve-http --module your_app:create_host --port 8765

# Or run the adapter host
chp-host serve --adapters http,filesystem,audit --port 8803

# Check it
curl http://localhost:8803/health
curl http://localhost:8803/capabilities | python3 -m json.tool | head -40
```

`chp-host serve --profile <file>` takes a profile written by `chp-host init`
(below); the flag expects a path you supply, not one that ships with the package.

Capability adapters install as separate packages
(`pip install chp-adapter-http chp-adapter-filesystem chp-adapter-audit`). Adapter
releases trail the core release train, so pin what you depend on and check
`pip index versions chp-adapter-<name>` rather than assuming parity with `chp-core`.

## 5. Use with Claude Desktop (MCP)

`chp-host mcp` exposes CHP capabilities as MCP tools. Add to
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

## 6. Set up a persistent node

```bash
# One command from zero to a boot-persistent service
chp-host init --role primary --yes

# Check it started
chp-host status
curl http://localhost:8803/health
```

## 7. Mesh multiple nodes

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

## 8. Query evidence

```bash
# Via adapter (requires audit adapter)
chp-host mcp --adapters audit
# Then invoke: chp.adapters.audit.query {"capability_id": "chp.adapters.http.request"}

# Direct SQLite
sqlite3 ~/.chp/mac.sqlite \
  "SELECT capability_id, outcome, started_at FROM invocations ORDER BY started_at DESC LIMIT 10;"
```

## 9. Run conformance

```bash
python -m pytest packages/python/tests/ packages/chp-host/tests/ -q --no-cov
```

## Read next

- `docs/why-chp.md` — why the protocol exists
- `docs/claude-desktop-mcp.md` — Claude Desktop / MCP integration guide
- `docs/adapter-authoring.md` — writing your own capability adapter
- `docs/wire-protocol.md` — HTTP wire protocol
- `docs/comparisons/chp-vs-mcp.md` — CHP vs MCP
- `docs/security/threat-model-v0.1.md` — security model
- `spec/README.md` — the specification index
