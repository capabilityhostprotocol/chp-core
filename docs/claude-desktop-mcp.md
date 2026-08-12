# CHP as an MCP Server — Claude Desktop Setup

CHP capabilities are exposed as MCP tools via `chp-host mcp`. Any MCP-compatible
client — Claude Desktop, Claude Code, or any MCP host — can invoke CHP
capabilities and receive governed, evidence-backed results.

## How It Works

`chp-host mcp` starts a stdio MCP server that:
- Lists every registered CHP capability as an MCP tool
- Wraps each invocation in a CHP evidence record
- Returns the evidence ID alongside the result so every tool call is replayable

## Prerequisites

```bash
# Install chp-host and at minimum the http adapter
pip install -e packages/python packages/chp-host packages/chp-adapter-http

# Or run the bootstrap script for a full primary node
bash scripts/bootstrap-mac.sh primary
```

## Option 1 — Profile Mode (recommended for Claude Desktop)

Create or reuse a host profile at `~/.chp/config/primary.json`
(created automatically by `chp-host init --role primary`).

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "chp": {
      "command": "chp-host",
      "args": [
        "mcp",
        "--profile", "/Users/YOU/.chp/config/primary.json"
      ]
    }
  }
}
```

If the profile declares a `secrets` list, `chp-host mcp` automatically reads
those keys from the macOS Keychain before loading adapters — no plaintext
secrets in the config file.

## Option 2 — Explicit Adapters

For quick experimentation without a profile file:

```json
{
  "mcpServers": {
    "chp": {
      "command": "chp-host",
      "args": [
        "mcp",
        "--adapters", "http,filesystem,git,github,audit",
        "--host-id", "chp-claude"
      ]
    }
  }
}
```

## Option 3 — Environment Mode (multi-host gateway)

Routes across your full mesh — local adapters plus remote nodes:

```json
{
  "mcpServers": {
    "chp": {
      "command": "chp-host",
      "args": [
        "mcp",
        "--environment", "dev",
        "--env-dir", "/Users/YOU/projects/chp-dev"
      ]
    }
  }
}
```

## Verify the Integration

After saving the config and restarting Claude Desktop:

1. Open a Claude conversation and type:
   ```
   Use the chp.adapters.http.request tool to GET https://httpbin.org/get
   ```
2. Claude will call the tool, CHP will wrap the HTTP request in evidence,
   and Claude will receive the response with an evidence ID.
3. You can replay the invocation:
   ```bash
   chp-host mcp --profile ~/.chp/config/primary.json
   # Then: invoke chp.adapters.audit.replay_result '{"invocation_id": "inv_..."}'
   ```

## Tool Naming

MCP tool names are derived from CHP capability IDs by replacing `.` with `__`:

| CHP capability ID | MCP tool name |
|---|---|
| `chp.adapters.http.request` | `chp__adapters__http__request` |
| `chp.adapters.git.status` | `chp__adapters__git__status` |
| `chp.adapters.audit.query` | `chp__adapters__audit__query` |

## Filtering by Status

Use `--min-status` to control which capabilities are exposed:

```json
"args": ["mcp", "--profile", "...", "--min-status", "experimental"]
```

| Value | Exposes |
|-------|---------|
| `draft` (default) | All registered capabilities |
| `experimental` | `experimental` and `certified` only |
| `certified` | Only fully certified capabilities |

## Evidence Store

By default `chp-host mcp` uses `:memory:` (ephemeral per session). To persist
evidence across sessions:

```json
"args": ["mcp", "--profile", "...", "--store", "/Users/YOU/.chp/claude.sqlite"]
```

A persistent store lets you query evidence after a Claude session ends:

```bash
sqlite3 ~/.chp/claude.sqlite \
  "SELECT capability_id, outcome, started_at FROM invocations ORDER BY started_at DESC LIMIT 10;"
```

## Mesh Mode (Claude Desktop + full node mesh)

If your primary node is already running via `chp-host init`, you can point
Claude Desktop at the live HTTP host rather than starting a new process:

```json
{
  "mcpServers": {
    "chp": {
      "command": "chp-host",
      "args": ["mcp", "--environment", "mesh", "--env-dir", "/Users/YOU/.chp"]
    }
  }
}
```

This routes Claude tool calls through the mesh gateway, spreading capability
invocations across your MacBook, NAS, and Pi nodes transparently.

## Troubleshooting

**No tools appear in Claude Desktop**

Claude Desktop requires a restart after editing the config file. Also verify:
```bash
chp-host mcp --profile ~/.chp/config/primary.json
# Should print: chp-host mcp: 'chp-primary' — N tools
```

**Adapter not found / 0 tools**

Check that the adapter packages are installed in the same Python environment
that `chp-host` resolves to:
```bash
which chp-host
chp-host adapters
```

**Keychain: WARNING — not found**

Run `chp-host secrets set KEY_NAME` for each missing key before starting the
MCP server.

**Evidence not persisting**

Pass `--store ~/.chp/claude.sqlite` to retain evidence across sessions.
