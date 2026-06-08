# CHP Adopter Quickstart

Get CHP evidence flowing in 10 minutes.

---

## Install

```bash
pip install chp-core
```

Requires Python 3.10+.

---

## Path A — Observe your Claude Code sessions (3 min)

If you use Claude Code, one command wires automatic evidence capture for every session:

```bash
chp hooks install
```

This adds PostToolUse and Stop hooks to `~/.claude/settings.json`. Every tool call
(Read, Bash, Edit, etc.) is recorded in `.chp/claude-code-sessions.sqlite`.

```bash
chp session list           # see recent sessions
chp session show <id>      # inspect files, commands, chain integrity
chp session replay <id>    # full event trace for a session
```

For Codex CLI or Gemini CLI, use `chp hooks install --codex` or `chp hooks install --gemini`.

---

## Path B — Govern your own capabilities (5 min)

Wrap any function in a CHP capability and every call gets evidence:

```python
from chp_core import LocalCapabilityHost, capability

@capability(
    id="files.word_count",
    version="1.0.0",
    description="Count words in a text string.",
)
def word_count(text: str) -> dict:
    return {"word_count": len(text.split())}

host = LocalCapabilityHost(host_id="my-project")
host.register(word_count)

# Invoke — evidence recorded automatically
result = host.invoke("files.word_count", {"text": "hello world"}, correlation_id="task-001")
print(result.outcome)   # success
print(result.data)      # {"word_count": 2}

# Replay the evidence
events = host.replay("task-001")
for ev in events:
    print(ev["event_type"], ev["outcome"])
```

Run it:
```bash
python my_capability.py
```

Evidence is stored in `.chp/my-project.sqlite` (or `~/.chp/my-project.sqlite` if no local `.chp/` directory).

---

## Verify your setup

After installing, run a quick smoke test to confirm the host and evidence store are working:

```bash
chp host verify
# chp host is healthy — evidence recorded and replayed
```

Pass `--store-dir` to also verify a real SQLite file gets written and cleaned up:

```bash
chp host verify --store-dir .chp
```

Exits 0 on success, 1 on failure (with a reason printed to stderr).

---

## Serve over HTTP

Expose any host over the CHP HTTP API with one command:

```bash
chp serve-http --module my_app:create_host
# Serving CHP host 'my-project' at http://127.0.0.1:8765
```

`my_app:create_host` is a Python import path + a zero-argument factory function that returns a `LocalCapabilityHost`.

Available routes:

| Route | Method | Description |
|-------|--------|-------------|
| `/health` | GET | Liveness check |
| `/host` | GET | Full host descriptor |
| `/capabilities` | GET | Capability list |
| `/invoke` | POST | Invoke a capability |
| `/replay/{id}` | GET | Replay by correlation ID |

Options: `--port 8765`, `--bind 127.0.0.1`.

---

## What you get

| Feature | How |
|---|---|
| SHA256-chained evidence | Every invocation appended to SQLite with `prev_hash` |
| Replay by correlation ID | `host.replay("task-001")` returns all related events |
| Policy enforcement | `.chp/policy.json` → `chp hooks install --with-governance` |
| CLI inspection | `chp session list/show/replay/export` |
| MCP server | `python -m tools.chp_mcp` — agent-loop access to evidence |

---

## Policy (optional)

Block dangerous patterns before they execute:

```json
{
  "block_patterns": [
    {
      "capability_id": "claude_code.bash",
      "field": "command",
      "pattern": "rm\\s+-rf\\s+(?!/tmp)",
      "reason": "destructive deletion requires explicit approval"
    }
  ],
  "max_risk_tier": "high"
}
```

Save as `.chp/policy.json`, then:
```bash
chp policy lint .chp/policy.json   # validate
chp hooks install --with-governance  # wire PreToolUse hook
```

---

## Next steps

- **More examples**: `examples/` — 14 runnable demos from simple tool calls to multi-agent correlation
- **Protocol spec**: `spec/chp-v0.1.md` — full object model and wire protocol
- **CLI reference**: `chp --help`
- **Dev workflow**: `docs/quickstart.md` — using CHP to govern your own development with `chp work *`
