# Capability Host Protocol

CHP is an open protocol for making agent, tool, and system execution visible, replayable, and ready for governance.

The first launch goal is simple:

> See what your agents and tools actually did.

CHP is not another agent framework, tool protocol, or workflow engine. It is an execution evidence layer at the capability boundary.

## Quick Start

```bash
pip install chp-core
chp hooks install
chp session list
```

One command wires automatic evidence capture for every Claude Code session. See [docs/adopter-quickstart.md](docs/adopter-quickstart.md) for the full 10-minute path — including how to govern your own capabilities and set up policy enforcement.

## What CHP Defines

- Capability descriptors
- Host descriptors
- Invocation envelopes
- Correlation context
- Structured execution evidence
- Outcome, error, and denial semantics
- Replay queries and results
- Replay by correlation ID
- Minimal conformance requirements

## From Source

Install the Python reference host from this checkout:

```bash
python -m pip install -e packages/python
```

Run the agent/tool observability demo:

```bash
python examples/agent-operations-demo/demo.py
```

Run conformance (29 checks):

```bash
python conformance/runner.py
```

Run the test suite:

```bash
python -m pytest packages/python/tests/
```

Check spec/implementation alignment (41 checks — required before commits to `spec/` or `types.py`):

```bash
chp work check-alignment --repo-root .
```

## Minimal Capability

```python
from chp_core import LocalCapabilityHost, capability

host = LocalCapabilityHost("example-host")

@capability(
    id="math.add",
    version="1.0.0",
    description="Add two numbers.",
)
def add(a: int, b: int):
    return {"sum": a + b}

host.register(add)

result = host.invoke(
    "math.add",
    {"a": 2, "b": 3},
    correlation_id="demo-correlation",
)

events = host.replay("demo-correlation")
```

The host emits `execution_started` and `execution_completed` evidence for the invocation. If execution fails, it emits `execution_failed`. If the host denies invocation, it emits `execution_denied`.

## Repository Map

- `spec/chp-v0.1.md`: normative CHP v0.1 specification
- `schemas/`: JSON Schemas for all protocol objects
- `packages/python/chp_core/`: Python reference host (`LocalCapabilityHost`, `SQLiteEvidenceStore`)
- `conformance/`: 29-check conformance runner
- `AGENTS.md`: orientation for AI agents working in this repo
- `docs/llms.txt`: compact protocol reference for LLM context windows
- `docs/adopter-quickstart.md`: 10-minute path to first evidence event
- `docs/roadmap.md`: shipped history and upcoming milestones
- `examples/capability-host-endpoint-demo/`: HTTP-served host demo
- `examples/agent-operations-demo/`: agent/tool observability demo
- `examples/codex-self-observation-demo/`: Codex dogfooding demo
- `examples/mcp-bridge-demo/`: experimental MCP-style bridge prototype
- `docs/comparisons/chp-vs-mcp.md`: precise MCP comparison
- `docs/security/threat-model-v0.1.md`: v0.1 threat model

## CHP vs MCP

MCP exposes tools and context to AI applications. CHP governs and evidences execution of capabilities.

They fit together. MCP can be a source of capability invocation, and CHP can add correlation, replay, evidence, denial semantics, and future governance at the execution boundary.

Read more: `docs/comparisons/chp-vs-mcp.md`.

## Open Source Boundary

Open source should include local visibility:

- spec and schemas
- local host
- SDK primitives
- conformance
- local replay
- agent observability wrapper
- experimental MCP bridge prototype

Commercial value can remain around production trust:

- hosted capability graph
- multi-host trace stitching
- retention
- team workspaces
- advanced explanation
- invariant libraries
- assurance derivation
- compliance exports
- enterprise identity and RBAC

Guiding rule:

> Local visibility should be free. Production trust should be paid.

## License

MIT. See `LICENSE`.
