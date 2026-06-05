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

## Quickstart

Install the Python reference host from this checkout:

```bash
python -m pip install -e packages/python
```

Run the agent/tool observability demo:

```bash
python examples/agent-operations-demo/demo.py
```

Run a served capability host endpoint demo:

```bash
chp demo endpoint
```

Run conformance:

```bash
python conformance/runner.py
```

Record development work as CHP evidence:

```bash
chp work run \
  --intent "Verify CHP tests." \
  --correlation-id chp-dev-001 \
  --test-run unit \
  -- python -m unittest discover -s packages/python/tests
chp work summary chp-dev-001
```

Validate the served-host demo as evidence:

```bash
chp work validate-demo endpoint --correlation-id chp-demo-validation
chp work replay chp-demo-validation
```

Check v0.1 protocol alignment:

```bash
chp work check-alignment --correlation-id chp-alignment
```

Check launch messaging:

```bash
chp work check-messaging --correlation-id chp-messaging
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

- `spec/chp-v0.1.md`: minimal CHP v0.1 specification
- `schemas/`: JSON Schemas for protocol objects
- `packages/python/chp_core/`: reference local host
- `examples/capability-host-endpoint-demo/`: HTTP-served host demo
- `examples/agent-operations-demo/`: agent/tool observability demo
- `examples/codex-self-observation-demo/`: Codex dogfooding demo
- `examples/mcp-bridge-demo/`: experimental MCP-style bridge prototype
- `conformance/`: conformance runner
- `docs/comparisons/chp-vs-mcp.md`: precise MCP comparison
- `docs/comparisons/chp-and-opentelemetry.md`: OpenTelemetry alignment note
- `docs/comparisons/landscape.md`: adjacent framework comparison
- `docs/design/codex-self-observation.md`: Codex dogfooding pattern
- `docs/design/public-v0.1-internal-legacy-boundary.md`: public/internal boundary
- `docs/design/evidence-integrity-v0.2.md`: future evidence integrity proposal
- `docs/security/threat-model-v0.1.md`: v0.1 threat model
- `docs/release-checklist-v0.1.md`: release-readiness checklist
- `docs/packaging-v0.1.md`: packaging and versioning plan

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
