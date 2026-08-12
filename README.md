# Capability Host Protocol

[![PyPI](https://img.shields.io/pypi/v/chp-core?label=chp-core)](https://pypi.org/project/chp-core/)
[![Python](https://img.shields.io/pypi/pyversions/chp-core)](https://pypi.org/project/chp-core/)
[![npm](https://img.shields.io/npm/v/@capabilityhostprotocol/sdk?label=%40capabilityhostprotocol%2Fsdk)](https://www.npmjs.com/package/@capabilityhostprotocol/sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-capabilityhostprotocol.com-informational)](https://docs.capabilityhostprotocol.com)

CHP is the open protocol for declaring, **governing**, and **proving** what agents, tools, and systems do — the single signed plane where a human approval, an agent's action, and a system call become the same governed, tamper-evident, replayable event.

The hook is simple:

> See what your agents and tools actually did — and what governed it.

## Try it in two minutes

Your coding agent reads files, runs commands, calls tools. This puts a governed boundary at the point of action — no application code changes:

```bash
pip install chp-core
chp hooks install                        # hooks Claude Code
chp hooks install --all-harnesses        # ...or Claude Code + Codex + Gemini CLI
```

Use your agent normally, then look at what it did:

```bash
chp session list
chp session tree <session_id>
```

Every tool call is a typed evidence event, hash-chained and stored locally in `~/.chp/evidence.sqlite`. A denial is a first-class event with a reason code — not a swallowed exception — and the chain is tamper-evident, so someone who did not run the agent can still tell whether the record is intact.

Prefer to drive the protocol directly? `chp serve-demo` starts a governed host and prints a copy-pasteable first invocation.

**Full guide:** [`docs/quickstart.md`](docs/quickstart.md) · **why it exists:** [`docs/why-chp.md`](docs/why-chp.md) · **docs site:** [docs.capabilityhostprotocol.com](https://docs.capabilityhostprotocol.com)

## What you get back

Replay is by correlation ID, and the record answers more than "what happened" — from [`examples/agent-operations-demo/`](examples/agent-operations-demo/):

```json
[
  {"sequence": 1,  "event_type": "execution_started",   "capability_id": "trace_execution", "outcome": null},
  {"sequence": 3,  "event_type": "execution_completed", "capability_id": "trace_execution", "outcome": "success"},
  {"sequence": 7,  "event_type": "execution_started",   "capability_id": "tool.add",        "outcome": null},
  {"sequence": 12, "event_type": "execution_started",   "capability_id": "tool.multiply",   "outcome": null},
  {"sequence": 13, "event_type": "execution_completed", "capability_id": "tool.multiply",   "outcome": "success"}
]
```

You can also ask what a policy *would* have done to a run that already happened:

```json
{
  "invariant": {"id": "deny_multiply_tool", "kind": "capability_id_matches"},
  "would_have_denied": true,
  "violating_events": [{"capability_id": "tool.multiply", "event_type": "execution_started"}]
}
```

## Why a protocol, not a library

CHP is not another agent framework, tool protocol, or workflow engine. It is the **governed evidence plane** at the capability boundary: what ran *and* what governed it (policy, risk tier, safety checks, human approval, autonomy budgets, denial) emit onto one signed, correlated record. Observability tools split execution across separate, optional, unsigned signals and carry no governance; CHP unifies both and proves them.

**Status:** CHP is a pre-1.0 **release candidate (v0.9.2)** — a frozen, additive wire surface backed by two independent implementations (Python + TypeScript) that pass conformance. `chp-core` ships on PyPI.

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

## Install

```bash
pip install chp-core                 # zero runtime dependencies
pip install 'chp-core[schema]'       # enforce declared input_schema
pip install 'chp-core[signing]'      # ed25519 — signed hosts, bundles, mandates
npm install @capabilityhostprotocol/sdk   # TypeScript client + verifier (alpha)
```

`chp host verify` smoke-tests the install in under a second and reports whether input-schema validation is enforced.

From this checkout: `python -m pip install -e packages/python`.

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

print(result.outcome)       # "success"
print(result.data)          # {"sum": 5}

for event in host.replay("demo-correlation"):
    print(event.event_type)  # execution_started, execution_completed
```

The host emits `execution_started` and `execution_completed` evidence for the invocation. If execution fails, it emits `execution_failed`. If the host denies invocation, it emits `execution_denied`.

## Repository Map

- `spec/README.md`: **the specification index** — core (v0.1), governance
  vocabulary, invocation pipeline, HTTP binding, evidence integrity + anchors
  (v0.2), reserved names, test vectors, changelog, proposal process
- `schemas/`: JSON Schemas for protocol objects
- `packages/python/chp_core/`: reference host (Python)
- `packages/chp-sdk/` + `packages/chp-host-ts/`: the second implementation (TypeScript)
- `examples/capability-host-endpoint-demo/`: HTTP-served host demo
- `examples/agent-operations-demo/`: agent/tool observability demo
- `examples/codex-self-observation-demo/`: Codex dogfooding demo
- `examples/mcp-bridge-demo/`: experimental MCP-style bridge prototype
- `conformance/`: conformance runner
- `docs/quickstart.md`: install, first run, serving, mesh
- `docs/why-chp.md`: the problem and the thesis
- `docs/adapter-authoring.md`: writing your own capability adapter
- `docs/production-runbook.md`: operations, backup/restore, key compromise
- `docs/comparisons/chp-vs-mcp.md`: precise MCP comparison
- `docs/comparisons/chp-and-opentelemetry.md`: OpenTelemetry alignment note
- `docs/comparisons/landscape.md`: adjacent framework comparison
- `docs/security/threat-model-v0.1.md`: v0.1 threat model

## Production Posture

The reference implementation is hardened for production operation: WAL
multi-writer safety with hot backup (`chp store backup --verify`), SIGTERM
drain (in-flight work completes before exit), a fail-loud auth flag
(`CHP_HOST_REQUIRE_AUTH=1`), scheduled retention, and operator metrics (store
size, witness-loop liveness, revocation counts, internal errors). Operations,
backup/restore, rolling upgrades, and the key-compromise runbook:
[docs/production-runbook.md](docs/production-runbook.md). Vulnerability
reporting: [SECURITY.md](SECURITY.md).

## CHP vs MCP

MCP exposes tools and context to AI applications. CHP governs and evidences execution of capabilities.

They fit together. MCP can be a source of capability invocation, and CHP adds correlation, replay, evidence, denial semantics, and governance at the execution boundary.

Read more: `docs/comparisons/chp-vs-mcp.md`.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. One thing to know before you open a pull request: **this repository is a generated mirror** of a private development repository. CI rejects pull requests that touch `packages/`, `docs/`, `spec/`, `schemas/`, or `examples/` from a branch that is not `sync/*`, so a code PR against those paths will fail by construction no matter how good it is.

That is not a brush-off — it is the publishing model, and we would rather say so up front than let you find out from a red check. Issues, spec proposals, comparisons, and discussion are the highest-bandwidth way in today; open an issue and we will route the change through the internal flow with attribution.

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

CHP is dual-licensed by asset:

- **Code** (`packages/`, `conformance/`, `examples/`, `scripts/`): Apache License 2.0 — see [`LICENSE`](LICENSE).
- **Specification, schemas & docs** (`spec/`, `schemas/`, `docs/`): Creative Commons Attribution 4.0 (CC BY 4.0) — see [`LICENSE-DOCS`](LICENSE-DOCS). Implementing the specification is additionally covered by a royalty-free patent grant — see [`PATENTS`](PATENTS).
- **Trademarks**: "CHP" and "CHP-Certified" — see [`TRADEMARK.md`](TRADEMARK.md).

Contributions are accepted under the [Contributor License Agreement](CLA.md); see [`CONTRIBUTING.md`](CONTRIBUTING.md).

Copyright © 2026 Project Auxo, Inc. See [`NOTICE`](NOTICE).
