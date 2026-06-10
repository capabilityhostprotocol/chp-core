# Contributing

CHP is early. Contributions should keep the v0.1 surface small, explicit, and testable.

## Principles

- Prefer local-first behavior over distributed assumptions.
- Preserve correlation IDs.
- Emit evidence for success, failure, and denial.
- Avoid logging sensitive payloads by default.
- Keep schemas and conformance aligned with implementation behavior.
- Do not position CHP as a replacement for MCP, workflow engines, or tracing systems.

## Development

Run Python tests:

```bash
cd packages/python
python -m pytest tests/
```

Run conformance (26 checks):

```bash
python conformance/runner.py
# or: chp conformance run
```

Verify spec/implementation alignment (41 checks — run before any commit touching `spec/`, `schemas/`, or `types.py`):

```bash
chp work check-alignment --repo-root .
```

Run demos:

```bash
python examples/agent-operations-demo/demo.py
python examples/mcp-bridge-demo/bridge.py
```

## For AI Agents

AI agents working in this repo should read `AGENTS.md` first — it describes the three invariants they must never violate and has the key commands in compact form.

## Pull Requests

Good first PRs:

- tighten schemas
- add conformance checks
- improve docs examples
- add bridge adapters
- add redaction utilities

Avoid broad rewrites while v0.1 is stabilizing.
