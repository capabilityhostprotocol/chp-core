# Contributing

CHP is early. Contributions should keep the v0.1 surface small, explicit, and testable.

## Contributor License Agreement

Before we can merge your contribution, you must sign the
[Contributor License Agreement](CLA.md). You keep ownership of your work; the CLA
lets Project Auxo, Inc. distribute and (re)license it so CHP stays durable. The
process is automated: open a pull request and a bot will prompt you to sign by
posting a one-line comment. You only sign once.

## What's open vs. commercial

This repository is the open core — Apache-2.0 (code) and CC BY 4.0 (spec/docs).
Commercial components (the hosted evidence service, registry network, compliance
products, and enterprise/regulated-system adapters) live in separate repositories
and are **not** accepted here. See [`GOVERNANCE.md`](GOVERNANCE.md).

## Proposing a protocol change

Protocol-level changes (spec text, schemas, canonical bytes, wire routes,
reserved names) follow the process in
[`spec/proposals/README.md`](spec/proposals/README.md): additive by default,
byte-compat vectors as the regression gate, both implementations (Python + TS)
move together, and every wire-visible change gains a conformance check. Start
from [`spec/README.md`](spec/README.md) (the index), copy the proposal template,
and link a Radicle issue. Regenerate vectors only via
`scripts/gen-test-vectors.py`; regenerate the reserved-names registry via
`scripts/gen-reserved-names.py`; record the change in
[`spec/CHANGELOG.md`](spec/CHANGELOG.md).

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
python -m unittest discover -s tests
```

Run conformance:

```bash
python conformance/runner.py
```

Run demos:

```bash
python examples/agent-operations-demo/demo.py
python examples/mcp-bridge-demo/bridge.py
```

## Pull Requests

Good first PRs:

- tighten schemas
- add conformance checks
- improve docs examples
- add bridge adapters
- add redaction utilities

**Writing a new adapter?** See [`docs/adapter-authoring.md`](docs/adapter-authoring.md) for the
full authoring guide — contract, conformance testing, publishing, and community listing.

Avoid broad rewrites while v0.1 is stabilizing.
