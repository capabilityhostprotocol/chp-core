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
