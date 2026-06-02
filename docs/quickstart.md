# CHP Quickstart

## 1. Install

```bash
pip install chp-core
```

From this repository:

```bash
python -m pip install -e packages/python
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
def greet(name: str):
    return {"message": f"Hello {name}"}

host.register(greet)

result = host.invoke(
    "demo.greet",
    {"name": "CHP"},
    correlation_id="quickstart-001",
)

print(result.to_dict())
print(host.replay_result("quickstart-001").to_dict())
```

When already inside an async event loop, use `await host.ainvoke(...)` instead
of `host.invoke(...)`.

Evidence payloads emitted through `ctx.emit(...)` are redacted by default for
common sensitive keys such as `token`, `secret`, `password`, `authorization`,
and `api_key`.

## 3. Run The Agent Demo

```bash
python examples/agent-operations-demo/demo.py
```

## 4. Serve A Capability Host

Run an end-to-end HTTP endpoint demo:

```bash
chp demo endpoint
```

Or serve the demo host and call it yourself:

```bash
chp serve-demo --port 8765
```

In another terminal:

```bash
chp host
chp invoke demo.search_information \
  --payload '{"query":"CHP vs MCP"}' \
  --correlation-id corr_demo
chp replay corr_demo
```

The served endpoint is deliberately small: `GET /host`, `GET /capabilities`,
`POST /invoke`, `POST /replay`, and `GET /replay/{correlation_id}`.

## 5. Run Conformance

```bash
python conformance/runner.py
python conformance/runner.py --sample failing-no-evidence
```

The first command should pass. The second command should fail several checks because the sample host does not emit evidence.

## 6. Record Development Evidence

```bash
chp work run \
  --intent "Verify the Python test suite." \
  --correlation-id chp-dev-001 \
  --test-run unit \
  -- python -m unittest discover -s packages/python/tests

chp work summary chp-dev-001
chp work replay chp-dev-001
chp work explain chp-dev-001
```

`chp work` records engineering actions into the local ignored evidence store.
When changed files are not provided explicitly, it detects them from Git status.

Validate the endpoint demo as CHP evidence:

```bash
chp work validate-demo endpoint --correlation-id chp-demo-validation
chp work replay chp-demo-validation
```

Check that the v0.1 spec, schemas, Python models, and TypeScript types still
agree:

```bash
chp work check-alignment --correlation-id chp-alignment
chp work replay chp-alignment
```

Check public launch messaging:

```bash
chp work check-messaging --correlation-id chp-messaging
chp work replay chp-messaging
```

## 7. Read Next

- `spec/chp-v0.1.md`
- `examples/capability-host-endpoint-demo/README.md`
- `docs/comparisons/chp-vs-mcp.md`
- `docs/comparisons/chp-and-opentelemetry.md`
- `docs/design/codex-self-observation.md`
- `docs/design/public-v0.1-internal-legacy-boundary.md`
- `docs/security/threat-model-v0.1.md`
- `docs/packaging-v0.1.md`
- `docs/release-checklist-v0.1.md`
