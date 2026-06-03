# CHP Onboarding

How to adopt the Capability Host Protocol in your project. Start with the Python reference host — it covers the full v0.1 protocol surface in about 15 minutes.

## Install

```bash
pip install chp-core
```

Requires Python 3.10+. No external services, databases, or network dependencies.

## Define Your First Capability

Wrap any existing function as a CHP capability using the `@capability` decorator:

```python
from chp_core import LocalCapabilityHost, capability

host = LocalCapabilityHost("my-host")

@capability(
    id="myproject.greet",
    version="1.0.0",
    description="Return a greeting.",
)
def greet(name: str):
    return {"message": f"Hello {name}"}

host.register(greet)
```

The `id` follows a dot-separated namespace convention:

```
{project}.{module}.{action}    e.g.,  payments.transfer.initiate
{service}.{domain}.{verb}      e.g.,  auth.session.create
```

Use lowercase with dots for hierarchy. Version separately: `payments.transfer.initiate:1.0.0`.

## Invoke and Replay

```python
result = host.invoke(
    "myproject.greet",
    {"name": "CHP"},
    correlation_id="onboard-001",
)

print(result.outcome)   # "success"
print(result.output)    # {"message": "Hello CHP"}

events = host.replay("onboard-001")
for event in events:
    print(event.evidence_type, event.sequence)
# execution_started 1
# execution_completed 2
```

The host emits `execution_started` and `execution_completed` evidence automatically.
If execution fails, it emits `execution_failed`. If the host denies the invocation, it emits `execution_denied`.

Evidence is stored locally in `.chp/` (SQLite). No network call is made.

## Correlation

The `correlation_id` links related executions. Pass it through to connect multiple capability invocations to the same trace:

```python
corr = "user-session-abc"

host.invoke("auth.session.validate", {"token": tok}, correlation_id=corr)
host.invoke("payments.transfer.initiate", {"amount": 100}, correlation_id=corr)
host.invoke("audit.log.write", {"action": "transfer"}, correlation_id=corr)

events = host.replay(corr)
# → all three invocations in sequence order
```

## Serving a Capability Host

To expose capabilities over HTTP:

```bash
chp serve-demo --port 8765   # starts the built-in demo host
```

Or build your own:

```python
from chp_core import LocalCapabilityHost, capability
from chp_core.server import serve

host = LocalCapabilityHost("production-host")

@capability(id="data.query", version="1.0.0", description="Run a query.")
def query(sql: str):
    return {"rows": run_query(sql)}

host.register(query)
serve(host, port=8765)
```

The served host exposes:
- `GET /host` — host descriptor
- `GET /capabilities` — capability list
- `POST /invoke` — invoke a capability
- `POST /replay` — replay by correlation ID

## TypeScript Types

For TypeScript projects consuming a CHP host:

```bash
npm install @capabilityhostprotocol/types
```

```typescript
import type {
  CapabilityDescriptor,
  InvocationEnvelope,
  InvocationResult,
  ExecutionEvidence,
  CorrelationContext,
  ReplayResult,
} from '@capabilityhostprotocol/types';
```

## Evidence Payload Redaction

Evidence payloads are redacted by default for common sensitive keys: `token`, `secret`, `password`, `authorization`, `api_key`. The raw value is replaced with `"[REDACTED]"` in stored evidence.

## Where to Go Next

- `spec/chp-v0.1.md` — normative protocol specification
- `docs/quickstart.md` — 15-minute getting-started guide
- `docs/why-chp.md` — motivation and design rationale
- `docs/comparisons/chp-vs-mcp.md` — how CHP and MCP compose
- `docs/comparisons/chp-and-opentelemetry.md` — CHP evidence vs OTel telemetry
- `conformance/runner.py` — verify a host against the conformance suite
- `examples/` — runnable demos
