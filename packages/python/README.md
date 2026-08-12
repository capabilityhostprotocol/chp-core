# chp-core

The reference local host for the [Capability Host Protocol](https://capabilityhostprotocol.com) —
the open protocol for declaring, **governing**, and **proving** what agents, tools, and systems do.

> See what your agents and tools actually did — and what governed it.

## Try it in two minutes

Your coding agent reads files, runs commands, calls tools. This puts a governed boundary at the
point of action — no application code changes:

```bash
pip install chp-core
chp hooks install                     # Claude Code
chp hooks install --all-harnesses     # ...or Claude Code + Codex + Gemini CLI
```

Use your agent normally, then look at what it did:

```bash
chp session list
chp session tree <session_id>
```

Every tool call becomes a typed evidence event, hash-chained and stored locally in
`~/.chp/evidence.sqlite`. A denial is a first-class event with a reason code — not a swallowed
exception — and the chain is tamper-evident, so someone who did not run the agent can still tell
whether the record is intact.

**Docs:** [docs.capabilityhostprotocol.com](https://docs.capabilityhostprotocol.com) ·
**Source:** [github.com/capabilityhostprotocol/chp-core](https://github.com/capabilityhostprotocol/chp-core)

## Install

```bash
pip install chp-core                 # zero runtime dependencies
pip install 'chp-core[schema]'       # enforce capabilities' declared input_schema
pip install 'chp-core[signing]'      # ed25519 — signed hosts, bundles, mandates
```

Without `[schema]`, a capability's declared `input_schema` is **not** enforced — the host warns at
registration and `chp host verify` reports it rather than letting the gap pass silently. Without
`[signing]`, evidence stays at the hash-chain tier rather than the signed tier.

```bash
chp host verify     # smoke-tests the host and evidence store in under a second
```

From a checkout of this repository:

```bash
python -m pip install -e packages/python
```

## What this package is

Intentionally small:

- register capabilities
- discover declarations
- invoke through a governed envelope
- preserve or generate correlation IDs
- emit append-only SQLite evidence
- replay evidence by correlation ID
- optionally serve discovery, invocation, and replay over local HTTP

## Quick Example

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

Async handlers are supported. Use `await host.ainvoke(...)` when already inside
an event loop.

By default, invocation payloads are not copied into evidence. Handlers can emit
explicit redacted evidence through `ctx.emit(...)`.

Payloads emitted through `ctx.emit(...)` are redacted by default for common
sensitive keys such as `token`, `secret`, `password`, `authorization`, and
`api_key`.

## Adapters

Group related capabilities into an adapter class using `BaseAdapter` and the
`@capability` decorator. All decorated methods are auto-discovered:

```python
from chp_core import BaseAdapter, capability, LocalCapabilityHost, register_adapter

class MathAdapter(BaseAdapter):
    adapter_id = "math"
    adapter_name = "Math Capabilities"

    @capability(id="math.add", version="1.0.0", description="Add two numbers.")
    async def add(self, ctx, payload):
        return {"sum": payload["a"] + payload["b"]}

    @capability(id="math.mul", version="1.0.0", description="Multiply two numbers.")
    async def multiply(self, ctx, payload):
        return {"product": payload["a"] * payload["b"]}

host = LocalCapabilityHost()
register_adapter(host, MathAdapter())
```

For standalone functions, use `SimpleAdapter`:

```python
from chp_core import SimpleAdapter, capability, register_adapter

@capability(id="greet.hello", version="1.0.0", description="Greet someone.")
def hello(name: str):
    return {"message": f"Hello, {name}!"}

register_adapter(host, SimpleAdapter("greet", [hello]))
```

### Shipping an adapter package

Publish your adapter as a standalone package (e.g. `chp-linear`) and declare
it under the `chp.adapters` entry-point group so hosts can discover it
automatically:

```toml
# your_adapter/pyproject.toml
[project.entry-points."chp.adapters"]
linear = "chp_linear:LinearAdapter"
```

Once installed, any host can load all registered adapters:

```python
from chp_core import auto_register_adapters

host = LocalCapabilityHost()
auto_register_adapters(host)  # loads every installed chp.adapters entry point
```

Or discover them manually:

```python
from chp_core import discover_adapters

for name, adapter_cls in discover_adapters().items():
    print(name, adapter_cls)
```

`chp-core` ships a built-in `chp-git` adapter that exposes Git version-control
governance capabilities. It is registered automatically when the package is
installed.

## HTTP Endpoint

The HTTP helper is transport glue around the same `LocalCapabilityHost`:

```python
from chp_core import create_http_server

server = create_http_server(host, port=8765)
server.serve_forever()
```

Routes:

- `GET /host`
- `GET /capabilities`
- `POST /invoke`
- `POST /replay`
- `GET /replay/{correlation_id}`

See `examples/capability-host-endpoint-demo/`.

The package also installs a small CLI:

```bash
chp demo endpoint
chp serve-demo --port 8765
chp host
chp invoke demo.search_information --payload '{"query":"CHP vs MCP"}' --correlation-id corr_demo
chp replay corr_demo
```

## Development Evidence Controls

Use `chp work` to record local engineering work as CHP evidence:

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

## Tests

```bash
cd packages/python
python -m unittest discover -s tests
```
