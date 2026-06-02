# chp-core

Reference local host for CHP v0.1.

This package is intentionally small:

- register capabilities
- discover declarations
- invoke through a governed envelope
- preserve or generate correlation IDs
- emit append-only SQLite evidence
- replay evidence by correlation ID
- optionally serve discovery, invocation, and replay over local HTTP

## Install

```bash
pip install chp-core
```

From this repository:

```bash
python -m pip install -e packages/python
```

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
chp work validate-demo endpoint --correlation-id chp-demo-validation
chp work check-alignment --correlation-id chp-alignment
chp work check-messaging --correlation-id chp-messaging
```

## Tests

```bash
cd packages/python
python -m unittest discover -s tests
```
