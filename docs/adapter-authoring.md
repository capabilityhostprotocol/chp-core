# Build A CHP Adapter

A CHP adapter wraps an external system — an API, a tool, a service — so that
every operation it performs is governed, evidence-wrapped, and replayable. Any
Python package that follows the adapter contract and registers the
`chp.adapters` entry point can be discovered and installed by `chp-host`.

This guide walks from zero to a published, conformance-passing adapter in about
fifteen minutes.

## Prerequisites

```bash
pip install chp-core>=0.7.0 chp-adapter-conformance>=0.7.0
```

## 1. Start from the template

The fastest start is the GitHub template repo:

```
https://github.com/capabilityhostprotocol/chp-adapter-template
```

Click **Use this template** → name it `chp-adapter-<yourname>` → clone it.

Or start from scratch using the structure below.

## 2. Package structure

```
chp-adapter-example/
  chp_adapter_example/
    __init__.py
    adapter.py
  tests/
    test_adapter.py
  pyproject.toml
  README.md
```

## 3. Implement the adapter

Every adapter subclasses `BaseAdapter`, declares a set of class attributes for
discovery metadata, and decorates capability methods with `@capability`.

```python
# chp_adapter_example/adapter.py
from chp_core import BaseAdapter, capability


class ExampleAdapter(BaseAdapter):
    adapter_id = "chp.adapters.example"        # stable dotted string — the discovery key
    adapter_name = "Example Adapter"
    adapter_description = "Minimal example adapter."
    adapter_category = "network"               # see categories table below
    adapter_tags = ["example", "demo"]

    @capability(
        id="chp.adapters.example.greet",
        version="1.0.0",
        description="Return a greeting.",
        category="network",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Who to greet."},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
    )
    async def greet(self, ctx, payload: dict) -> dict:
        ctx.emit("greeted", {"name": payload["name"]})
        return {"message": f"Hello, {payload['name']}!"}
```

Key rules:

- `adapter_id` must be a stable, dotted lowercase string — this is the primary
  discovery key used by `chp-host`. Do not change it after publishing.
- Decorate every capability with `@capability(id=..., version=..., description=..., input_schema=...)`.
  The `input_schema` field is required by the conformance checker — omitting it
  is an error-level violation. The schema must be a JSON Schema object type.
- Call `ctx.emit(event_type, payload)` for every significant step — this is the
  evidence record that makes operations replayable and auditable. Omit sensitive
  values (tokens, passwords) from payloads.
- Capability methods must be `async def` and return a JSON-serializable dict.

### What `ctx` provides

| Attribute / method | Description |
|--------------------|-------------|
| `ctx.emit(event, payload)` | Append an evidence event to the current invocation record |
| `ctx.correlation_id` | The correlation ID propagated from the caller |
| `ctx.invoke(capability_id, payload)` | Invoke another capability through the host (preferred over direct calls) |

### `adapter_category` values

`network` · `filesystem` · `ai` · `code` · `infra` · `agents` ·
`cloud` · `messaging` · `data` · `platform`

## 4. Register the entry point

```toml
# pyproject.toml
[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "chp-adapter-example"
version = "0.1.0"
description = "CHP adapter — example greet capability"
requires-python = ">=3.10"
license = { text = "Apache-2.0" }
dependencies = ["chp-core>=0.7.0"]

[project.entry-points."chp.adapters"]
myorg.example = "chp_adapter_example:ExampleAdapter"

[tool.hatch.build.targets.wheel]
packages = ["chp_adapter_example"]
```

The `[project.entry-points."chp.adapters"]` section is what makes `chp-host`
auto-discover your adapter. The key (`myorg.example` above) is the
**discovery name** — the string by which `chp-host` refers to your adapter
when loading it from the environment. Community adapters should namespace
the key with their org name (e.g. `myorg.example`) to avoid collisions with
official adapters, which use bare names (e.g. `http`, `filesystem`).

## 5. Expose from `__init__.py`

```python
# chp_adapter_example/__init__.py
from .adapter import ExampleAdapter
__all__ = ["ExampleAdapter"]
```

## 6. Test with conformance

The `chp-adapter-conformance` package provides two complementary checkers:

- `check_source_file(path)` — static AST analysis; catches missing `ctx.emit`,
  raw file I/O, direct HTTP imports, and silent error handlers.
- `check_registered_adapter(adapter)` — runtime introspection; catches missing
  `adapter_id`, missing `adapter_category`, missing `input_schema`, and
  capabilities without a version.

```python
# tests/test_adapter.py
from pathlib import Path

from chp_adapter_conformance import check_registered_adapter, check_source_file, score
from chp_adapter_example import ExampleAdapter


def test_static_conformance():
    path = Path(__file__).parent.parent / "chp_adapter_example" / "adapter.py"
    violations = check_source_file(path)
    errors = [v for v in violations if v.severity == "error"]
    assert errors == [], errors


def test_runtime_conformance():
    violations = check_registered_adapter(ExampleAdapter())
    errors = [v for v in violations if v.severity == "error"]
    assert errors == [], errors


def test_score():
    violations = check_registered_adapter(ExampleAdapter())
    assert score(violations) == 100
```

Run:

```bash
python -m pytest tests/ -v
```

The conformance suite surfaces violations as structured `Violation` objects with
a `rule`, `severity` (`"error"` or `"warning"`), and `message`. An error-level
violation (e.g. `missing_emit`, `raw_io`, `missing_schema`) means the adapter
breaks the CHP contract. Warning-level violations (e.g. `missing_category`) are
recommended but non-blocking. The `score()` function converts violations to a
0–100 score (100 = no violations; each error deducts 15 points, each warning 5).

## 7. Test end-to-end with a local host

```python
from chp_core import LocalCapabilityHost, register_adapter
from chp_adapter_example import ExampleAdapter

host = LocalCapabilityHost("example-host")
register_adapter(host, ExampleAdapter())

result = host.invoke("chp.adapters.example.greet", {"name": "CHP"})
print(result.data)          # {"message": "Hello, CHP!"}
print(result.evidence_ids)  # one or more evidence event IDs
```

## 8. Build and publish to PyPI

Name your package `chp-adapter-<name>` — this is the community naming
convention and makes your adapter easy to find. Any installed package that
registers a `chp.adapters` entry point is discovered automatically; there is no
allowlist required at runtime.

```bash
pip install build twine
python -m build
twine check dist/*
twine upload dist/*
```

Once published, anyone can install your adapter and have `chp-host` pick it up
automatically:

```bash
pip install chp-adapter-example
chp-host serve --adapters myorg.example
```

## 9. Submit for listing

Once your package is on PyPI, open a PR adding one entry to
`registry/adapters.json` under the `community` array:

```json
{
  "id": "chp-adapter-example",
  "pypi": "chp-adapter-example",
  "github": "https://github.com/you/chp-adapter-example",
  "category": "network",
  "description": "Return a greeting.",
  "maintainer": "your-github-username",
  "status": "experimental"
}
```

**PR checklist:**

- [ ] Package published to PyPI (`pip install chp-adapter-example` works)
- [ ] `chp.adapters` entry point registered in `pyproject.toml`
- [ ] Static and runtime conformance checks pass (no error-level violations)
- [ ] README includes install instructions and a usage example
- [ ] No proprietary data, tokens, or credentials in any committed file

Maintainers review only for spam and obvious policy violations — not for code
style or feature completeness. Your adapter remains fully under your control.

## Naming conventions

| Scope | Package name | Entry-point key |
|-------|-------------|-----------------|
| Official (maintained by Project Auxo, Inc.) | `chp-adapter-<name>` | `<name>` (e.g. `http`) |
| Community | `chp-adapter-<name>` (preferred) | `<org>.<name>` (e.g. `myorg.obsidian`) |

## See also

- `registry/adapters.json` — the adapter catalog (official + community)
- `packages/chp-adapter-http/` — a production adapter to reference
- `packages/chp-adapter-conformance/` — conformance checker source and rules
- `docs/wire-protocol.md` — HTTP wire protocol
- `spec/chp-v0.1.md` — protocol specification
