# AGENTS.md — Capability Host Protocol

CHP is a protocol and Python SDK for making agent, tool, and system execution **observable, replayable, and governable**. Every function wrapped as a `@capability` gets automatic evidence emission, correlation propagation, replay by session ID, and optional policy enforcement — with zero mandatory infrastructure. The reference host is `LocalCapabilityHost` in `packages/python/chp_core/`.

## Three invariants you must never violate

1. **Evidence is append-only.** Never modify or delete rows in an evidence SQLite store. The SHA256 hash chain breaks if any row changes. `store.py` is insert-only by design.
2. **Preserve caller correlation IDs.** If an `InvocationEnvelope` arrives with a `correlation_id`, the host must forward it verbatim into every evidence event and the result. Never generate a new ID over a supplied one.
3. **Spec, schemas, and types must stay in sync.** Any change to `spec/chp-v0.1.md`, `schemas/*.json`, or `packages/python/chp_core/types.py` must be validated with `chp work check-alignment --repo-root .` (runs 41 cross-artifact checks). CI will catch drift, but run it locally first.

## Key commands

```bash
# Fast test suite (~6s)
cd packages/python && python -m pytest tests/ -m "not slow" -q --no-cov

# Full test suite
cd packages/python && python -m pytest tests/ -q --no-cov

# Protocol conformance (9 checks)
python conformance/runner.py

# Spec/schema/type alignment (41 checks)
PYTHONPATH=packages/python chp work check-alignment --repo-root .

# Wire evidence capture for every Claude Code session
PYTHONPATH=packages/python chp hooks install
```

## Navigation

| Where to look | What you'll find |
|---|---|
| `spec/chp-v0.1.md` | Normative protocol — start here for definitions and MUST/SHOULD requirements |
| `schemas/` | JSON Schema for every protocol object (29 files) |
| `packages/python/chp_core/host.py` | `LocalCapabilityHost` — registration, invocation, evidence emission |
| `packages/python/chp_core/store.py` | `SQLiteEvidenceStore` — append-only, SHA256-chained |
| `packages/python/chp_core/types.py` | Python dataclasses for all protocol objects |
| `conformance/runner.py` | 9 conformance checks against a live host |
| `docs/adopter-quickstart.md` | 10-minute path to first evidence event |
| `examples/` | 14 runnable demos |

## Common pitfalls

- **Three docs are legacy** (`docs/onboarding.md`, `docs/agent-prompt.md`, `docs/capability-lookup-prompt.md`) — they describe pre-v0.1 Zenoh-mesh patterns. Do not update or reference them. They redirect to the current docs.
- **`chp-dev` is the private monorepo.** `chp-core` (this repo) is the public mirror, synced via `scripts/sync-to-public.sh`. If you're in `chp-core`, do not manually sync — the pipeline handles it.
- **`jsonschema` is a transitive dep.** Input schema validation in `host.py` uses a lazy import — do not add it to the top-level imports or it becomes a hard dependency for all users.
- **`host.invoke()` cannot run inside an async loop** — use `await host.ainvoke()` instead. The sync wrapper raises `RuntimeError` if an event loop is running.
