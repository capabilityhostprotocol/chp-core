#!/usr/bin/env python3
"""onboard — turn a codebase's functions into governed CHP capabilities, portably.

Assumes NONE of our plumbing (no mesh, no models). Two modes:

  • Mode A (deterministic, zero-dependency): wrap existing, importable functions — generate an adapter
    whose @capabilitys import the source module and DELEGATE to the real code. No model. Governance +
    evidence sit at the wrapper boundary (the wrapper is conformance-clean even if internals aren't).

  • Mode B (BYO coding agent): for new integrations / non-importable code, emit a self-contained handoff
    SPEC + scaffold and hand it to whatever coding agent the user has (claude/codex/gemini/aider/cursor),
    detected on PATH. conformance.check_source is the acceptance gate, so the handoff is safe regardless
    of who wrote the code.

CLI (scriptable; the interactive wizard wraps this):
    chp-host onboard <repo> --module <import.path> --ops a,b,c --name <adapter-name>
    chp-host onboard --detect-agents
"""
from __future__ import annotations

import importlib
import inspect
import os
import shutil
import sys

_PY_TYPE = {str: "string", int: "integer", float: "number", bool: "boolean",
            list: "array", dict: "object", tuple: "array"}
_AGENTS = [  # (binary on PATH, how it takes a prompt headless)
    ("claude", 'claude -p "<SPEC>"'),
    ("codex", 'codex exec "<SPEC>"'),
    ("gemini", 'gemini -p "<SPEC>"'),
    ("aider", 'aider --message "<SPEC>"'),
    ("cursor", "open the spec in Cursor (Cmd-K / Composer)"),
]


def detect_agents() -> list[tuple[str, str]]:
    """Which coding agents the user already has (detect, don't require)."""
    return [(name, how) for name, how in _AGENTS if shutil.which(name)]


def _schema_for(fn) -> dict:
    """Infer a capability input_schema from a function signature (names + annotations + defaults)."""
    props, required = {}, []
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return {"type": "object", "additionalProperties": True}
    for name, p in sig.parameters.items():
        if name in ("self", "cls") or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        jtype = _PY_TYPE.get(p.annotation, "string") if p.annotation is not inspect._empty else "string"
        props[name] = {"type": jtype}
        if p.default is inspect._empty:
            required.append(name)
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


def _risk_of(name: str) -> str:
    n = name.lower()
    if any(v in n for v in ("delete", "remove", "drop", "write", "create", "update", "run",
                            "exec", "send", "deploy", "install", "push")):
        return "high"
    if any(n.startswith(v) for v in ("get", "list", "read", "fetch", "search", "query", "find")):
        return "low"
    return "medium"


def _cap_block(namespace: str, adapter: str, module: str, op: str, schema: dict, doc: str, risk: str, prov: str) -> str:
    desc = (doc or f"Wraps {module}.{op}() as a governed capability.").replace('"', "'")[:160]
    params = list((schema.get("properties") or {}).keys())
    return f'''
    @capability(
        id="{namespace}.{op}",
        version="1.0.0",
        description="{desc}",
        category="onboarded", provider="{adapter}", risk="{risk}", emits=_EMITS,
        input_schema={schema!r},
    )
    async def {op}(self, ctx: Any, payload: dict) -> dict:
        # Provenance: this capability wraps {prov}
        ctx.emit("{namespace}.{op}_called", {{"op": "{op}", "source": "{prov}"}}, redacted=False)
        kwargs = {{k: payload[k] for k in {params!r} if k in payload}}
        result = _delegate("{module}", "{op}", kwargs)
        if _inspect.isawaitable(result):
            result = await result
        return {{"result": _jsonable(result), "wraps": "{prov}"}}
'''


def generate_mode_a(repo: str, module: str, ops: list[str], adapter: str, out_root: str,
                    namespace: str | None = None) -> str:
    """Generate packages/chp-adapter-<adapter>/ that delegates to <module>'s functions. Returns path.

    ``namespace`` prefixes capability ids and event types. Default
    ``onboarded.<adapter>`` — NOT ``chp.adapters.*``, which is reserved for the
    protocol's own adapter registry (governance §5). Use your reverse-DNS
    domain (``com.acme.<adapter>``) when you have one."""
    namespace = namespace or f"onboarded.{adapter}"
    mod = importlib.import_module(module)
    blocks = []
    for op in ops:
        fn = getattr(mod, op, None)
        if not callable(fn):
            continue
        try:
            src_file = inspect.getsourcefile(fn) or module
            line = inspect.getsourcelines(fn)[1]
        except (OSError, TypeError):
            src_file, line = module, 0
        prov = f"{os.path.basename(repo.rstrip('/'))}:{os.path.relpath(src_file, repo) if os.path.isabs(src_file) else src_file}:{line}"
        blocks.append(_cap_block(namespace, adapter, module, op, _schema_for(fn),
                                 (inspect.getdoc(fn) or "").split("\n")[0], _risk_of(op), prov))
    pkg = os.path.join(out_root, f"chp-adapter-{adapter}")
    code_dir = os.path.join(pkg, f"chp_adapter_{adapter}")
    os.makedirs(code_dir, exist_ok=True)
    cls = "".join(w.capitalize() for w in adapter.replace("-", "_").split("_")) + "Adapter"
    adapter_py = f'''"""chp-adapter-{adapter} — governs {module} via delegating capabilities (onboarded).

Generated by `chp-host onboard` (Mode A): each capability imports {module} and delegates to the real
function. Governance + evidence sit at this boundary — the wrapper is conformance-clean even if the
wrapped internals are not. Provenance (source file:line) is recorded in each invocation's evidence.
"""
from __future__ import annotations

import importlib
import inspect as _inspect
import json as _json
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [{", ".join(f'"{namespace}.{op}_called"' for op in ops)}]


def _delegate(module: str, fn_name: str, kwargs: dict):
    return getattr(importlib.import_module(module), fn_name)(**kwargs)


def _jsonable(v):
    try:
        _json.dumps(v); return v
    except Exception:
        return str(v)


class {cls}(BaseAdapter):
    """Onboarded {module} operations as governed CHP capabilities."""

    adapter_id = "{namespace}"
    adapter_name = "{adapter}"
    adapter_description = "Onboarded capabilities wrapping {module} (generated by chp-host onboard)."
    adapter_category = "onboarded"
    adapter_tags = ["onboarded", "{adapter}"]
{"".join(blocks)}'''
    open(os.path.join(code_dir, "adapter.py"), "w").write(adapter_py)
    open(os.path.join(code_dir, "__init__.py"), "w").write(
        f'"""chp-adapter-{adapter} — onboarded {module} (generated)."""\nfrom .adapter import {cls}\n\n__all__ = ["{cls}"]\n')
    open(os.path.join(pkg, "pyproject.toml"), "w").write(f'''[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "chp-adapter-{adapter}"
version = "0.1.0"
description = "CHP adapter — onboarded {module} (governed delegating capabilities)"
readme = "README.md"
requires-python = ">=3.10"
dependencies = ["chp-core>=0.7.0"]

[project.entry-points."chp.adapters"]
{adapter} = "chp_adapter_{adapter}:{cls}"

[tool.hatch.build.targets.wheel]
packages = ["chp_adapter_{adapter}"]
''')
    open(os.path.join(pkg, "README.md"), "w").write(
        f"# chp-adapter-{adapter}\n\nOnboarded capabilities wrapping `{module}` — generated by "
        f"`chp-host onboard` (Mode A). Each capability delegates to the real function; CHP governs + "
        f"evidences at the boundary. Capabilities: {', '.join(ops)}.\n")
    return pkg


def handoff_spec(adapter: str, kind: str, ops: list[str]) -> str:
    agents = detect_agents()
    spec = (f"Implement a CHP adapter `chp-adapter-{adapter}` (kind: {kind}). Capabilities: "
            f"{', '.join(ops)}. Contract: subclass chp_core.BaseAdapter; each op is an async "
            f"@capability(id, version, description, category, provider, risk, emits, input_schema); "
            f"capability ids + custom event types are namespaced `onboarded.{adapter}.*` or your "
            f"reverse-DNS domain — NEVER `chp.adapters.*` (reserved, governance spec §5); "
            f"declared emits is a contract (§4.4) — declare every event you emit; "
            f"compose ALL external HTTP through chp.adapters.http (never import httpx/requests/urllib); "
            f"read secrets by NAME from env (never from payloads or evidence); "
            f"emit redacted-safe metadata only. ACCEPTANCE: `conformance.check_source` must score 100.")
    lines = [f"📦 Mode B — hand off to your coding agent ({len(agents)} detected):", ""]
    for name, how in (agents or [("(none)", "no coding agent on PATH — paste the spec into your editor")]):
        lines.append(f"  • {name}:  {how.replace('<SPEC>', '<spec below>')}")
    lines += ["", "SPEC:", spec]
    return "\n".join(lines)


def wizard(repo: str) -> int:
    """Guided onboarding (portable, no plumbing): scan + show the two paths forward."""
    try:
        from .scan import scan  # bundled in the chp-host wheel
    except ImportError:  # run as a loose script (dev checkout)
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from scan import scan
    rep = scan(repo)
    integ = rep["integrations"]
    new = [i for i in integ if not i["already_in_chp"]]
    print(f"\n🧭 Onboarding {repo}  ({rep['files_scanned']} .py files)\n")
    print(f"  {len(rep['functions'])} operations + {len(new)} new external integration(s) could become capabilities.\n")
    print("Two ways forward:\n")
    print("  ▸ Mode A — wrap EXISTING functions (deterministic, no model):")
    print("      chp-host onboard <repo> --module <import.path> --ops fn1,fn2 --name <adapter>")
    print("      → generates a conformant adapter that delegates to your real code.\n")
    print("  ▸ Mode B — NEW integration → hand off to your coding agent:")
    if new:
        print(f"      candidates: {', '.join('chp-adapter-' + i['adapter_kind'] for i in new)}")
    print(handoff_spec(new[0]["adapter_kind"] if new else "<kind>", "integration", ["<op1>", "<op2>"]))
    return 0


def main() -> int:
    if "--detect-agents" in sys.argv:
        print("coding agents available:", [a for a, _ in detect_agents()] or "none on PATH"); return 0
    args = sys.argv[1:]
    if not args or args[0].startswith("--"):
        print("usage: chp-host onboard <repo> [--module <m> --ops a,b --name <name> [--namespace <ns>]]"); return 2
    repo = args[0]

    def opt(flag):
        return args[args.index(flag) + 1] if flag in args else None
    module, ops, name = opt("--module"), (opt("--ops") or "").split(","), opt("--name")
    namespace = opt("--namespace")  # default onboarded.<name>; chp.adapters.* is reserved (governance §5)
    if not module:
        return wizard(repo)  # no --module → guided wizard
    if not (name and ops[0]):
        print("Mode A needs --module, --ops, --name. (Mode B: see handoff_spec.)"); return 2
    if repo not in sys.path:
        sys.path.insert(0, repo)
    pkg = generate_mode_a(repo, module, [o for o in ops if o], name,
                          os.path.join(os.path.dirname(repo) or ".", "_onboarded"),
                          namespace=namespace)
    print(f"✓ generated {pkg}\n  → run conformance.check_source on its adapter.py, then register.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
