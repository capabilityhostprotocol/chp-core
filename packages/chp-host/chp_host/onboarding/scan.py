#!/usr/bin/env python3
"""capability-scanner — surface candidate CHP capabilities from any codebase.

Onboarding infra: point this at a repo and it surfaces what that codebase could contribute to the
CHP protocol — (a) external integrations (imported SDKs) that could become **adapters**, and
(b) public functions/operations that could become governed **capabilities** — each with an inferred
category + risk hint, cross-referenced against the adapters CHP already ships (so you see what's
NEW vs already covered).

Pure stdlib (ast + os). Surfaces, never modifies. Usage:
    chp-host onboard <path-to-codebase>   (or: python -m chp_host.onboarding.scan <path> [--json])
"""
from __future__ import annotations

import ast
import json
import os
import sys

# Imported library (top-level module) → the kind of CHP adapter it implies.
_INTEGRATIONS = {
    "stripe": "payments", "boto3": "aws", "botocore": "aws", "google": "gcp",
    "azure": "azure", "kubernetes": "kubernetes", "docker": "docker", "openai": "openai",
    "anthropic": "anthropic", "cohere": "cohere", "slack_sdk": "slack", "slack": "slack",
    "jira": "jira", "atlassian": "jira", "notion_client": "notion", "linear": "linear",
    "github": "github", "gitlab": "gitlab", "psycopg2": "postgres", "psycopg": "postgres",
    "sqlalchemy": "sql", "redis": "redis", "pymongo": "mongo", "kafka": "kafka",
    "confluent_kafka": "kafka", "pika": "rabbitmq", "twilio": "twilio", "sendgrid": "email",
    "smtplib": "email", "elasticsearch": "elasticsearch", "snowflake": "snowflake",
    "transformers": "huggingface", "torch": "ml", "tensorflow": "ml", "sklearn": "ml",
    "pandas": "data", "numpy": "data", "playwright": "browser", "selenium": "browser",
    "paramiko": "ssh", "fabric": "ssh", "ldap3": "ldap", "stripe_agent": "payments",
}
# High-risk verbs in a function/method name → mutation/side effect.
_RISK = {"high": ("delete", "remove", "drop", "destroy", "exec", "run", "kill", "deploy",
                  "install", "push", "write", "create", "update", "send", "purge", "rotate"),
         "low": ("get", "list", "read", "fetch", "search", "query", "find", "show", "describe",
                 "status", "info", "count", "scan", "view")}
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
              ".next", ".pytest_cache", ".mypy_cache", "site-packages"}


def _existing_adapters(repo: str) -> set[str]:
    pkgs = os.path.join(repo, "packages")
    if not os.path.isdir(pkgs):
        return set()
    return {d[len("chp-adapter-"):] for d in os.listdir(pkgs) if d.startswith("chp-adapter-")}


def _risk_of(name: str) -> str:
    n = name.lower()
    if any(v in n for v in _RISK["high"]):
        return "high"
    if any(n.startswith(v) or v in n for v in _RISK["low"]):
        return "low"
    return "medium"


def scan(path: str) -> dict:
    repo_adapters = _existing_adapters(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    integrations: dict[str, dict] = {}   # adapter-kind → {modules, files}
    functions: list[dict] = []
    files_scanned = 0

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if not fn.endswith(".py") or fn.startswith("test_") or fn.endswith("_test.py"):
                continue
            fp = os.path.join(root, fn)
            try:
                tree = ast.parse(open(fp, encoding="utf-8").read())
            except Exception:
                continue
            files_scanned += 1
            rel = os.path.relpath(fp, path)
            for node in ast.walk(tree):
                # imports → external integrations
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mod = (node.names[0].name if isinstance(node, ast.Import)
                           else (node.module or "")).split(".")[0]
                    kind = _INTEGRATIONS.get(mod)
                    if kind:
                        e = integrations.setdefault(kind, {"modules": set(), "files": set()})
                        e["modules"].add(mod); e["files"].add(rel)
                # public functions → candidate capabilities (skip dunder/private + nested helpers)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                    doc = (ast.get_docstring(node) or "").strip().split("\n")[0][:100]
                    functions.append({
                        "name": node.name, "file": rel, "line": node.lineno,
                        "args": [a.arg for a in node.args.args if a.arg not in ("self", "cls")],
                        "risk": _risk_of(node.name), "doc": doc,
                    })

    # rank function candidates: side-effecting (high/medium risk) + documented first
    functions.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f["risk"]], not f["doc"]))
    integ_out = []
    for kind, e in sorted(integrations.items()):
        integ_out.append({"adapter_kind": kind, "modules": sorted(e["modules"]),
                          "files": len(e["files"]), "already_in_chp": kind in repo_adapters})
    return {"path": path, "files_scanned": files_scanned,
            "integrations": integ_out, "functions": functions}


def _print(rep: dict) -> None:
    print(f"\n📡 Capability scan of {rep['path']}  ({rep['files_scanned']} .py files)\n")
    integ = rep["integrations"]
    new = [i for i in integ if not i["already_in_chp"]]
    print(f"── External integrations → candidate ADAPTERS ({len(new)} new of {len(integ)}) ──")
    for i in integ:
        flag = "✅ already in CHP" if i["already_in_chp"] else "🆕 candidate adapter"
        print(f"  {flag:22s} chp-adapter-{i['adapter_kind']:12s} ({', '.join(i['modules'])}; {i['files']} files)")
    fns = rep["functions"]
    hi = [f for f in fns if f["risk"] in ("high", "medium")]
    print(f"\n── Public operations → candidate CAPABILITIES ({len(fns)} total, {len(hi)} side-effecting) ──")
    for f in fns[:25]:
        sig = f"{f['name']}({', '.join(f['args'][:4])})"
        print(f"  [{f['risk']:6s}] {sig:42s} {f['file']}:{f['line']}  {f['doc']}")
    if len(fns) > 25:
        print(f"  … +{len(fns) - 25} more")
    print(f"\n→ Onboard: wrap each NEW integration as a chp-adapter-* and the side-effecting "
          f"operations as governed capabilities (risk-tag them; route mutating ones through safety.assess).\n")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("usage: chp-host onboard <path-to-codebase>   (or: python -m chp_host.onboarding.scan <path> [--json])"); return 2
    rep = scan(args[0])
    if "--json" in sys.argv:
        print(json.dumps(rep, indent=2))
    else:
        _print(rep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
