"""CLI commands: host verify and serve-http."""

from __future__ import annotations

import argparse
import importlib
import sys


def cmd_host_verify(args: argparse.Namespace) -> int:
    import asyncio
    from pathlib import Path

    from ..decorators import capability
    from ..host import LocalCapabilityHost
    from ..store import SQLiteEvidenceStore

    store_dir: str | None = getattr(args, "store_dir", None)

    @capability(id="verify.ping", version="1.0.0", description="Verify host liveness.")
    def ping() -> dict:  # type: ignore[return-value]
        return {"pong": True}

    async def _run(store_path: str) -> bool:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("chp-verify", store=store)
        host.register(ping)
        result = await host.ainvoke(
            "verify.ping", {},
            correlation={"correlation_id": "chp-verify-001"},
        )
        if not result.success:
            print(f"FAIL: invocation failed — {result.error}", file=sys.stderr)
            return False
        events = host.replay("chp-verify-001")
        if len(events) < 2:
            print(f"FAIL: expected >=2 evidence events, got {len(events)}", file=sys.stderr)
            return False
        return True

    ok = asyncio.run(_run(":memory:"))
    if not ok:
        return 1

    if store_dir and Path(store_dir).is_dir():
        verify_path = str(Path(store_dir) / "verify.sqlite")
        try:
            ok = asyncio.run(_run(verify_path))
            if ok:
                Path(verify_path).unlink(missing_ok=True)
            else:
                return 1
        except Exception as exc:
            print(f"FAIL: store-dir check raised {exc}", file=sys.stderr)
            return 1

    print("chp host is healthy — evidence recorded and replayed")
    return 0


def cmd_serve_http(args: argparse.Namespace) -> int:
    from ..http import serve_http

    module_spec: str = args.module
    if ":" not in module_spec:
        print(f"ERROR: --module must be in the form 'pkg.module:factory_fn', got: {module_spec!r}", file=sys.stderr)
        return 1

    mod_path, attr_name = module_spec.rsplit(":", 1)
    try:
        mod = importlib.import_module(mod_path)
    except ImportError as exc:
        print(f"ERROR: cannot import {mod_path!r}: {exc}", file=sys.stderr)
        return 1

    factory = getattr(mod, attr_name, None)
    if factory is None:
        print(f"ERROR: {attr_name!r} not found in {mod_path!r}", file=sys.stderr)
        return 1
    if not callable(factory):
        print(f"ERROR: {module_spec!r} is not callable", file=sys.stderr)
        return 1

    host = factory()
    bind: str = args.bind
    port: int = args.port
    print(f"Serving CHP host {host.host_id!r} at http://{bind}:{port}")
    print("Routes: GET /health, GET /host, GET /capabilities, POST /invoke, GET /replay/{id}")
    try:
        serve_http(host, bind=bind, port=port)
    except KeyboardInterrupt:
        print("\nStopped CHP host.")
    return 0
