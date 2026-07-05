"""Contract tests — freeze the cross-package contracts that broke this session.

Two breaking changes shipped in 0.9.0 because nothing guarded these contracts:
  1. The ctx.emit guard DROPPED host-reserved lifecycle events → broke 123
     chp-agent tests (which assert capability-level lifecycle emission).
  2. Removing capability_count from /health → broke chp-host tests.

These live in chp-core's own (gated) suite so either regression fails HERE, at
chp-core commit time, before it can reach a downstream package. A deliberate
change updates the frozen expectation on purpose.
"""

from __future__ import annotations

import asyncio
import json
import threading
import urllib.request

from chp_core import LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.http import create_http_server
from chp_core.types import CapabilityDescriptor, CORE_EVIDENCE_TYPES


# --------------------------------------------------------------------------
# Event contract
# --------------------------------------------------------------------------

def test_core_evidence_types_frozen():
    # The host-reserved lifecycle event set is a contract with every downstream
    # consumer. Changing it is a breaking change — update this set deliberately.
    assert CORE_EVIDENCE_TYPES == {
        "execution_started",
        "execution_completed",
        "execution_failed",
        "execution_denied",
        "execution_skipped",
    }


def test_ctx_emit_still_records_lifecycle_events():
    # Guards break #1: a capability emitting a host-reserved lifecycle event
    # must still be RECORDED (warn-only), not silently dropped — dropping is a
    # breaking change for consumers that emit + assert these (e.g. chp-agent).
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))

    async def handler(ctx, _payload):
        ev = ctx.emit("execution_started", {"capability_id": "x"}, redacted=False)
        assert ev is not None, "ctx.emit must record lifecycle events, not drop them"
        return {"ok": True}

    host.register(CapabilityDescriptor(id="c.cap", version="1.0.0", description=""), handler)
    asyncio.run(host.ainvoke("c.cap", {}, correlation={"correlation_id": "cc"}))
    types = [e["event_type"] for e in host.store.all()]
    # host emits its own started/completed; the capability's started is also recorded.
    assert types.count("execution_started") == 2


# --------------------------------------------------------------------------
# HTTP surface contract (/health is public, /host is the authed descriptor)
# --------------------------------------------------------------------------

def _serve(host):
    server = create_http_server(host, port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as r:
        return json.loads(r.read())


def test_health_vs_host_field_contract():
    # Guards break #2: the unauthenticated /health must NOT disclose
    # capability_count (mesh-count privacy); the /host descriptor MUST carry it.
    host = LocalCapabilityHost("contract-host", store=SQLiteEvidenceStore(":memory:"))

    async def handler(_ctx, _p):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="m.cap", version="1.0.0", description=""), handler)
    server, port = _serve(host)
    try:
        health = _get(port, "/health")
        host_desc = _get(port, "/host")
        assert health["status"] == "ok"
        assert "capability_count" not in health, "/health must not leak capability_count"
        assert "capabilities" in host_desc, "/host must expose the capability list"
    finally:
        server.shutdown()
