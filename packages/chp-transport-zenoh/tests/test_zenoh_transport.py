"""Zenoh transport binding — a CHP invocation round-trips over Zenoh query/reply
with envelope/result BYTE-IDENTICAL to the in-process/HTTP path, and evidence is
delivered via native pub/sub (which HTTP request/response cannot do)."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("zenoh")

from chp_core import (CapabilityDescriptor, LocalCapabilityHost,  # noqa: E402
                      SQLiteEvidenceStore)
from chp_core.transport import Transport  # noqa: E402
from chp_core.types import InvocationEnvelope  # noqa: E402
from chp_transport_zenoh import ZenohHostServer, ZenohTransport  # noqa: E402


def _host(host_id: str = "zt-host") -> LocalCapabilityHost:
    h = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))

    async def add(_c, p):
        return {"sum": p["a"] + p["b"]}

    h.register(CapabilityDescriptor(id="math.add", version="1.0.0", description="."), add)
    return h


def test_zenoh_transport_satisfies_protocol():
    t = ZenohTransport.__new__(ZenohTransport)  # structural check, no session
    assert isinstance(ZenohTransport, type) and issubclass(ZenohTransport, object)
    for m in ("ainvoke_envelope", "discover", "replay_result", "health", "supports"):
        assert hasattr(ZenohTransport, m), m
    del t


def test_invoke_roundtrip_byte_identical(tmp_path):
    host = _host("zt-a")
    server = ZenohHostServer(host)
    transport = ZenohTransport("zt-a")
    time.sleep(0.4)  # let the two peer sessions discover each other
    try:
        assert isinstance(transport, Transport)  # runtime_checkable Protocol
        env = InvocationEnvelope.from_mapping(
            {"capability_id": "math.add", "payload": {"a": 4, "b": 5},
             "correlation": {"correlation_id": "zt-corr"}})
        result = asyncio.run(transport.ainvoke_envelope(env))
        assert result.success and result.data == {"sum": 9}

        # BYTE-IDENTICAL wire object: the same envelope invoked in-process on the
        # host produces a result whose wire dict matches (modulo ids/timestamps).
        local = asyncio.run(host.ainvoke_envelope(InvocationEnvelope.from_mapping(
            {"capability_id": "math.add", "payload": {"a": 4, "b": 5},
             "correlation": {"correlation_id": "local-corr"}})))
        rz, rl = result.to_dict(), local.to_dict()
        for k in ("capability_id", "capability_version", "outcome", "success", "data"):
            assert rz[k] == rl[k], (k, rz[k], rl[k])
    finally:
        transport.close(); server.close()


def test_discover_and_health_over_zenoh():
    host = _host("zt-b")
    server = ZenohHostServer(host)
    transport = ZenohTransport("zt-b")
    time.sleep(0.4)
    try:
        desc = asyncio.run(transport.discover())
        assert desc["id"] == "zt-b"
        assert any(c["id"] == "math.add" for c in desc["capabilities"])
        health = asyncio.run(transport.health())
        assert health["status"] == "ok" and health["capability_count"] >= 1
        assert transport.supports("evidence") and transport.supports("streaming")
    finally:
        transport.close(); server.close()


def test_evidence_pubsub_delivers_completed_event():
    host = _host("zt-c")
    server = ZenohHostServer(host)
    transport = ZenohTransport("zt-c")
    received: list = []
    sub = transport.subscribe_evidence(received.append)
    time.sleep(0.4)
    try:
        asyncio.run(transport.ainvoke_envelope(InvocationEnvelope.from_mapping(
            {"capability_id": "math.add", "payload": {"a": 1, "b": 2},
             "correlation": {"correlation_id": "ev-corr"}})))
        # the host published the completed evidence to the stream — wait for it
        for _ in range(20):
            if received:
                break
            time.sleep(0.1)
        assert received, "no evidence delivered over the pub/sub stream"
        assert any(e.get("event_type") == "execution_completed" for e in received)
    finally:
        sub.undeclare(); transport.close(); server.close()


def test_export_bundle_signed_and_verifiable(tmp_path):
    """The denial-evidence path: export_bundle over zenoh yields a SIGNED bundle that verify_bundle
    accepts against the host's pinned key and REJECTS against a wrong key (forged-denial defense)."""
    from chp_core import signing

    host = _host("zt-exp")
    kd = signing.resolve_key_dir("zt-exp")
    key = signing.load_host_key(kd) or signing.generate_keypair(kd)
    server = ZenohHostServer(host)
    transport = ZenohTransport("zt-exp")
    time.sleep(0.4)
    try:
        asyncio.run(transport.ainvoke_envelope(InvocationEnvelope.from_mapping(
            {"capability_id": "math.add", "payload": {"a": 1, "b": 2},
             "correlation": {"correlation_id": "exp-corr"}})))
        bundle = asyncio.run(transport.export_bundle("exp-corr"))
        assert bundle.get("events"), "no events in the exported bundle"
        assert signing.verify_bundle(bundle, expected_key_id=key.key_id).valid       # right key ✓
        assert not signing.verify_bundle(bundle, expected_key_id="deadbeef").valid   # wrong key ✗
    finally:
        transport.close()
        server.close()


def test_decision_stream_pubsub_delivers():
    """The async HITL carrier: a host publishes a decision, a subscriber receives it — no blocking
    query (the sync await_decision's timeout class of bug is gone by construction)."""
    host = _host("zt-dec")
    server = ZenohHostServer(host)
    transport = ZenohTransport("zt-dec")
    received: list = []
    sub = transport.subscribe_decisions(received.append)
    time.sleep(0.4)
    try:
        server.publish_decision({"approval_id": "a1", "decision": "approve", "by": "@pm:chp.local"})
        for _ in range(20):
            if received:
                break
            time.sleep(0.1)
        assert received and received[0]["decision"] == "approve" and received[0]["approval_id"] == "a1"
    finally:
        sub.undeclare(); transport.close(); server.close()


def test_liveliness_presence_up_and_down():
    """Push-based presence: a host declares a liveliness token → a watcher sees it UP and can query the
    live set; when the host closes (token drops) the watcher sees it DOWN — no heartbeat/TTL polling."""
    host = _host("zt-live")
    server = ZenohHostServer(host, declare_presence=True)
    transport = ZenohTransport("zt-live")
    changes: list = []
    sub = transport.watch_presence(lambda key, alive: changes.append((key, alive)))
    time.sleep(0.5)
    try:
        for _ in range(20):                       # UP: token appeared (history replays it)
            if any(alive for _, alive in changes):
                break
            time.sleep(0.1)
        assert any(alive for _, alive in changes), "presence UP not observed"
        assert any("zt-live" in k for k in transport.live_hosts()), "live_hosts missing the host"

        server.close()                            # drop the token → DOWN
        for _ in range(20):
            if any(not alive for _, alive in changes):
                break
            time.sleep(0.1)
        assert any(not alive for _, alive in changes), "presence DOWN not observed after close"
    finally:
        sub.undeclare(); transport.close()


def test_long_invoke_does_not_starve_health():
    """The hardening: a long-running invocation must NOT block health/discover. Invokes are drained off
    the Zenoh callback thread (FifoChannel + worker), so while a slow invoke runs the node stays live."""
    import threading

    host = LocalCapabilityHost("zt-slow", store=SQLiteEvidenceStore(":memory:"))
    started = threading.Event()

    async def slow(_c, _p):
        started.set()
        await asyncio.sleep(2.0)   # stand-in for a long sovereign-model generation
        return {"ok": True}

    host.register(CapabilityDescriptor(id="slow.op", version="1.0.0", description="."), slow)
    server = ZenohHostServer(host)
    # Two independent clients (separate sessions), as in production: one runs the slow invoke, the
    # other checks health while it is in-flight.
    caller = ZenohTransport("zt-slow")
    watcher = ZenohTransport("zt-slow")
    time.sleep(0.4)
    done: list = []

    def _run_slow():
        env = InvocationEnvelope.from_mapping(
            {"capability_id": "slow.op", "payload": {}, "correlation": {"correlation_id": "slow-corr"}})
        done.append(asyncio.run(caller.ainvoke_envelope(env)))

    try:
        worker = threading.Thread(target=_run_slow, daemon=True)
        worker.start()
        assert started.wait(3.0), "slow invoke never started on the node"
        # WHILE the 2s invoke runs, health must return promptly — not queue behind it.
        t0 = time.monotonic()
        health = asyncio.run(watcher.health())
        dt = time.monotonic() - t0
        assert health["status"] == "ok"
        assert dt < 1.5, f"health starved {dt:.2f}s behind the in-flight invoke (loop not hardened)"
        worker.join(5.0)
        assert done and done[0].success and done[0].data == {"ok": True}  # the slow invoke still completed
    finally:
        caller.close(); watcher.close(); server.close()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider"]))
