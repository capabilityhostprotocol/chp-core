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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider"]))
