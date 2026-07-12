"""Log monitor / fork detection (chp-v0.2.md §12, proposal 0023): a monitor
reconstructs a host's head as-of each anchored sequence from the live store and
checks it still equals the immutable external anchor. A rewrite is caught."""

from __future__ import annotations

import asyncio
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (CapabilityDescriptor, LocalCapabilityHost,
                      SQLiteEvidenceStore, signing, witnessing)
from chp_core.types import CorrelationContext, InvocationEnvelope

TS = "2026-07-12T00:00:00Z"


def _key(offset: int = 0) -> signing.HostKey:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(offset, offset + 32)))
    pub = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                           public_key_b64=pub, _private=priv)


def _growing_host(host_id: str = "monitored"):
    """A host whose log grows across sequences; returns (host, anchors) where each
    anchor captures the store head after one more correlation was recorded."""
    host = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))

    async def handler(_ctx, payload):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="m.cap", version="1.0.0", description="."), handler)
    anchors = []
    for i, corr in enumerate(["c-a", "c-b", "c-c", "c-d"]):
        asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="m.cap", payload={"i": i},
            correlation=CorrelationContext(correlation_id=corr))))
        head = host.store.get_store_head()
        anchors.append({
            "kind": "store-head-anchor", "host_id": host_id,
            "sequence": head["sequence"], "store_head": head["store_head"],
            "store_head_scheme": head["scheme"],
        })
    return host, anchors


def _monitor(host, anchors, host_id="monitored"):
    return witnessing.monitor_anchor_history(
        host.store, anchors, host_id=host_id, monitor_key=_key(40),
        monitor_id="mon", monitored_at=TS)


def test_faithful_log_is_consistent():
    host, anchors = _growing_host()
    report = _monitor(host, anchors)
    assert report["verdict"] == "consistent"
    assert report["verified_through_sequence"] == anchors[-1]["sequence"]
    assert report["anchor_count"] == len(anchors)
    assert "divergence" not in report  # omit-when-consistent
    assert signing.verify_store_head_monitor_report(report).valid


def test_rewritten_old_event_is_forked():
    host, anchors = _growing_host()
    # The operator rewrites history: edit an OLD event's content_hash in the raw
    # store (simulating an altered/dropped event). The head as-of that sequence now
    # reconstructs to a root ≠ the immutable anchor.
    with host.store._lock:
        host.store._conn.execute(
            "UPDATE evidence_events SET content_hash = ? WHERE sequence = ?",
            ("f" * 64, anchors[0]["sequence"]))
        host.store._conn.commit()
    report = _monitor(host, anchors)
    assert report["verdict"] == "forked"
    # diverges at the FIRST anchor whose reconstruction is affected
    assert report["divergence"]["sequence"] == anchors[0]["sequence"]
    assert report["divergence"]["anchored_root"] == anchors[0]["store_head"]
    assert report["divergence"]["reconstructed_root"] != anchors[0]["store_head"]
    assert report["verified_through_sequence"] == 0  # nothing confirmed before the fork
    v = signing.verify_store_head_monitor_report(report)
    assert v.valid and v.checks.get("divergence_present") is True


def test_report_signature_binds_and_pins():
    host, anchors = _growing_host()
    report = _monitor(host, anchors)
    mk = _key(40)
    assert signing.verify_store_head_monitor_report(
        report, expected_monitor_key=mk.key_id, expected_host_id="monitored").valid
    # flipping the verdict without re-signing breaks the header signature
    tampered = dict(report)
    tampered["verdict"] = "forked"
    assert not signing.verify_store_head_monitor_report(tampered).valid
    # wrong monitored host / wrong monitor key pin fail
    assert not signing.verify_store_head_monitor_report(report, expected_host_id="other").valid
    assert not signing.verify_store_head_monitor_report(
        report, expected_monitor_key="wrong-key").valid
