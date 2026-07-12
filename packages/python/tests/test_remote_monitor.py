"""Remote log monitor (chp-v0.2.md §12, proposal 0024): a monitor holding ONLY a
host's immutable anchors verifies append-only by asking the host to serve
consistency proofs — no store copy. A rewrite is caught because the served proof's
root no longer matches the immutable anchor."""

from __future__ import annotations

import asyncio
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import (CapabilityDescriptor, LocalCapabilityHost,
                      SQLiteEvidenceStore, signing, witnessing)
from chp_core.merkle import CHP_STORE_HEAD_V2, store_head_consistency_proof
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
    host = LocalCapabilityHost(host_id, store=SQLiteEvidenceStore(":memory:"))

    async def handler(_ctx, payload):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="m.cap", version="1.0.0", description="."), handler)
    anchors = []
    for i, corr in enumerate(["c-a", "c-b", "c-c", "c-d"]):
        asyncio.run(host.ainvoke_envelope(InvocationEnvelope(
            capability_id="m.cap", payload={"i": i},
            correlation=CorrelationContext(correlation_id=corr))))
        # Remote monitoring requires v2 (Merkle) anchors — consistency proofs are
        # a chp-store-head-v2 feature.
        head = host.store.get_store_head(scheme=CHP_STORE_HEAD_V2)
        anchors.append({"kind": "store-head-anchor", "host_id": host_id,
                        "sequence": head["sequence"], "store_head": head["store_head"],
                        "store_head_scheme": head["scheme"]})
    return host, anchors


def _served_fetch(store):
    """Emulate GET /head/consistency: reconstruct both heads from the store and
    return a consistency proof. The remote monitor only ever calls THIS — it never
    touches the store itself."""
    def fetch(first: int, second: int):
        old = store.get_store_head(at_sequence=first, fresh=True, scheme=CHP_STORE_HEAD_V2)
        new = store.get_store_head(at_sequence=second, fresh=True, scheme=CHP_STORE_HEAD_V2)
        return store_head_consistency_proof(old["leaves"], new["leaves"])
    return fetch


def _remote(anchors, fetch, host_id="monitored"):
    return witnessing.monitor_anchor_history_remote(
        anchors, fetch, host_id=host_id, monitor_key=_key(60),
        monitor_id="remote-mon", monitored_at=TS)


def test_faithful_log_is_consistent_remotely():
    host, anchors = _growing_host()
    report = _remote(anchors, _served_fetch(host.store))
    assert report["verdict"] == "consistent"
    assert report["verified_through_sequence"] == anchors[-1]["sequence"]
    assert "divergence" not in report
    assert signing.verify_store_head_monitor_report(report).valid


def test_rewrite_detected_with_no_store_copy():
    host, anchors = _growing_host()
    # Operator rewrites an old event; a proof the host now serves for the pair that
    # spans the rewrite carries a root ≠ the immutable anchor.
    victim = anchors[1]["sequence"]
    with host.store._lock:
        host.store._conn.execute(
            "UPDATE evidence_events SET content_hash = ? WHERE sequence = ?",
            ("d" * 64, victim))
        host.store._conn.commit()
    report = _remote(anchors, _served_fetch(host.store))
    assert report["verdict"] == "forked"
    assert report["divergence"]["sequence"] == victim
    assert report["divergence"]["anchored_root"] == anchors[1]["store_head"]
    assert report["divergence"]["reconstructed_root"] != anchors[1]["store_head"]
    assert report["verified_through_sequence"] == anchors[0]["sequence"]  # first pair failed
    assert signing.verify_store_head_monitor_report(report).valid


def test_unreachable_host_is_unprovable_forked():
    host, anchors = _growing_host()
    # A host that will not serve a proof (returns None) is unprovable — reported
    # forked (not consistent): the monitor cannot attest append-only it never saw.
    report = _remote(anchors, lambda a, b: None)
    assert report["verdict"] == "forked"
    assert signing.verify_store_head_monitor_report(report).valid


def test_v1_anchors_are_refused_not_falsely_forked():
    import pytest

    host, anchors = _growing_host()
    # A v1 (flat-fold) anchor has no consistency proof; remote monitoring must
    # REFUSE rather than emit a false 'forked' against an uncheckable host.
    v1_anchors = [dict(a, store_head_scheme="chp-store-head-v1") for a in anchors]
    with pytest.raises(ValueError, match="chp-store-head-v2"):
        _remote(v1_anchors, _served_fetch(host.store))
