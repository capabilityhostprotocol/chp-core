"""Non-omission / completeness proofs (chp-v0.2.md §12, proposal 0018):
chp-completeness-v1 — a bundle self-declares completeness, audited against a
witnessed store head."""

from __future__ import annotations

import asyncio

import pytest

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core import signing
from chp_core.witnessing import audit_completeness

pytestmark = pytest.mark.skipif(
    not signing.signing_available(), reason="signing backend not installed"
)

CORR = "corr-complete"


def _host_with_events(n_extra_payloads=("a", "b")):
    """A host + store holding one correlation with len(n_extra_payloads) events."""
    host = LocalCapabilityHost("comp-host", store=SQLiteEvidenceStore(":memory:"))

    async def echo(_c, p):
        return {"echo": p}

    host.register(CapabilityDescriptor(id="c.echo", version="1.0.0", description=""), echo)
    for pv in n_extra_payloads:
        asyncio.run(host.ainvoke("c.echo", {"v": pv}, correlation={"correlation_id": CORR}))
    return host


def _witness_receipt(store, witness_key, *, at_sequence=None):
    """A received-witness receipt over the store's head: {statement, leaves}."""
    head = store.get_store_head(at_sequence, fresh=True)
    stmt = signing.build_chain_witness(
        "comp-host", head["sequence"], head["store_head"], witness_key,
        witness_id="witness-1", witnessed_at="2026-07-12T00:00:00Z")
    return {"statement": stmt, "leaves": head["leaves"]}


# ── the claim + self-check ───────────────────────────────────────────────────

def test_build_completeness_shape():
    host = _host_with_events()
    events = host.store.export_correlation(CORR)
    seq = host.store.get_store_head()["sequence"]
    c = signing.build_completeness(CORR, events, seq)
    assert c == {
        "scheme": "chp-completeness-v1",
        "correlation_id": CORR,
        "as_of_sequence": seq,
        "head_hash": events[-1]["content_hash"],
    }


def test_completeness_bundle_verifies(tmp_path):
    host = _host_with_events()
    events = host.store.export_correlation(CORR)
    seq = host.store.get_store_head()["sequence"]
    key = signing.generate_keypair(tmp_path)
    c = signing.build_completeness(CORR, events, seq)
    bundle = signing.sign_bundle(signing.build_bundle(
        "comp-host", events, created_at="2026-07-12T00:00:00Z", completeness=c), key)
    v = signing.verify_bundle(bundle)
    assert v.valid, v.reason
    assert v.checks["completeness"] and v.checks["signature"]


def test_bundle_without_completeness_is_byte_identical(tmp_path):
    """Omit-when-absent: a bundle without a completeness block signs+verifies
    exactly as before (the header has no completeness key)."""
    host = _host_with_events()
    events = host.store.export_correlation(CORR)
    key = signing.generate_keypair(tmp_path)
    plain = signing.build_bundle("comp-host", events, created_at="2026-07-12T00:00:00Z")
    assert "completeness" not in signing.bundle_header(plain)
    assert signing.verify_bundle(signing.sign_bundle(plain, key)).valid


def test_lying_head_hash_fails_selfcheck(tmp_path):
    host = _host_with_events()
    events = host.store.export_correlation(CORR)
    seq = host.store.get_store_head()["sequence"]
    key = signing.generate_keypair(tmp_path)
    c = signing.build_completeness(CORR, events, seq)
    c["head_hash"] = "0" * 64  # claim a tail that isn't the bundle's tail
    bundle = signing.sign_bundle(signing.build_bundle(
        "comp-host", events, created_at="2026-07-12T00:00:00Z", completeness=c), key)
    v = signing.verify_bundle(bundle)
    assert v.checks["completeness"] is False and not v.valid


def test_completeness_claim_is_signed(tmp_path):
    """Tampering the claim after signing breaks the signature (it's in the header)."""
    host = _host_with_events()
    events = host.store.export_correlation(CORR)
    seq = host.store.get_store_head()["sequence"]
    key = signing.generate_keypair(tmp_path)
    bundle = signing.sign_bundle(signing.build_bundle(
        "comp-host", events, created_at="2026-07-12T00:00:00Z",
        completeness=signing.build_completeness(CORR, events, seq)), key)
    bundle["completeness"]["as_of_sequence"] = 99999  # tamper
    assert signing.verify_bundle(bundle).checks["signature"] is False


# ── the audit (the teeth) ────────────────────────────────────────────────────

def test_audit_complete_against_matching_head(tmp_path):
    host = _host_with_events()
    events = host.store.export_correlation(CORR)
    seq = host.store.get_store_head()["sequence"]
    wkey = signing.generate_keypair(tmp_path / "witness")
    receipt = _witness_receipt(host.store, wkey)
    c = signing.build_completeness(CORR, events, seq)
    bundle = signing.build_bundle("comp-host", events, created_at="t", completeness=c)
    audit = audit_completeness(bundle, [receipt])
    assert audit["verdict"] == "complete", audit


def test_audit_incomplete_when_head_advanced(tmp_path):
    """The teeth: a host truncates the tail but a FRESHER witnessed head proves
    the correlation advanced past the claimed tail."""
    host = _host_with_events(("a", "b"))
    full = host.store.export_correlation(CORR)
    # Witness the head AFTER both events (leaves[CORR] = b's content_hash).
    wkey = signing.generate_keypair(tmp_path / "witness")
    receipt = _witness_receipt(host.store, wkey)
    # The host exports a TRUNCATED bundle [a] claiming complete as of a's sequence.
    truncated = full[:1]
    c = signing.build_completeness(CORR, truncated, truncated[-1]["sequence"])
    bundle = signing.build_bundle("comp-host", truncated, created_at="t", completeness=c)
    audit = audit_completeness(bundle, [receipt])
    assert audit["verdict"] == "incomplete", audit
    assert audit["advanced_at"] == receipt["statement"]["sequence"]


def test_audit_unwitnessed_when_no_head(tmp_path):
    host = _host_with_events()
    events = host.store.export_correlation(CORR)
    seq = host.store.get_store_head()["sequence"]
    c = signing.build_completeness(CORR, events, seq)
    bundle = signing.build_bundle("comp-host", events, created_at="t", completeness=c)
    assert audit_completeness(bundle, [])["verdict"] == "unwitnessed"


def test_audit_snapshot_invalid_when_leaves_tampered(tmp_path):
    host = _host_with_events()
    events = host.store.export_correlation(CORR)
    seq = host.store.get_store_head()["sequence"]
    wkey = signing.generate_keypair(tmp_path / "witness")
    receipt = _witness_receipt(host.store, wkey)
    receipt["leaves"][CORR] = "f" * 64  # tamper the snapshot (no longer matches signed store_head)
    c = signing.build_completeness(CORR, events, seq)
    bundle = signing.build_bundle("comp-host", events, created_at="t", completeness=c)
    assert audit_completeness(bundle, [receipt])["verdict"] == "snapshot_invalid"


def test_audit_no_claim():
    bundle = signing.build_bundle("comp-host", [], created_at="t")
    assert audit_completeness(bundle, [])["verdict"] == "no_claim"
