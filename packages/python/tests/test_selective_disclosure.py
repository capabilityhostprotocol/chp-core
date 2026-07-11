"""Selective disclosure (chp-v0.2.md §14, proposal 0011) — chp-event-hash-v2
payload commitments + withholdable payloads."""

from __future__ import annotations

import asyncio
import hashlib
import json

from chp_core import signing
from chp_core.host import LocalCapabilityHost
from chp_core.store import (
    EVENT_HASH_V2,
    SQLiteEvidenceStore,
    _compute_event_hash,
    _payload_commitment,
)
from chp_core.types import CapabilityDescriptor

CORR = "corr-disclose-1"
CREATED = "2026-07-11T00:00:00Z"


def _host(tmp_path) -> LocalCapabilityHost:
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(str(tmp_path / "ev.sqlite")))

    async def handler(_ctx, payload):
        return {"echo": payload}

    host.register(CapabilityDescriptor(id="s.cap", version="1.0.0", description=""), handler)
    asyncio.run(host.ainvoke("s.cap", {"secret": "alpha"}, correlation={"correlation_id": CORR}))
    asyncio.run(host.ainvoke("s.cap", {"secret": "bravo"}, correlation={"correlation_id": CORR}))
    return host


def _signed_bundle(tmp_path):
    host = _host(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(signing.build_bundle("h", events, created_at=CREATED), key)
    return bundle


# ── the v2 scheme ────────────────────────────────────────────────────────────

def test_v1_event_byte_identical():
    """An event with no hash_scheme hashes exactly as the legacy inline-payload
    formula — v1 is untouched."""
    ev = {"event_id": "e1", "event_type": "x", "invocation_id": "i", "capability_id": "c",
          "host_id": "h", "correlation": {"correlation_id": "corr"}, "timestamp": CREATED,
          "outcome": "success", "payload": {"a": 1}}
    legacy_stable = {"event_id": "e1", "event_type": "x", "invocation_id": "i",
                     "capability_id": "c", "host_id": "h", "correlation_id": "corr",
                     "timestamp": CREATED, "outcome": "success", "payload": {"a": 1},
                     "prev_hash": None}
    expected = hashlib.sha256(json.dumps(legacy_stable, sort_keys=True).encode()).hexdigest()
    assert _compute_event_hash(ev, None) == expected


def test_v2_hashes_commitment_not_payload():
    """Under v2 the content_hash commits to sha256(payload); changing the payload
    while keeping the commitment does NOT move the hash."""
    payload = {"a": 1}
    ev = {"event_id": "e1", "event_type": "x", "invocation_id": "i", "capability_id": "c",
          "host_id": "h", "correlation": {"correlation_id": "corr"}, "timestamp": CREATED,
          "outcome": "success", "payload": payload, "hash_scheme": EVENT_HASH_V2,
          "payload_commitment": _payload_commitment(payload)}
    h1 = _compute_event_hash(ev, None)
    # withhold the payload → same commitment → same content_hash
    ev_withheld = dict(ev, payload={"chp_withheld": True})
    assert _compute_event_hash(ev_withheld, None) == h1
    # v1 and v2 of the same event differ (distinct schemes)
    ev_v1 = {k: v for k, v in ev.items() if k not in ("hash_scheme", "payload_commitment")}
    assert _compute_event_hash(ev_v1, None) != h1


def test_empty_payload_commitment_pins_missing_case():
    """None and {} commit identically — the pinned cross-impl empty form."""
    assert _payload_commitment(None) == _payload_commitment({})
    assert _payload_commitment({}) == hashlib.sha256(b"{}").hexdigest()


# ── emission ─────────────────────────────────────────────────────────────────

def test_emitted_events_are_v2(tmp_path):
    events = _host(tmp_path).store.export_correlation(CORR)
    assert events, "expected emitted events"
    for ev in events:
        assert ev["hash_scheme"] == EVENT_HASH_V2
        assert ev["payload_commitment"] == _payload_commitment(ev["payload"])


# ── withholding ──────────────────────────────────────────────────────────────

def test_withheld_bundle_still_verifies(tmp_path):
    bundle = _signed_bundle(tmp_path)
    assert signing.verify_bundle(bundle).valid

    minimized = signing.withhold_payloads(bundle)
    # payloads gone, commitments + root + signature intact
    assert all(ev["payload"] == {"chp_withheld": True} for ev in minimized["events"])
    assert minimized["root_hash"] == bundle["root_hash"]
    assert minimized["signature"] == bundle["signature"]
    v = signing.verify_bundle(minimized)
    assert v.valid, v.reason
    assert v.checks["payload_commitments"] and v.checks["event_hashes"] and v.checks["root_hash"]
    # and the sensitive values are truly absent
    assert "alpha" not in json.dumps(minimized) and "bravo" not in json.dumps(minimized)


def test_selective_withhold_by_predicate(tmp_path):
    bundle = _signed_bundle(tmp_path)
    first = bundle["events"][0]["event_id"]
    minimized = signing.withhold_payloads(bundle, lambda ev: ev["event_id"] == first)
    assert minimized["events"][0]["payload"] == {"chp_withheld": True}
    assert minimized["events"][1]["payload"] != {"chp_withheld": True}  # disclosed
    assert signing.verify_bundle(minimized).valid


# ── disclosed-payload binding ────────────────────────────────────────────────

def test_tampered_disclosed_payload_fails(tmp_path):
    """A disclosed payload swapped while keeping the signed commitment is caught
    by the commitment bind (chain still 'verifies' via the commitment)."""
    bundle = _signed_bundle(tmp_path)
    bundle["events"][0]["payload"] = {"secret": "FORGED"}  # commitment unchanged
    v = signing.verify_bundle(bundle)
    assert not v.valid
    assert v.checks["payload_commitments"] is False
    assert v.checks["event_hashes"] is True  # the hash binds the commitment, not the payload


def test_tampered_commitment_fails(tmp_path):
    """Editing the commitment breaks the content_hash recompute."""
    bundle = _signed_bundle(tmp_path)
    bundle["events"][0]["payload_commitment"] = "0" * 64
    assert signing.verify_bundle(bundle).checks["event_hashes"] is False


# ── coexistence + invariants ─────────────────────────────────────────────────

def test_mixed_v1_v2_chain_verifies(tmp_path):
    """A hand-built chain of a v1 event then a v2 event verifies end to end."""
    v1 = {"event_id": "e1", "event_type": "execution_started", "invocation_id": "i1",
          "capability_id": "c", "host_id": "h", "correlation": {"correlation_id": "m"},
          "timestamp": CREATED, "outcome": None, "payload": {"step": 1}}
    v1["content_hash"] = _compute_event_hash(v1, None)
    v1["prev_hash"] = None
    p2 = {"step": 2}
    v2 = {"event_id": "e2", "event_type": "execution_completed", "invocation_id": "i2",
          "capability_id": "c", "host_id": "h", "correlation": {"correlation_id": "m"},
          "timestamp": CREATED, "outcome": "success", "payload": p2,
          "hash_scheme": EVENT_HASH_V2, "payload_commitment": _payload_commitment(p2)}
    v2["content_hash"] = _compute_event_hash(v2, v1["content_hash"])
    v2["prev_hash"] = v1["content_hash"]
    key = signing.generate_keypair(tmp_path / "keys")
    bundle = signing.sign_bundle(signing.build_bundle("h", [v1, v2], created_at=CREATED), key)
    assert signing.verify_bundle(bundle).valid
    # withholding the v2 payload keeps it valid; the v1 event is left intact
    minimized = signing.withhold_payloads(bundle)
    assert minimized["events"][0]["payload"] == {"step": 1}          # v1 untouched
    assert minimized["events"][1]["payload"] == {"chp_withheld": True}
    assert signing.verify_bundle(minimized).valid


def test_cli_minimize_then_verify(tmp_path):
    """`chp bundle minimize` produces a still-verifying bundle; `chp bundle
    verify` exits 0 on it and 1 on a tampered one."""
    import argparse

    from chp_core.cli._core import cmd_bundle_minimize, cmd_bundle_verify

    src = tmp_path / "bundle.json"
    src.write_text(json.dumps(_signed_bundle(tmp_path)))
    out = tmp_path / "min.json"
    rc = cmd_bundle_minimize(argparse.Namespace(bundle=str(src), out=str(out),
                                                capability=None, event=None))
    assert rc == 0
    minimized = json.loads(out.read_text())
    assert all(e["payload"] == {"chp_withheld": True} for e in minimized["events"])
    assert cmd_bundle_verify(argparse.Namespace(bundle=str(out), key_id=None)) == 0

    # tamper a disclosed payload → verify exits 1
    bundle = json.loads(src.read_text())
    bundle["events"][0]["payload"] = {"secret": "FORGED"}
    tampered = tmp_path / "bad.json"
    tampered.write_text(json.dumps(bundle))
    assert cmd_bundle_verify(argparse.Namespace(bundle=str(tampered), key_id=None)) == 1


def test_store_head_unchanged_by_withhold(tmp_path):
    """Withholding changes no content_hash, so the store head / root are stable."""
    host = _host(tmp_path)
    head_before = host.store.get_store_head()["store_head"]
    bundle = signing.build_bundle("h", host.store.export_correlation(CORR), created_at=CREATED)
    minimized = signing.withhold_payloads(bundle)
    assert signing.compute_root_hash(minimized["events"]) == bundle["root_hash"]
    assert host.store.get_store_head()["store_head"] == head_before  # store never mutated
