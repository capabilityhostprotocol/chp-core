"""Tests for evidence integrity v0.2 — signing.py + strict verify_chain."""

from __future__ import annotations

import asyncio
import os
import stat

import pytest

from chp_core.host import LocalCapabilityHost
from chp_core.store import SQLiteEvidenceStore
from chp_core.types import CapabilityDescriptor
from chp_core import signing


CORR = "corr-sign-1"


def _host_with_events(tmp_path) -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost(store=store)

    async def handler(_ctx, _payload):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="s.cap", version="1.0.0", description=""), handler)
    asyncio.run(host.ainvoke("s.cap", {"n": 1}, correlation={"correlation_id": CORR}))
    asyncio.run(host.ainvoke("s.cap", {"n": 2}, correlation={"correlation_id": CORR}))
    return host


# --------------------------------------------------------------------------
# Keypair
# --------------------------------------------------------------------------

def test_generate_keypair_private_is_0600(tmp_path):
    key = signing.generate_keypair(tmp_path / "keys")
    assert key.can_sign
    assert len(key.key_id) == 16
    priv = tmp_path / "keys" / "host_ed25519"
    mode = stat.S_IMODE(os.stat(priv).st_mode)
    assert mode == 0o600, oct(mode)


def test_load_host_key_none_when_absent(tmp_path):
    assert signing.load_host_key(tmp_path / "nope") is None


def test_key_id_stable_from_pubkey(tmp_path):
    k1 = signing.generate_keypair(tmp_path / "k")
    k2 = signing.load_host_key(tmp_path / "k")
    assert k2 is not None and k2.key_id == k1.key_id


# --------------------------------------------------------------------------
# Bundle build / sign / verify round trip
# --------------------------------------------------------------------------

def test_unsigned_bundle_verifies_at_hash_chain_tier(tmp_path):
    host = _host_with_events(tmp_path)
    events = host.store.export_correlation(CORR)
    bundle = signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z")
    assert bundle["assurance"] == "hash-chain"
    v = signing.verify_bundle(bundle)
    assert v.valid and v.assurance == "hash-chain"


def test_signed_bundle_round_trip(tmp_path):
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z"), key
    )
    assert bundle["assurance"] == "signed"
    v = signing.verify_bundle(bundle)
    assert v.valid
    assert v.checks["signature"] is True
    # pinning the correct signer still passes
    assert signing.verify_bundle(bundle, expected_key_id=key.key_id).valid


def test_tampered_event_payload_fails(tmp_path):
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z"), key
    )
    # Mutate a payload but leave its content_hash — hash recompute must catch it.
    bundle["events"][0]["payload"] = {"n": 999}
    v = signing.verify_bundle(bundle)
    assert not v.valid
    assert v.checks["event_hashes"] is False


def test_tampered_root_hash_fails(tmp_path):
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z"), key
    )
    bundle["root_hash"] = "0" * 64
    v = signing.verify_bundle(bundle)
    assert not v.valid


def test_signature_from_unexpected_key_rejected(tmp_path):
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z"), key
    )
    # A valid signature, but not from the key we trust.
    v = signing.verify_bundle(bundle, expected_key_id="deadbeefdeadbeef")
    assert not v.valid


def test_forged_signature_fails(tmp_path):
    host = _host_with_events(tmp_path)
    attacker = signing.generate_keypair(tmp_path / "attacker")
    events = host.store.export_correlation(CORR)
    # Attacker rebuilds + re-signs after tampering (the exact threat unsigned
    # hash-chains can't stop). Verifier pins the real host key → rejected.
    real = signing.generate_keypair(tmp_path / "real")
    bundle = signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z")
    bundle["events"][0]["payload"] = {"n": 999}
    forged = signing.sign_bundle(bundle, attacker)
    v = signing.verify_bundle(forged, expected_key_id=real.key_id)
    assert not v.valid


# --------------------------------------------------------------------------
# Strict verify_chain
# --------------------------------------------------------------------------

def test_degrades_without_cryptography(tmp_path, monkeypatch):
    # Optional-dep contract: no cryptography → unsigned bundles still build and
    # verify at hash-chain tier; only signing raises a clear error.
    def _boom():
        raise signing.SigningUnavailable("simulated missing cryptography")

    monkeypatch.setattr(signing, "_load_backend", _boom)
    assert signing.signing_available() is False
    host = _host_with_events(tmp_path)
    events = host.store.export_correlation(CORR)
    bundle = signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z")
    assert signing.verify_bundle(bundle).valid  # hash-chain tier unaffected
    with pytest.raises(signing.SigningUnavailable):
        signing.generate_keypair(tmp_path / "k2")


def test_strict_verify_chain_fails_on_null_hash(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "legacy.sqlite"))
    # Simulate a legacy event with no content_hash.
    with store._lock:
        store._conn.execute("INSERT INTO evidence_sequence DEFAULT VALUES")
        store._conn.execute(
            "INSERT INTO evidence_events (sequence, event_id, event_type, invocation_id, "
            "capability_id, host_id, correlation_id, timestamp, payload_json, event_json, "
            "content_hash, prev_hash) VALUES (1,'e1','execution_started','i1','c','h','cx','t','{}','{}',NULL,NULL)"
        )
        store._conn.commit()
    lenient = store.verify_chain("cx")
    strict = store.verify_chain("cx", strict=True)
    assert lenient.valid is True          # legacy tolerated by default
    assert strict.valid is False          # strict flags the unhashed event
    assert strict.first_broken_sequence == 1


def test_verify_attestation_primitive(tmp_path):
    # The primitive both the bundle path and the mesh key-pinning path use.
    from chp_core.types import utc_now
    key = signing.generate_keypair(tmp_path / "keys")
    att = signing.build_attestation("prod-gateway", key, valid_from="2026-01-01T00:00:00Z")

    assert signing.verify_attestation(att, public_key=key.public_key_b64,
                                      expected_host_id="prod-gateway", at_time=utc_now())
    # wrong host_id, wrong key, and a tampered claim all fail
    assert not signing.verify_attestation(att, expected_host_id="attacker")
    assert not signing.verify_attestation(att, public_key="AAAA")
    tampered = {**att, "host_id": "spoofed"}
    assert not signing.verify_attestation(tampered)
    # expired: bundle/pin time after valid_until
    expiring = signing.build_attestation("h", key, valid_from="2026-01-01T00:00:00Z",
                                         valid_until="2026-02-01T00:00:00Z")
    assert not signing.verify_attestation(expiring, at_time="2026-06-01T00:00:00Z")


def test_relabelled_host_id_fails_verification(tmp_path):
    # Provenance: the header signature covers host_id, so relabelling the origin
    # (the exact "anyone can sign a bundle labeled prod-gateway-acme" gap) breaks it.
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("real-host", events, created_at="2026-07-03T00:00:00Z"), key
    )
    assert signing.verify_bundle(bundle).valid
    bundle["host_id"] = "prod-gateway-acme"
    v = signing.verify_bundle(bundle)
    assert not v.valid
    assert v.checks["signature"] is False


def test_attestation_binds_key_to_host(tmp_path):
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("real-host", events, created_at="2026-07-03T00:00:00Z"), key
    )
    att = bundle["host_identity"]
    assert att["host_id"] == "real-host" and att["public_key"] == key.public_key_b64
    assert signing.verify_bundle(bundle).checks["host_identity"] is True
    # Swapping the attestation's host_id (without re-signing) is caught.
    bundle["host_identity"]["host_id"] = "someone-else"
    assert signing.verify_bundle(bundle).checks["host_identity"] is False


def test_expired_key_identity_fails(tmp_path):
    # Key lifecycle: a bundle whose created_at is after the attestation's
    # valid_until (the key was rotated out) fails — offline, no wall clock.
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z"),
        key, valid_until="2026-01-01T00:00:00Z",  # expired well before created_at
    )
    v = signing.verify_bundle(bundle)
    assert not v.valid
    assert v.checks["host_identity"] is False


def test_unexpired_key_identity_passes(tmp_path):
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("h", events, created_at="2026-07-03T00:00:00Z"),
        key, valid_until="2027-01-01T00:00:00Z",  # still valid at created_at
    )
    assert signing.verify_bundle(bundle).checks["host_identity"] is True


def test_governed_bundle_has_no_floats_and_verifies(tmp_path):
    # chp-stable-v1 §2: no floats in canonicalized content. A governed bundle
    # carrying a safety score would silently fail cross-language verification if
    # the score were a float (Python "0.0" vs JS "0"). Guard: the score is a
    # string in the hashed payload, and the signed bundle verifies.
    from chp_core.safety import RuleBasedSafetyEvaluator
    from chp_core.types import GuardrailDefinition

    ev = RuleBasedSafetyEvaluator(guardrails=[GuardrailDefinition(
        id="g", capability_id_pattern="x.cap", max_risk_level="critical",
        requires_human_for=[])])
    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("gh", store=store, safety_evaluator=ev)

    async def _h(_c, _p):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="x.cap", version="1.0.0", description=""), _h)
    asyncio.run(host.ainvoke("x.cap", {}, correlation={"correlation_id": "c"}))

    events = store.export_correlation("c")
    completed = next(e for e in events if e["event_type"] == "safety_assessment_completed")
    assert isinstance(completed["payload"]["score"], str), "score must be string-encoded, not float"

    def _no_floats(v):
        assert not isinstance(v, float), f"float in hashed payload: {v!r}"
        if isinstance(v, dict):
            [_no_floats(x) for x in v.values()]
        elif isinstance(v, list):
            [_no_floats(x) for x in v]
    for e in events:
        _no_floats(e.get("payload") or {})

    key = signing.generate_keypair(tmp_path / "keys")
    bundle = signing.sign_bundle(signing.build_bundle("gh", events, created_at="2026-07-05T00:00:00Z"), key)
    assert signing.verify_bundle(bundle).valid


def test_published_vectors_match_current_canonicalization():
    # Drift guard: the published spec/test-vectors are what non-Python verifiers
    # rely on. If the canonicalization ever changes without regenerating them,
    # cross-language verification silently breaks — this test catches it.
    import json
    from pathlib import Path
    from chp_core.store import _compute_event_hash

    root = Path(__file__).resolve().parents[3] / "spec" / "test-vectors"
    exp = json.loads((root / "expected.json").read_text())
    ev = json.loads((root / "event.json").read_text())["event"]

    assert _compute_event_hash(ev, None) == exp["event_content_hash"], \
        "content_hash drifted from published vector — regenerate spec/test-vectors"
    bundle = json.loads((root / "signed-bundle.json").read_text())
    assert signing.verify_bundle(bundle).valid, "published signed-bundle vector no longer verifies"
    assert bundle["root_hash"] == exp["root_hash"]

    # The governed vector: a safety-blocked chain with a string-encoded score.
    # If canonicalization or the no-float rule regresses, this stops verifying.
    gov = json.loads((root / "governance-bundle.json").read_text())
    assert signing.verify_bundle(gov).valid, "published governance-bundle vector no longer verifies"
    completed = next(e for e in gov["events"] if e["event_type"] == "safety_assessment_completed")
    assert isinstance(completed["payload"]["score"], str), "governed vector score must be string-encoded"


# ── Anchors (cross-org trust, spec §3 Anchors) ────────────────────────────────

def test_anchored_attestation_roundtrip_and_tamper(tmp_path):
    key = signing.generate_keypair(tmp_path / "keys")
    anchors = [{"type": "domain", "domain": "acme.example"}]
    att = signing.build_attestation("h", key, valid_from="2026-01-01T00:00:00Z",
                                    anchors=anchors)
    assert att["anchors"] == anchors
    assert signing.verify_attestation(att, public_key=key.public_key_b64)
    # STRIP (downgrade): removing anchors breaks the self-signature.
    stripped = {k: v for k, v in att.items() if k != "anchors"}
    assert not signing.verify_attestation(stripped, public_key=key.public_key_b64)
    # STAPLE (forgery): adding/altering an anchor breaks it too.
    stapled = {**att, "anchors": [{"type": "domain", "domain": "evil.example"}]}
    assert not signing.verify_attestation(stapled, public_key=key.public_key_b64)


def test_no_anchor_attestation_bytes_unchanged(tmp_path):
    # The omit-when-empty rule: anchors=None and anchors=[] MUST both produce
    # the exact pre-anchor claim (no "anchors" key) — the byte-compat guarantee.
    key = signing.generate_keypair(tmp_path / "keys")
    a1 = signing.build_attestation("h", key, valid_from="2026-01-01T00:00:00Z")
    a2 = signing.build_attestation("h", key, valid_from="2026-01-01T00:00:00Z", anchors=[])
    assert "anchors" not in a1 and "anchors" not in a2
    assert a1["signature"] == a2["signature"]


def test_resolve_anchor_confirms_and_rejects(tmp_path):
    import io, json as _json
    from contextlib import contextmanager

    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("h", events, created_at="2026-07-05T00:00:00Z"), key,
    )
    # sign_bundle builds the attestation without anchors; rebuild with one.
    bundle["host_identity"] = signing.build_attestation(
        "h", key, valid_from="2026-07-05T00:00:00Z",
        anchors=[{"type": "domain", "domain": "acme.example"}],
    )

    def _doc_opener(doc):
        @contextmanager
        def _open(url, timeout=None):  # noqa: ARG001
            yield io.BytesIO(_json.dumps(doc).encode())
        return _open

    good = {"assurance": "signed", "public_key": key.public_key_b64}
    monkey = signing.resolve_host_identity
    doc = signing.resolve_host_identity("acme.example", _urlopen=_doc_opener(good))
    assert doc["public_key"] == key.public_key_b64

    # Wire the injected resolver through verify_bundle via monkeypatching the
    # module-level function (verify_bundle calls resolve_host_identity directly).
    import chp_core.signing as S
    orig = S.resolve_host_identity
    try:
        S.resolve_host_identity = lambda d, **kw: good
        v = S.verify_bundle(bundle, resolve=True)
        assert v.checks["anchor"] is True
        assert v.anchored_domain == "acme.example"

        S.resolve_host_identity = lambda d, **kw: {"public_key": "SOMEONE-ELSES-KEY"}
        v2 = S.verify_bundle(bundle, resolve=True)
        assert v2.checks["anchor"] is False and not v2.valid
        assert v2.anchored_domain is None
    finally:
        S.resolve_host_identity = orig
    assert monkey is S.resolve_host_identity


def test_resolve_requires_https():
    import pytest as _pytest
    with _pytest.raises(signing.AnchorResolutionError, match="https"):
        signing.resolve_host_identity("http://acme.example")


def test_no_anchor_bundle_under_resolve_is_tofu_floor(tmp_path):
    # resolve=True on an anchor-less bundle: no 'anchor' check appears — the
    # caller can SEE it's TOFU-floor, and validity is unchanged.
    host = _host_with_events(tmp_path)
    key = signing.generate_keypair(tmp_path / "keys")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("h", events, created_at="2026-07-05T00:00:00Z"), key)
    v = signing.verify_bundle(bundle, resolve=True)
    assert v.valid and "anchor" not in v.checks and v.anchored_domain is None


def test_load_or_build_attestation_is_stable_and_rebuilds_on_change(tmp_path):
    key = signing.generate_keypair(tmp_path / "keys")
    a1 = signing.load_or_build_attestation("h", key, None, key_dir=tmp_path / "keys")
    a2 = signing.load_or_build_attestation("h", key, None, key_dir=tmp_path / "keys")
    assert a1 == a2, "attestation must be persisted, not rebuilt per request"
    # anchor config change → rebuild (new signature, anchors present)
    a3 = signing.load_or_build_attestation(
        "h", key, [{"type": "domain", "domain": "acme.example"}], key_dir=tmp_path / "keys")
    assert a3 != a1 and a3["anchors"][0]["domain"] == "acme.example"
    # and the anchored one is now stable too
    a4 = signing.load_or_build_attestation(
        "h", key, [{"type": "domain", "domain": "acme.example"}], key_dir=tmp_path / "keys")
    assert a3 == a4
