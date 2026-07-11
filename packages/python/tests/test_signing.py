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
    # Mutate a payload but leave its content_hash. Emitted events are
    # chp-event-hash-v2 (§14), so the content_hash binds the payload_commitment,
    # not the raw payload: the chain still recomputes (event_hashes True) but the
    # disclosed-payload bind catches the swap (payload_commitments False).
    bundle["events"][0]["payload"] = {"n": 999}
    v = signing.verify_bundle(bundle)
    assert not v.valid
    assert v.checks["payload_commitments"] is False


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


# ---------------------------------------------------------------------------
# Per-host key custody (chp-v0.2.md §3 "Key custody")
# ---------------------------------------------------------------------------

class TestResolveKeyDir:
    def test_env_override_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CHP_KEY_DIR", str(tmp_path / "env-keys"))
        assert signing.resolve_key_dir("any-host") == tmp_path / "env-keys"

    def test_per_host_dir_used_when_it_holds_a_key(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CHP_KEY_DIR", raising=False)
        monkeypatch.setattr(signing, "DEFAULT_KEY_DIR", tmp_path / "keys")
        signing.generate_keypair(tmp_path / "keys" / "host-a")
        assert signing.resolve_key_dir("host-a") == tmp_path / "keys" / "host-a"

    def test_legacy_fallback_when_no_per_host_key(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CHP_KEY_DIR", raising=False)
        monkeypatch.setattr(signing, "DEFAULT_KEY_DIR", tmp_path / "keys")
        assert signing.resolve_key_dir("host-a") == tmp_path / "keys"
        assert signing.resolve_key_dir(None) == tmp_path / "keys"

    def test_unsafe_host_id_never_maps_to_per_host_dir(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CHP_KEY_DIR", raising=False)
        monkeypatch.setattr(signing, "DEFAULT_KEY_DIR", tmp_path / "keys")
        signing.generate_keypair(tmp_path / "keys" / "host-a")
        assert signing.resolve_key_dir("../host-a") == tmp_path / "keys"
        assert signing.resolve_key_dir("a/../../b") == tmp_path / "keys"

    def test_two_hosts_sign_with_distinct_keys(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CHP_KEY_DIR", raising=False)
        monkeypatch.setattr(signing, "DEFAULT_KEY_DIR", tmp_path / "keys")
        ka = signing.generate_keypair(tmp_path / "keys" / "host-a")
        kb = signing.generate_keypair(tmp_path / "keys" / "host-b")
        assert ka.key_id != kb.key_id
        assert signing.load_host_key(signing.resolve_key_dir("host-a")).key_id == ka.key_id
        assert signing.load_host_key(signing.resolve_key_dir("host-b")).key_id == kb.key_id


# ---------------------------------------------------------------------------
# Aggregated task bundles + participation manifests (chp-v0.2.md §8)
# ---------------------------------------------------------------------------

class TestAggregatedTaskBundle:
    def _task(self, tmp_path, declare=None):
        import asyncio
        from chp_core.types import utc_now
        key = signing.generate_keypair(tmp_path / "k")

        def member(host_id, corr):
            store = SQLiteEvidenceStore(":memory:")
            host = LocalCapabilityHost(host_id, store=store)
            async def work(ctx, _p):
                if declare and host_id == declare[0]:
                    ctx.declare_participants(declare)
                return {}
            host.register(CapabilityDescriptor(id=f"{host_id}.w", version="1.0.0", description=""), work)
            r = asyncio.run(host.ainvoke(f"{host_id}.w", {}, correlation={"correlation_id": corr}))
            assert r.success
            b = signing.build_bundle(host_id, store.export_correlation(corr), created_at=utc_now())
            return signing.sign_bundle(b, key)

        ba, bb = member("agg-a", "t-corr"), member("agg-b", "t-corr")
        return signing.build_task_bundle("t-corr", [ba, bb], created_at=utc_now()), key

    def test_unsigned_assembly_surfaces_null_aggregator(self, tmp_path):
        task, _ = self._task(tmp_path)
        v = signing.verify_task_bundle(task)
        assert v.valid and "aggregator" not in v.checks and v.aggregator is None
        assert "aggregator" not in task  # omit-when-empty: bytes unchanged

    def test_signed_assembly_verifies_and_names_aggregator(self, tmp_path):
        task, key = self._task(tmp_path)
        signed = signing.sign_task_bundle(task, key, aggregator_host_id="gw-x")
        v = signing.verify_task_bundle(signed)
        assert v.valid and v.checks["aggregator"]
        assert v.aggregator["host_id"] == "gw-x" and v.aggregator["valid"]

    def test_reassembled_set_breaks_aggregator_signature(self, tmp_path):
        task, key = self._task(tmp_path)
        signed = signing.sign_task_bundle(task, key, aggregator_host_id="gw-x")
        signed["bundles"] = signed["bundles"][:1]
        signed["task_root_hash"] = signing.compute_task_root_hash(signed["bundles"])
        v = signing.verify_task_bundle(signed)
        assert not v.valid and v.checks["aggregator"] is False

    def test_declared_participant_missing_fails_participation(self, tmp_path):
        task, _ = self._task(tmp_path, declare=["agg-a", "agg-b"])
        v = signing.verify_task_bundle(task)
        assert v.valid and v.checks["participation"] is True
        task["bundles"] = [b for b in task["bundles"] if b["host_id"] != "agg-b"]
        task["task_root_hash"] = signing.compute_task_root_hash(task["bundles"])
        v2 = signing.verify_task_bundle(task)
        assert not v2.valid and v2.checks["participation"] is False
        assert "declared but missing" in v2.reason

    def test_no_manifest_means_no_participation_check(self, tmp_path):
        task, _ = self._task(tmp_path)
        v = signing.verify_task_bundle(task)
        assert "participation" not in v.checks


# ---------------------------------------------------------------------------
# Adapter provenance (chp-v0.2.md §9, proposal 0001)
# ---------------------------------------------------------------------------

class TestAdapterProvenance:
    def _stmt(self, tmp_path, **kw):
        import hashlib
        key = signing.generate_keypair(tmp_path / "pubkey")
        sha = hashlib.sha256(b"wheel bytes").hexdigest()
        stmt = signing.build_provenance_statement(
            "chp-adapter-x", "1.2.3", sha, key,
            publisher_id="acme-release", created_at="2026-07-09T00:00:00Z", **kw)
        return stmt, key, sha

    def test_round_trip_with_artifact_hash(self, tmp_path):
        stmt, key, sha = self._stmt(tmp_path)
        v = signing.verify_provenance_statement(stmt, wheel_sha256=sha)
        assert v.valid and v.checks["artifact_hash"] and v.checks["publisher_identity"]

    def test_tampered_artifact_fails_artifact_hash(self, tmp_path):
        import hashlib
        stmt, key, _ = self._stmt(tmp_path)
        v = signing.verify_provenance_statement(
            stmt, wheel_sha256=hashlib.sha256(b"EVIL").hexdigest())
        assert not v.valid and v.checks["artifact_hash"] is False
        assert v.checks["signature"] is True  # the statement itself is intact

    def test_relabel_breaks_signature(self, tmp_path):
        stmt, *_ = self._stmt(tmp_path)
        for field in ("package", "version", "wheel_sha256"):
            bad = dict(stmt); bad[field] = "tampered"
            assert signing.verify_provenance_statement(bad).checks["signature"] is False

    def test_expected_key_pin(self, tmp_path):
        stmt, key, sha = self._stmt(tmp_path)
        assert signing.verify_provenance_statement(stmt, expected_key_id=key.key_id).valid
        v = signing.verify_provenance_statement(stmt, expected_key_id="deadbeefdeadbeef")
        assert not v.valid and "unexpected key" in v.reason

    def test_missing_attestation_fails(self, tmp_path):
        stmt, *_ = self._stmt(tmp_path)
        bad = dict(stmt); bad["publisher"] = {k: v for k, v in stmt["publisher"].items()
                                             if k != "host_identity"}
        assert signing.verify_provenance_statement(bad).checks["publisher_identity"] is False

# ---------------------------------------------------------------------------
# Mandates (chp-v0.2.md §10, proposal 0002)
# ---------------------------------------------------------------------------

class TestMandates:
    def _mandate(self, tmp_path, **kw):
        key = signing.generate_keypair(tmp_path / "pubkey")
        mandate = signing.build_mandate(
            "principal-a", key, delegate_id="steward-x",
            scope=["demo.echo", "chp.adapters.audit.*"],
            valid_from="2026-07-09T00:00:00Z", valid_until="2026-07-10T00:00:00Z",
            created_at="2026-07-09T00:00:00Z", **kw)
        return mandate, key

    def test_round_trip_in_scope_in_window(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        v = signing.verify_mandate(
            mandate, at_time="2026-07-09T12:00:00Z",
            capability_id="demo.echo", delegate_id="steward-x")
        assert v.valid and v.checks["scope"] and v.checks["principal_identity"]

    def test_wildcard_scope_grammar(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        assert signing.scope_allows(mandate["scope"], "chp.adapters.audit.stats")
        assert not signing.scope_allows(mandate["scope"], "chp.adapters.git.push")

    def test_expired_fails_temporal_only(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        v = signing.verify_mandate(mandate, at_time="2026-07-11T00:00:00Z")
        assert not v.valid and v.checks["temporal"] is False
        assert v.checks["signature"] is True

    def test_not_yet_valid_fails_temporal(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        assert not signing.verify_mandate(mandate, at_time="2026-07-08T00:00:00Z").valid

    def test_out_of_scope_fails_scope(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        v = signing.verify_mandate(mandate, capability_id="demo.other")
        assert not v.valid and v.checks["scope"] is False

    def test_wrong_delegate_fails_delegate(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        v = signing.verify_mandate(mandate, delegate_id="someone-else")
        assert not v.valid and v.checks["delegate"] is False

    def test_widened_scope_breaks_signature(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        bad = dict(mandate); bad["scope"] = ["*"]
        assert signing.verify_mandate(bad).checks["signature"] is False
        for field in ("delegate_id", "valid_until", "mandate_id"):
            bad = dict(mandate); bad[field] = "tampered"
            assert signing.verify_mandate(bad).checks["signature"] is False

    def test_expected_principal_key_pin(self, tmp_path):
        mandate, key = self._mandate(tmp_path)
        assert signing.verify_mandate(mandate, expected_principal_key=key.key_id).valid
        v = signing.verify_mandate(mandate, expected_principal_key="deadbeefdeadbeef")
        assert not v.valid and "unexpected key" in v.reason

    def test_missing_attestation_fails(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        bad = dict(mandate)
        bad["principal"] = {k: v for k, v in mandate["principal"].items()
                            if k != "host_identity"}
        assert signing.verify_mandate(bad).checks["principal_identity"] is False

    def test_scope_sorted_and_key_history_omitted_when_empty(self, tmp_path):
        mandate, _ = self._mandate(tmp_path)
        assert mandate["scope"] == sorted(mandate["scope"])
        assert "key_history" not in mandate["principal"]

    def test_unsigned_key_cannot_issue(self, tmp_path):
        mandate, key = self._mandate(tmp_path)
        public_only = signing.HostKey(key_id=key.key_id,
                                      public_key_b64=key.public_key_b64, _private=None)
        import pytest
        with pytest.raises(signing.SigningUnavailable):
            signing.build_mandate("principal-a", public_only, delegate_id="d",
                                  scope=["x"], valid_from="2026-01-01T00:00:00Z",
                                  valid_until="2026-01-02T00:00:00Z",
                                  created_at="2026-01-01T00:00:00Z")
