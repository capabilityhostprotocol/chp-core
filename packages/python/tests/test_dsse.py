"""in-toto / DSSE attestation bridge (chp-v0.2.md §15, proposal 0021)."""

from __future__ import annotations

import asyncio
import base64
import json

import pytest

from chp_core import signing, dsse
from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore

pytestmark = pytest.mark.skipif(
    not signing.signing_available(), reason="signing backend not installed")

CORR = "corr-dsse"


def _signed_bundle(tmp_path):
    host = LocalCapabilityHost("dsse-host", store=SQLiteEvidenceStore(":memory:"))

    async def echo(_c, p):
        return {"echo": p}

    host.register(CapabilityDescriptor(id="d.echo", version="1.0.0", description=""), echo)
    asyncio.run(host.ainvoke("d.echo", {"v": "café 🔒"}, correlation={"correlation_id": CORR}))
    events = host.store.export_correlation(CORR)
    key = signing.generate_keypair(tmp_path)
    bundle = signing.sign_bundle(signing.build_bundle("dsse-host", events, created_at="2026-07-12T00:00:00Z"), key)
    return bundle, key


# ── PAE (the exact DSSE bytes) ───────────────────────────────────────────────

def test_pae_is_the_dsse_spec_encoding():
    # DSSEv1 SP LEN(type) SP type SP LEN(body) SP body
    assert dsse._pae(b"application/vnd.in-toto+json", b"{}") == \
        b"DSSEv1 28 application/vnd.in-toto+json 2 {}"


# ── statement + envelope shape ───────────────────────────────────────────────

def test_statement_subject_is_the_root_hash(tmp_path):
    bundle, _ = _signed_bundle(tmp_path)
    stmt = dsse.bundle_to_statement(bundle)
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == "https://chp.dev/attestation/evidence-bundle/v1"
    assert stmt["subject"][0]["name"] == CORR
    assert stmt["subject"][0]["digest"]["sha256"] == bundle["root_hash"]
    assert stmt["predicate"] == bundle  # lossless


def test_envelope_shape(tmp_path):
    bundle, key = _signed_bundle(tmp_path)
    env = dsse.bundle_to_attestation(bundle, key)
    assert env["payloadType"] == "application/vnd.in-toto+json"
    assert env["signatures"][0]["keyid"] == key.key_id
    # payload is base64 of the statement JSON
    assert json.loads(base64.b64decode(env["payload"]))["predicate"] == bundle


# ── verification, both levels ────────────────────────────────────────────────

def test_dsse_signature_verifies_independently(tmp_path):
    """Level 1 — any DSSE verifier (no CHP): recompute the PAE, check ed25519."""
    bundle, key = _signed_bundle(tmp_path)
    env = dsse.bundle_to_attestation(bundle, key)
    assert dsse.verify_dsse(env, key.public_key_b64)
    # wrong key fails
    other = signing.generate_keypair(tmp_path / "other")
    assert not dsse.verify_dsse(env, other.public_key_b64)


def test_full_attestation_verifies(tmp_path):
    bundle, key = _signed_bundle(tmp_path)
    env = dsse.bundle_to_attestation(bundle, key)
    v = dsse.verify_attestation(env)  # public key comes from the embedded bundle
    assert v.valid, v.reason
    assert v.checks == {"dsse_signature": True, "statement_type": True,
                        "subject_digest": True, "bundle": True}


def test_round_trips_to_a_verifiable_bundle(tmp_path):
    bundle, key = _signed_bundle(tmp_path)
    env = dsse.bundle_to_attestation(bundle, key)
    back = dsse.attestation_to_bundle(env)
    assert back == bundle
    assert signing.verify_bundle(back).valid


# ── tamper detection ─────────────────────────────────────────────────────────

def test_tampered_payload_fails_dsse(tmp_path):
    bundle, key = _signed_bundle(tmp_path)
    env = dsse.bundle_to_attestation(bundle, key)
    stmt = dsse.dsse_statement(env)
    stmt["subject"][0]["digest"]["sha256"] = "0" * 64  # tamper the body
    env["payload"] = base64.b64encode(json.dumps(stmt, sort_keys=True).encode()).decode()
    assert not dsse.verify_dsse(env, key.public_key_b64)  # sig no longer matches PAE
    assert not dsse.verify_attestation(env).valid


def test_subject_digest_mismatch_detected(tmp_path):
    """Even a correctly-DSSE-signed statement whose subject ≠ the bundle root fails."""
    bundle, key = _signed_bundle(tmp_path)
    stmt = dsse.bundle_to_statement(bundle)
    stmt["subject"][0]["digest"]["sha256"] = "0" * 64  # lie about the subject, then RE-SIGN
    env = dsse.dsse_sign(stmt, key)
    v = dsse.verify_attestation(env)
    assert not v.valid and v.checks["subject_digest"] is False and v.checks["dsse_signature"] is True
