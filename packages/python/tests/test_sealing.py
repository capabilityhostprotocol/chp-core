"""Sealed payloads — confidentiality over the evidence chain (chp-v0.2.md §16,
proposal 0025). A sealed bundle verifies offline with NO key; only the recipient
unseals; the chain/root/signature are untouched (the §14 withhold seam)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore, signing
from chp_core import sealing
from chp_core.types import CorrelationContext, InvocationEnvelope

CORR = "seal-corr-1"


def _signed_bundle(tmp_path):
    host = LocalCapabilityHost("seal-host", store=SQLiteEvidenceStore(":memory:"))

    async def handler(_ctx, payload):
        return {"echo": payload}

    host.register(CapabilityDescriptor(id="s.cap", version="1.0.0", description="."), handler)
    asyncio.run(host.ainvoke("s.cap", {"secret": "hunter2", "amount": 42},
                             correlation={"correlation_id": CORR}))
    key = signing.generate_keypair(tmp_path / "k")
    events = host.store.export_correlation(CORR)
    bundle = signing.sign_bundle(
        signing.build_bundle("seal-host", events, created_at="2026-07-12T00:00:00Z"), key)
    assert signing.verify_bundle(bundle).valid
    return bundle


def test_sealed_bundle_verifies_offline_with_no_key(tmp_path):
    bundle = _signed_bundle(tmp_path)
    recipient = sealing.generate_enc_keypair(tmp_path / "enc")
    pub = sealing.load_enc_public_key_b64(tmp_path / "enc")
    sealed = sealing.seal_payloads(bundle, pub)
    # every payload with real content is now a sealed marker
    sealed_evs = [e for e in sealed["events"] if isinstance(e.get("payload"), dict)
                  and "chp_sealed" in e["payload"]]
    assert sealed_evs, "at least one payload should be sealed"
    # a THIRD PARTY with no key verifies the full chain/root/signature
    v = signing.verify_bundle(sealed)
    assert v.valid, v.reason
    assert v.checks["payload_commitments"] and v.checks["root_hash"] and v.checks["signature"]
    # the ciphertext does not leak the plaintext
    import json as _json
    assert "hunter2" not in _json.dumps(sealed)


def test_recipient_unseals_and_commitment_holds(tmp_path):
    bundle = _signed_bundle(tmp_path)
    recipient = sealing.generate_enc_keypair(tmp_path / "enc")
    pub = sealing.load_enc_public_key_b64(tmp_path / "enc")
    sealed = sealing.seal_payloads(bundle, pub)
    # the recipient decrypts back to the exact original bundle
    opened = sealing.unseal_bundle(sealed, recipient)
    assert opened == bundle
    # and the recovered payloads still match their committed hashes
    from chp_core.store import _payload_commitment
    for ev in opened["events"]:
        if ev.get("hash_scheme") == "chp-event-hash-v2" and ev.get("payload_commitment"):
            assert _payload_commitment(ev["payload"]) == ev["payload_commitment"]


def test_wrong_key_fails(tmp_path):
    bundle = _signed_bundle(tmp_path)
    sealing.generate_enc_keypair(tmp_path / "enc")
    pub = sealing.load_enc_public_key_b64(tmp_path / "enc")
    sealed = sealing.seal_payloads(bundle, pub)
    wrong = sealing.generate_enc_keypair(tmp_path / "wrong")
    with pytest.raises(Exception):  # AEAD tag failure
        sealing.unseal_bundle(sealed, wrong)


def test_enc_public_key_binds_in_attestation(tmp_path):
    key = signing.generate_keypair(tmp_path / "k")
    enc_pub = sealing.load_enc_public_key_b64(tmp_path / "enc") or \
        (sealing.generate_enc_keypair(tmp_path / "enc") and sealing.load_enc_public_key_b64(tmp_path / "enc"))
    att = signing.build_attestation("seal-host", key, valid_from="2026-07-12T00:00:00Z",
                                    enc_public_key=enc_pub)
    assert att["enc_public_key"] == enc_pub
    assert signing.verify_attestation(att)  # signature covers enc_public_key
    # tampering the sealing key breaks the self-signature
    att["enc_public_key"] = "A" * 43 + "="
    assert not signing.verify_attestation(att)


def test_no_enc_key_is_byte_identical(tmp_path):
    # omit-when-empty: an attestation without enc_public_key is unchanged
    key = signing.generate_keypair(tmp_path / "k")
    a = signing.build_attestation("h", key, valid_from="2026-07-12T00:00:00Z")
    assert "enc_public_key" not in a
    assert signing.verify_attestation(a)
