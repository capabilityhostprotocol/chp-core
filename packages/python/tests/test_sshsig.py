"""Tests for SSHSIG verification + did:key codec — the `did` anchor (§3.1)."""

from __future__ import annotations

import json
from pathlib import Path

from chp_core import signing, sshsig

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "test-vectors"


def _did_bundle() -> dict:
    return json.loads((VECTORS / "did-anchored-bundle.json").read_text())


def test_did_key_codec_roundtrip():
    bundle = _did_bundle()
    did = bundle["host_identity"]["anchors"][0]["did"]
    raw = sshsig.did_key_to_raw(did)
    assert len(raw) == 32
    assert sshsig.raw_to_did_key(raw) == did
    # the Radicle fixture DID from the adapter tests decodes too
    rad_fixture = "did:key:z6MkuyYxVQL4aRVpAKPbG4tc15FJ9E1ryZSSHjFyqsBBuxAn"
    assert len(sshsig.did_key_to_raw(rad_fixture)) == 32


def test_sshsig_verifies_published_countersignature():
    bundle = _did_bundle()
    anchor = bundle["host_identity"]["anchors"][0]
    message = signing.did_anchor_message(bundle["public_key"], bundle["host_id"])
    raw_pub = sshsig.did_key_to_raw(anchor["did"])
    assert sshsig.verify_sshsig(anchor["countersignature"], message,
                                expected_raw_pubkey=raw_pub)
    # wrong message → fail
    assert not sshsig.verify_sshsig(anchor["countersignature"], b"other message",
                                    expected_raw_pubkey=raw_pub)
    # wrong signer pin → fail
    assert not sshsig.verify_sshsig(anchor["countersignature"], message,
                                    expected_raw_pubkey=b"\x00" * 32)
    # wrong namespace → fail
    assert not sshsig.verify_sshsig(anchor["countersignature"], message,
                                    namespace="other-ns", expected_raw_pubkey=raw_pub)


def test_did_anchored_bundle_verifies_offline():
    v = signing.verify_bundle(_did_bundle())
    assert v.valid
    assert v.checks["did_anchor"] is True
    assert v.anchored_did and v.anchored_did.startswith("did:key:z6Mk")


def test_did_anchor_forgery_fails():
    bundle = _did_bundle()
    # A different DID claiming the countersignature: did_anchor fails (signer pin)
    # AND host_identity fails (the anchor is inside the signed claim).
    forged = json.loads(json.dumps(bundle))
    forged["host_identity"]["anchors"][0]["did"] = (
        "did:key:z6MkuyYxVQL4aRVpAKPbG4tc15FJ9E1ryZSSHjFyqsBBuxAn")
    v = signing.verify_bundle(forged)
    assert not v.valid
    assert v.checks["host_identity"] is False  # claim bytes changed
    assert v.checks["did_anchor"] is False     # countersig not by that DID
    assert v.anchored_did is None
