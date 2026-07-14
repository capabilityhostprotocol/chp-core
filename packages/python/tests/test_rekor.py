"""Rekor transparency-log anchor (chp-v0.2.md §12, proposal 0033). A bundle → DSSE →
submitted to a transparency log; the returned RFC 6962 inclusion proof + SET fold into
a store-head-anchor (anchor.type="rekor") that a stranger verifies OFFLINE against the
log's pinned public key. Exercised against a LOCAL structurally-real log — a real
ECDSA-P256 log key, a real merkle tree, a real SET — so the whole verifier runs with no
network + no permanent external footprint (a real Rekor submission is user-gated)."""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("cryptography")

from chp_core import (CapabilityDescriptor, LocalCapabilityHost,  # noqa: E402
                      SQLiteEvidenceStore, signing)
from chp_core import merkle, rekor  # noqa: E402


def _signed_bundle(tmp_path):
    host = LocalCapabilityHost("rk-host", store=SQLiteEvidenceStore(":memory:"))

    async def h(_c, p):
        return {"echo": p}

    host.register(CapabilityDescriptor(id="r.cap", version="1.0.0", description="."), h)
    asyncio.run(host.ainvoke("r.cap", {"x": 1}, correlation={"correlation_id": "rk"}))
    key = signing.generate_keypair(tmp_path / "k")
    events = host.store.export_correlation("rk")
    bundle = signing.sign_bundle(
        signing.build_bundle("rk-host", events, created_at="2026-07-13T00:00:00Z"), key)
    return bundle, key


class _LocalRekorLog:
    """A minimal but STRUCTURALLY-REAL Rekor log: an ECDSA-P256 key signs the SET,
    a real RFC 6962 tree (merkle) yields the inclusion proof. Byte-compatible with
    the fields rekor.verify_rekor_anchor checks."""

    def __init__(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.log_id = "a" * 64

    def post(self, _url: str, entry_body: dict) -> dict:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        body_bytes = json.dumps(entry_body).encode()
        # place our entry among decoys so the audit path is non-trivial (index 1 of 3)
        leaves = [b"decoy-0", body_bytes, b"decoy-2"]
        index, size = 1, len(leaves)
        root = merkle.merkle_root(leaves)
        path = merkle.inclusion_proof(leaves, index)
        body_b64 = base64.b64encode(body_bytes).decode()
        integrated_time, log_index = 1_700_000_000, 42
        set_msg = rekor.set_message({"entry_body": body_b64, "integrated_time": integrated_time,
                                     "log_id": self.log_id, "log_index": log_index})
        set_sig = self._key.sign(set_msg, ec.ECDSA(hashes.SHA256()))
        return {"uuid-xyz": {
            "body": body_b64, "logID": self.log_id, "logIndex": log_index,
            "integratedTime": integrated_time,
            "verification": {
                "signedEntryTimestamp": base64.b64encode(set_sig).decode(),
                "inclusionProof": {
                    "logIndex": index, "treeSize": size,
                    "rootHash": root.hex(),
                    "hashes": [h.hex() for h in path],
                },
            },
        }}


def test_rekor_anchor_verifies_offline(tmp_path):
    bundle, key = _signed_bundle(tmp_path)
    log = _LocalRekorLog()
    response = rekor.submit_bundle(bundle, key, rekor_url="http://local",
                                   http_post=log.post)
    anchor = rekor.rekor_anchor_from_response(
        bundle, key, response, host_id="rk-host", sequence=1,
        anchored_at="2026-07-13T01:00:00Z")
    assert anchor["anchor"]["type"] == "rekor"
    assert anchor["store_head"] == bundle["root_hash"]

    v = rekor.verify_rekor_anchor(anchor, log_public_key_pem=log.public_key_pem)
    assert v.valid, (v.reason, v.checks)
    assert v.checks == {"structure": True, "inclusion": True, "set": True,
                        "entry_binds_dsse": True, "root": True}


def test_dispatch_via_verify_store_head_anchor(tmp_path):
    bundle, key = _signed_bundle(tmp_path)
    log = _LocalRekorLog()
    response = rekor.submit_bundle(bundle, key, rekor_url="http://local", http_post=log.post)
    anchor = rekor.rekor_anchor_from_response(bundle, key, response, host_id="rk-host",
                                              sequence=1, anchored_at="t")
    # the generic anchor verifier dispatches rekor anchors to the rekor path
    assert signing.verify_store_head_anchor(
        anchor, rekor_log_public_key_pem=log.public_key_pem).valid
    # without the pinned key, a rekor anchor cannot be verified
    assert not signing.verify_store_head_anchor(anchor).valid


def test_tamper_breaks_each_check(tmp_path):
    bundle, key = _signed_bundle(tmp_path)
    log = _LocalRekorLog()
    response = rekor.submit_bundle(bundle, key, rekor_url="http://local", http_post=log.post)
    anchor = rekor.rekor_anchor_from_response(bundle, key, response, host_id="rk-host",
                                              sequence=1, anchored_at="t")
    # a wrong log key fails the SET
    other = _LocalRekorLog()
    assert not rekor.verify_rekor_anchor(anchor, log_public_key_pem=other.public_key_pem).checks["set"]
    # a tampered store_head breaks the root binding
    bad = json.loads(json.dumps(anchor))
    bad["store_head"] = "f" * 64
    assert not rekor.verify_rekor_anchor(bad, log_public_key_pem=log.public_key_pem).checks["root"]
    # a tampered inclusion hash breaks inclusion
    bad2 = json.loads(json.dumps(anchor))
    bad2["anchor"]["inclusion_hashes"] = ["0" * 64]
    assert not rekor.verify_rekor_anchor(bad2, log_public_key_pem=log.public_key_pem).checks["inclusion"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider", "--no-cov"]))
