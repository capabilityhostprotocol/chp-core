"""RFC 6962 Merkle tree + chp-store-head-v2 (proposal 0019): third-party
inclusion proofs, and v1 byte-compatibility."""

from __future__ import annotations

import hashlib

import pytest

from chp_core import merkle


def test_rfc6962_selfcheck():
    merkle._selfcheck()  # raises on any failure


def test_v1_store_head_root_is_byte_identical_to_the_flat_fold():
    """The v1 dispatcher MUST reproduce the exact legacy fold (byte gate)."""
    leaves = {"c2": "b" * 64, "c1": "a" * 64, "c3": None}
    h = hashlib.sha256()
    for cid in sorted(leaves):
        h.update(f"{cid}\x00{leaves[cid] or ''}\n".encode())
    assert merkle.store_head_root(merkle.CHP_STORE_HEAD_V1, leaves) == h.hexdigest()


def test_v2_root_differs_and_is_deterministic():
    leaves = {"c1": "a" * 64, "c2": "b" * 64, "c3": "c" * 64}
    v1 = merkle.store_head_root(merkle.CHP_STORE_HEAD_V1, leaves)
    v2 = merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, leaves)
    assert v1 != v2
    assert v2 == merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, dict(reversed(list(leaves.items()))))  # order-independent


def test_unknown_scheme_raises():
    with pytest.raises(ValueError, match="unknown store-head scheme"):
        merkle.store_head_root("chp-store-head-v9", {"c": "x"})


def test_inclusion_proof_verifies_for_every_correlation():
    leaves = {f"corr-{i}": hashlib.sha256(str(i).encode()).hexdigest() for i in range(7)}
    root = merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, leaves)
    for cid, head in leaves.items():
        proof = merkle.store_head_inclusion_proof(leaves, cid)
        assert proof["scheme"] == "chp-store-head-v2" and proof["head_hash"] == head
        assert merkle.verify_store_head_inclusion(root, cid, head, proof)


def test_inclusion_rejects_forged_tail_or_wrong_correlation():
    leaves = {f"corr-{i}": hashlib.sha256(str(i).encode()).hexdigest() for i in range(5)}
    root = merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, leaves)
    proof = merkle.store_head_inclusion_proof(leaves, "corr-2")
    real = leaves["corr-2"]
    # a forged tail for the same correlation fails (the proof binds the leaf bytes)
    assert not merkle.verify_store_head_inclusion(root, "corr-2", "f" * 64, proof)
    # the proof does not transfer to a different correlation
    assert not merkle.verify_store_head_inclusion(root, "corr-3", real, proof)
    # a tampered audit-path node fails
    bad = {**proof, "audit_path": (["0" * 64] + proof["audit_path"][1:]) if proof["audit_path"] else ["0" * 64]}
    assert not merkle.verify_store_head_inclusion(root, "corr-2", real, bad)


def test_scheme_matching_self_validates():
    leaves = {"c1": "a" * 64, "c2": "b" * 64}
    v1_root = merkle.store_head_root(merkle.CHP_STORE_HEAD_V1, leaves)
    v2_root = merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, leaves)
    assert merkle.store_head_scheme_matching(leaves, v1_root) == merkle.CHP_STORE_HEAD_V1
    assert merkle.store_head_scheme_matching(leaves, v2_root) == merkle.CHP_STORE_HEAD_V2
    assert merkle.store_head_scheme_matching(leaves, "0" * 64) is None  # tampered


def test_single_correlation_inclusion():
    leaves = {"only": "a" * 64}
    root = merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, leaves)
    proof = merkle.store_head_inclusion_proof(leaves, "only")
    assert proof["audit_path"] == []  # a one-leaf tree needs no siblings
    assert merkle.verify_store_head_inclusion(root, "only", "a" * 64, proof)
