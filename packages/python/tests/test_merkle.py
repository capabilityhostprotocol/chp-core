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


# ── Consistency proofs (proposal 0022) ───────────────────────────────────────


def test_consistency_recomputes_both_roots_for_every_m_le_n():
    for n in range(1, 10):
        leaves = [f"L{i}".encode() for i in range(n)]
        new_root = merkle.merkle_root(leaves)
        for m in range(0, n + 1):
            old_root = merkle.merkle_root(leaves[:m]) if m else hashlib.sha256(b"").digest()
            proof = merkle.consistency_proof(leaves, m)
            assert merkle.verify_consistency(old_root, new_root, m, n, proof), (m, n)


def test_consistency_rejects_a_rewritten_or_dropped_old_leaf():
    leaves = [f"L{i}".encode() for i in range(7)]
    new_root = merkle.merkle_root(leaves)
    proof = merkle.consistency_proof(leaves, 4)          # first 4 are "old"
    good_old = merkle.merkle_root(leaves[:4])
    assert merkle.verify_consistency(good_old, new_root, 4, 7, proof)
    # An old root over a rewritten prefix no longer matches the proof.
    forged = merkle.merkle_root(leaves[:3] + [b"REWRITTEN"])
    assert not merkle.verify_consistency(forged, new_root, 4, 7, proof)
    # A tampered proof entry fails.
    bad = list(proof); bad[0] = b"\x00" * 32
    assert not merkle.verify_consistency(good_old, new_root, 4, 7, bad)


def test_consistency_empty_and_identity_proofs():
    leaves = [b"a", b"b", b"c"]
    root = merkle.merkle_root(leaves)
    empty = hashlib.sha256(b"").digest()
    # m == 0: the empty tree extends into anything, empty proof.
    assert merkle.consistency_proof(leaves, 0) == []
    assert merkle.verify_consistency(empty, root, 0, 3, [])
    # m == n: same tree, empty proof, roots must match.
    assert merkle.consistency_proof(leaves, 3) == []
    assert merkle.verify_consistency(root, root, 3, 3, [])
    assert not merkle.verify_consistency(root, b"\x00" * 32, 3, 3, [])


def test_store_head_consistency_append_only():
    old = {"c1": "a" * 64, "c2": "b" * 64}
    new = {"c1": "a" * 64, "c2": "b" * 64, "c3": "c" * 64, "c4": "d" * 64}
    proof = merkle.store_head_consistency_proof(old, new)
    old_root = merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, old)
    new_root = merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, new)
    assert proof["first_root"] == old_root and proof["second_root"] == new_root
    assert merkle.verify_store_head_consistency(old_root, new_root, proof)
    # A later head that ALTERED an old correlation's head_hash is caught: its true
    # v2 root differs from the proof's first_root, so a stranger's check fails.
    tampered = {"c1": "a" * 64, "c2": "Z" * 64, "c3": "c" * 64, "c4": "d" * 64}
    tampered_root = merkle.store_head_root(merkle.CHP_STORE_HEAD_V2, tampered)
    assert not merkle.verify_store_head_consistency(old_root, tampered_root, proof)
    # Wrong carried root (anchor mismatch) fails.
    assert not merkle.verify_store_head_consistency("0" * 64, new_root, proof)
