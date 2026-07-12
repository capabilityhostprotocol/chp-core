"""RFC 6962 (Certificate Transparency) Merkle tree — the `chp-store-head-v2`
construction (proposal 0019).

Domain-separated and second-preimage-safe: leaf hash ``SHA256(0x00 ‖ data)``,
interior node ``SHA256(0x01 ‖ left ‖ right)``, odd sizes split at the largest
power of two ``< n`` (RFC 6962 §2.1). It is the audited standard, so a Python, a
TypeScript, and a stdlib implementation compute the identical root and inclusion
proofs — the JCS/RFC-8785 discipline applied to trees.

Functions operate on ``bytes`` leaves; the store-head layer hex-encodes.
``verify_inclusion`` recomputes the root by replaying the SAME recursive split
the proof was built from — provably consistent with ``merkle_root`` /
``inclusion_proof`` rather than the error-prone fn/sn bit walk.
"""

from __future__ import annotations

import hashlib
from typing import Iterator


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two strictly less than n (RFC 6962 §2.1; n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over the ordered leaf byte-strings."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _split(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """RFC 6962 §2.1.1 audit path for leaf ``index`` — sibling subtree roots,
    ordered bottom-up (the leaf's immediate sibling first, the top sibling last)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} out of range for {n} leaves")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def _walk(size: int, index: int, path: Iterator[bytes], leaf: bytes) -> bytes:
    if size == 1:
        return leaf
    k = _split(size)
    if index < k:
        left = _walk(k, index, path, leaf)
        return _node_hash(left, next(path))          # sibling = right subtree
    right = _walk(size - k, index - k, path, leaf)
    return _node_hash(next(path), right)             # sibling = left subtree


def verify_inclusion(root: bytes, leaf_data: bytes, index: int,
                     tree_size: int, audit_path: list[bytes]) -> bool:
    """True iff ``leaf_data`` at ``index`` is committed under ``root`` given
    ``audit_path`` (RFC 6962). Recomputes by replaying the build's split, so it
    is exactly the inverse of ``inclusion_proof``. All path entries must be
    consumed (a too-long or too-short path fails)."""
    if not 0 <= index < tree_size:
        return False
    it: Iterator[bytes] = iter(audit_path)
    try:
        computed = _walk(tree_size, index, it, _leaf_hash(leaf_data))
    except StopIteration:
        return False
    if next(it, None) is not None:
        return False  # leftover path entries
    return computed == root


# ── Consistency proofs (RFC 6962 §2.1.2, proposal 0022) ─────────────────────
# Prove a later tree (size n) is an append-only extension of an earlier one
# (size m ≤ n): a minimal set of subtree hashes from which BOTH roots recompute.
# Like inclusion, we replay the prover's recursive split rather than the fn/sn
# bit walk, so verify is exactly the inverse of the build.


def consistency_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """RFC 6962 §2.1.2 consistency proof between the first ``m`` leaves and the
    full tree (``n = len(leaves)``, ``0 <= m <= n``). ``PROOF(m, D[0:n]) =
    SUBPROOF(m, D[0:n], true)``; the top ``b=true`` omits the old root (the
    verifier already holds it). Empty when ``m == 0`` or ``m == n``."""
    n = len(leaves)
    if not 0 <= m <= n:
        raise ValueError(f"consistency: need 0 <= m({m}) <= n({n})")
    if m == 0 or m == n:
        return []
    return _subproof(m, leaves, True)


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        # A complete subtree: omit its root when the verifier already has it (b),
        # else hand it over.
        return [] if b else [merkle_root(leaves)]
    k = _split(n)
    if m <= k:
        # The old tree lives entirely in the left subtree; the right is new.
        return _subproof(m, leaves[:k], b) + [merkle_root(leaves[k:])]
    # m > k: the left subtree is wholly old; recurse into the right (now b=False).
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def _consistency_walk(m: int, n: int, b: bool, path: Iterator[bytes],
                      first_root: bytes) -> tuple[bytes, bytes]:
    """Replay SUBPROOF(m, D[0:n], b), returning (old_root@m, new_root@n). At the
    ``m == n`` base the old root is either the verifier-known ``first_root``
    (b=true, omitted from the proof) or the next path entry (b=false)."""
    if m == n:
        if b:
            return first_root, first_root
        h = next(path)
        return h, h
    k = _split(n)
    if m <= k:
        old, new_left = _consistency_walk(m, k, b, path, first_root)
        right = next(path)                       # MTH(D[k:n]) — the new right subtree
        return old, _node_hash(new_left, right)
    old_right, new_right = _consistency_walk(m - k, n - k, False, path, first_root)
    left = next(path)                            # MTH(D[0:k]) — shared left subtree
    return _node_hash(left, old_right), _node_hash(left, new_right)


def verify_consistency(first_root: bytes, second_root: bytes, m: int, n: int,
                       proof: list[bytes]) -> bool:
    """True iff a tree of size ``n`` with root ``second_root`` is an append-only
    extension of a tree of size ``m`` with root ``first_root``, given ``proof``
    (RFC 6962 §2.1.2). Recomputes BOTH roots by replaying the build's split; all
    path entries must be consumed. ``m == 0`` (extend the empty tree) and
    ``m == n`` (same tree) take an empty proof."""
    if not 0 <= m <= n:
        return False
    if m == 0:
        return proof == []                       # empty tree extends into anything
    if m == n:
        return proof == [] and first_root == second_root
    it: Iterator[bytes] = iter(proof)
    try:
        old, new = _consistency_walk(m, n, True, it, first_root)
    except StopIteration:
        return False
    if next(it, None) is not None:
        return False                             # leftover path entries
    return old == first_root and new == second_root


# ── Store-head schemes (chp-v0.2.md §12) ────────────────────────────────────
# v1 = the flat SHA-256 fold; v2 = the RFC 6962 Merkle root (proposal 0019). One
# dispatcher so every recompute site agrees; raises on an unknown scheme (the §2
# canonicalization-dispatch pattern). The per-leaf bytes are identical in both.

CHP_STORE_HEAD_V1 = "chp-store-head-v1"
CHP_STORE_HEAD_V2 = "chp-store-head-v2"


def store_head_leaf(correlation_id: str, head_hash: str | None) -> bytes:
    """The per-correlation leaf bytes (identical under v1 and v2)."""
    return f"{correlation_id}\x00{head_hash or ''}\n".encode()


def store_head_root(scheme: str, leaves: dict) -> str:
    """The store-head root over ``{correlation_id: head_hash}``, hex. v1 folds;
    v2 builds the RFC 6962 Merkle root. Raises ``ValueError`` on an unknown
    scheme — a recompute under the wrong scheme cannot equal a signed root."""
    ordered = sorted(leaves)
    if scheme == CHP_STORE_HEAD_V1:
        h = hashlib.sha256()
        for cid in ordered:
            h.update(store_head_leaf(cid, leaves[cid]))
        return h.hexdigest()
    if scheme == CHP_STORE_HEAD_V2:
        return merkle_root([store_head_leaf(cid, leaves[cid]) for cid in ordered]).hex()
    raise ValueError(f"unknown store-head scheme: {scheme!r}")


def store_head_scheme_matching(leaves: dict, signed_root: str) -> str | None:
    """The store-head scheme whose recompute of ``leaves`` equals ``signed_root``,
    or None (tamper). Self-validating: because the signed root selects the scheme,
    a witness receipt need not carry the scheme — the witness header stays
    byte-identical for v1, and the audit tries each known scheme."""
    for scheme in (CHP_STORE_HEAD_V1, CHP_STORE_HEAD_V2):
        if store_head_root(scheme, leaves) == signed_root:
            return scheme
    return None


def store_head_inclusion_proof(leaves: dict, correlation_id: str) -> dict:
    """An RFC 6962 inclusion proof (chp-store-head-v2) that ``correlation_id``'s
    leaf is committed under the Merkle root — the `store-head-inclusion` object."""
    ordered = sorted(leaves)
    if correlation_id not in leaves:
        raise KeyError(correlation_id)
    index = ordered.index(correlation_id)
    leaf_bytes = [store_head_leaf(cid, leaves[cid]) for cid in ordered]
    path = inclusion_proof(leaf_bytes, index)
    return {
        "scheme": CHP_STORE_HEAD_V2,
        "correlation_id": correlation_id,
        "head_hash": leaves[correlation_id],
        "leaf_index": index,
        "tree_size": len(ordered),
        "audit_path": [p.hex() for p in path],
    }


def verify_store_head_inclusion(root: str, correlation_id: str,
                                head_hash: str | None, proof: dict) -> bool:
    """Third-party, witness-free (§12, proposal 0019): recompute the Merkle root
    from a single correlation's leaf up ``proof.audit_path`` and check it equals
    the signed/anchored ``root`` — with NO leaves snapshot. The proof binds the
    leaf bytes, so a forged head_hash or wrong correlation_id fails."""
    if proof.get("scheme") != CHP_STORE_HEAD_V2:
        return False
    if proof.get("correlation_id") != correlation_id or proof.get("head_hash") != head_hash:
        return False
    try:
        path = [bytes.fromhex(h) for h in proof.get("audit_path", [])]
        return verify_inclusion(
            bytes.fromhex(root), store_head_leaf(correlation_id, head_hash),
            int(proof["leaf_index"]), int(proof["tree_size"]), path)
    except (ValueError, KeyError, TypeError):
        return False


def store_head_consistency_proof(old_leaves: dict, new_leaves: dict) -> dict:
    """A `store-head-consistency` object proving the ``new_leaves`` store head
    (chp-store-head-v2) is an append-only extension of ``old_leaves``. Requires
    the old leaves to be a sorted prefix of the new ones (every old correlation
    still present with the same head_hash, in sort order) — the caller supplies
    two snapshots; the proof is what a stranger checks against the anchored roots."""
    old_ordered = sorted(old_leaves)
    new_ordered = sorted(new_leaves)
    m, n = len(old_ordered), len(new_ordered)
    new_bytes = [store_head_leaf(cid, new_leaves[cid]) for cid in new_ordered]
    return {
        "scheme": CHP_STORE_HEAD_V2,
        "first_size": m,
        "second_size": n,
        "first_root": store_head_root(CHP_STORE_HEAD_V2, old_leaves),
        "second_root": merkle_root(new_bytes).hex(),
        "proof": [h.hex() for h in consistency_proof(new_bytes, m)],
    }


def verify_store_head_consistency(old_root: str, new_root: str, proof: dict) -> bool:
    """Third-party, witness-free (§12, proposal 0022): from two anchored
    chp-store-head-v2 roots and ``proof``, verify the later log only APPENDED —
    no old correlation dropped, altered, or reordered. The carried roots must
    equal the anchored ``old_root``/``new_root``."""
    if proof.get("scheme") != CHP_STORE_HEAD_V2:
        return False
    if proof.get("first_root") != old_root or proof.get("second_root") != new_root:
        return False
    try:
        path = [bytes.fromhex(h) for h in proof.get("proof", [])]
        return verify_consistency(
            bytes.fromhex(old_root), bytes.fromhex(new_root),
            int(proof["first_size"]), int(proof["second_size"]), path)
    except (ValueError, KeyError, TypeError):
        return False


def _selfcheck() -> None:
    """Assertion-based sanity check (RFC 6962 known-answers + inclusion round
    trips). Runnable: ``python -m chp_core.merkle``."""
    # Empty tree: SHA256 of the empty string (the RFC 6962 fixed point).
    assert merkle_root([]).hex() == \
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # Single leaf: SHA256(0x00 ‖ data).
    assert merkle_root([b"L0"]) == _leaf_hash(b"L0")
    # Two leaves: SHA256(0x01 ‖ leaf(L0) ‖ leaf(L1)).
    assert merkle_root([b"L0", b"L1"]) == _node_hash(_leaf_hash(b"L0"), _leaf_hash(b"L1"))
    # Odd (3) leaves split 2|1 (largest power of two < 3 is 2).
    three = [b"a", b"b", b"c"]
    assert merkle_root(three) == _node_hash(
        _node_hash(_leaf_hash(b"a"), _leaf_hash(b"b")), _leaf_hash(b"c"))
    # Every leaf's inclusion proof round-trips for sizes 1..9; a forged leaf fails.
    for n in range(1, 10):
        leaves = [f"leaf-{i}".encode() for i in range(n)]
        root = merkle_root(leaves)
        for i in range(n):
            proof = inclusion_proof(leaves, i)
            assert verify_inclusion(root, leaves[i], i, n, proof), (n, i)
            assert not verify_inclusion(root, b"FORGED", i, n, proof), (n, i)
            if proof:  # a tampered path fails
                bad = list(proof); bad[0] = b"\x00" * 32
                assert not verify_inclusion(root, leaves[i], i, n, bad), (n, i)
    # Consistency: for every m <= n (n up to 9), the proof recomputes BOTH the
    # size-m and size-n roots; empty proof for m==0 and m==n.
    for n in range(1, 10):
        leaves = [f"leaf-{i}".encode() for i in range(n)]
        new_root = merkle_root(leaves)
        for m in range(0, n + 1):
            old_root = merkle_root(leaves[:m]) if m else hashlib.sha256(b"").digest()
            proof = consistency_proof(leaves, m)
            assert verify_consistency(old_root, new_root, m, n, proof), (m, n)
            if 0 < m < n:
                assert proof, (m, n)  # a real extension needs a non-empty proof
                # A later tree that DROPPED the last old leaf breaks consistency:
                # rebuild an "old" root over a rewritten prefix → recompute ≠ signed.
                forged_old = merkle_root(leaves[:m - 1] + [b"REWRITTEN"])
                assert not verify_consistency(forged_old, new_root, m, n, proof), (m, n)
                # A tampered proof entry fails.
                bad = list(proof); bad[0] = b"\x00" * 32
                assert not verify_consistency(old_root, new_root, m, n, bad), (m, n)
    # A truncated log (later root drops a leaf) is caught: proof for (m, n) cannot
    # validate against a second_root that removed leaves.
    full = [f"c{i}".encode() for i in range(6)]
    truncated_root = merkle_root(full[:5])
    p = consistency_proof(full, 4)
    assert not verify_consistency(merkle_root(full[:4]), truncated_root, 4, 6, p)
    print("merkle self-check OK (RFC 6962 inclusion + consistency)")


if __name__ == "__main__":
    _selfcheck()
