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
    print("merkle self-check OK (RFC 6962)")


if __name__ == "__main__":
    _selfcheck()
