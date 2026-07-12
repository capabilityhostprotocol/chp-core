"""Witness receipt persistence + store-side verification (chp-v0.2.md §12).

Witness records NEVER enter the evidence store — appending one would draw a
global sequence and move the very head being witnessed. They live in sidecar
files under ``~/.chp/witnesses/`` (the ``key_history.json``/``revocations.json``
precedent):

- ``received.json`` — statements OTHER peers signed over THIS host's head,
  each persisted **with a leaves snapshot** taken at the witnessed sequence.
  The signed root makes the snapshot tamper-evident, and the snapshot is what
  lets verification distinguish lawful retention from tampering per-leaf.
- ``issued/<host_id>.json`` — statements THIS host signed over a peer's head
  (rolling window). Their value is location: the witnessed operator cannot
  delete records held by the witness.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .types import JSON

# Rolling window of issued statements kept per witnessed host.
ISSUED_WINDOW = 50


def witness_dir() -> Path:
    override = os.environ.get("CHP_WITNESS_DIR")
    return Path(override) if override else Path.home() / ".chp" / "witnesses"


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def record_received(statement: JSON, leaves: dict,
                    revocations: list | None = None) -> None:
    """Persist a verified received witness statement WITH the leaves snapshot
    at its sequence (caller has already verified signature + head match). When
    the statement countersigns a ``revocation_head`` (proposal 0010), the held
    revocation-identifier set is snapshotted too, so the freshness audit can
    recompute the digest and detect a dropped revocation."""
    path = witness_dir() / "received.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    receipts = _load_json(path, [])
    receipt: JSON = {"statement": statement, "leaves": leaves}
    if revocations is not None:
        receipt["revocations"] = revocations
    receipts.append(receipt)
    path.write_text(json.dumps(receipts, indent=2, sort_keys=True) + "\n")


def load_received() -> list[JSON]:
    return _load_json(witness_dir() / "received.json", [])


def evaluate_witness_quorum(statements: list[JSON], *, host_id: str, sequence: int,
                            store_head: str, k: int,
                            witness_set: list | None = None) -> JSON:
    """Witness quorum (chp-v0.2.md §12, proposal 0013): the anti-collusion proof
    over a collected set of ``chain-witness`` statements. Verify each, keep only
    those over the EXACT ``(host_id, sequence, store_head)``, DEDUPE by the
    witness's ``signature.key_id`` (a witness re-submitting counts once — quorum
    measures distinct identities, not statement volume), optionally restrict to
    an allowed ``witness_set`` (the *n*), and count. Verdict ``quorum_met`` when
    distinct ≥ ``k``, else ``quorum_short``."""
    from .signing import verify_chain_witness  # noqa: PLC0415

    allowed = set(witness_set) if witness_set is not None else None
    distinct: dict[str, str] = {}  # witness key_id -> witness host_id
    for stmt in statements:
        if (stmt.get("host_id") != host_id
                or stmt.get("sequence") != sequence
                or stmt.get("store_head") != store_head):
            continue  # a valid statement over a different head does not count
        if not verify_chain_witness(stmt, expected_host_id=host_id).valid:
            continue
        key_id = str((stmt.get("signature") or {}).get("key_id") or "")
        if not key_id or (allowed is not None and key_id not in allowed):
            continue
        distinct.setdefault(key_id, str((stmt.get("witness") or {}).get("host_id") or ""))
    met = len(distinct) >= k
    return {"verdict": "quorum_met" if met else "quorum_short",
            "k": k, "distinct": len(distinct), "witnesses": sorted(distinct),
            "host_id": host_id, "sequence": sequence, "store_head": store_head}


def record_anchor(statement: JSON) -> None:
    """Persist an external store-head anchor (§12 External anchoring, 0013) —
    sidecar serving state like witness receipts, never hashed into the chain."""
    path = witness_dir() / "anchors.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    anchors = _load_json(path, [])
    anchors.append(statement)
    path.write_text(json.dumps(anchors, indent=2, sort_keys=True) + "\n")


def load_anchors() -> list[JSON]:
    return _load_json(witness_dir() / "anchors.json", [])


def record_issued(statement: JSON) -> None:
    """Keep the statements this host signed over a peer's head (rolling)."""
    host_id = str(statement.get("host_id") or "unknown")
    path = witness_dir() / "issued" / f"{host_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    issued = _load_json(path, [])
    issued.append(statement)
    path.write_text(json.dumps(issued[-ISSUED_WINDOW:], indent=2, sort_keys=True) + "\n")


def load_issued(host_id: str) -> list[JSON]:
    return _load_json(witness_dir() / "issued" / f"{host_id}.json", [])


def latest_issued_at() -> str | None:
    """The newest witnessed_at across every issued record — the operator's
    'is the witness loop alive?' signal (/metrics)."""
    issued_dir = witness_dir() / "issued"
    if not issued_dir.exists():
        return None
    newest: str | None = None
    for path in issued_dir.glob("*.json"):
        for stmt in _load_json(path, []):
            at = stmt.get("witnessed_at")
            if isinstance(at, str) and (newest is None or at > newest):
                newest = at
    return newest


def compute_root(leaves: dict, scheme: str | None = None) -> str:
    """A store-head root over a leaves mapping. Defaults to chp-store-head-v1
    (byte-identical) — a v2 Merkle root is available via ``scheme``. Delegates to
    the single dispatcher so every recompute site agrees."""
    from .merkle import CHP_STORE_HEAD_V1, store_head_root  # noqa: PLC0415
    return store_head_root(scheme or CHP_STORE_HEAD_V1, leaves)


def audit_completeness(bundle: JSON, receipts: list[JSON]) -> JSON:
    """Non-omission audit (§12, proposal 0018): check a bundle's `completeness`
    claim against witnessed store-head receipts. For each receipt carrying a
    `leaves` snapshot, verify the witness statement, recompute `store_head` from
    the snapshot and require it equals the peer-signed value (tamper-evidence).
    Then, because the per-correlation chain is APPEND-ONLY:

    - a witnessed head at ``sequence >= as_of_sequence`` whose ``leaves[X]``
      equals ``head_hash`` → **complete** (a witness countersigned this exact tail
      at/after the claimed point);
    - a witnessed head at ``sequence >= as_of_sequence`` whose ``leaves[X]``
      DIFFERS → **incomplete** (the witnessed tail at/after the claim is not the
      one the bundle shows — a dropped tail; the per-correlation chain is
      append-only, so the leaf only moves forward);
    - no witnessed head covers X at/after the claim → **unwitnessed** (the honest
      boundary: recording itself cannot be forced).
    """
    from .signing import verify_chain_witness  # noqa: PLC0415

    claim = bundle.get("completeness")
    if not claim:
        return {"verdict": "no_claim"}
    corr = claim.get("correlation_id")
    as_of = claim.get("as_of_sequence")
    head_hash = claim.get("head_hash")

    confirmed_at: int | None = None   # highest witnessed sequence proving the tail
    advanced_at: int | None = None    # lowest witnessed sequence past as_of that moved the leaf
    snapshot_invalid: list[str] = []
    witnessed_seqs: list[int] = []
    for receipt in receipts:
        leaves = receipt.get("leaves")
        stmt = receipt.get("statement") or {}
        signed = stmt.get("store_head")
        seq = stmt.get("sequence")
        if leaves is None or signed is None or seq is None:
            continue
        if not verify_chain_witness(stmt).valid:
            continue  # only validly-witnessed heads count
        # Tamper check under whichever store-head scheme the signed root selects
        # (v1 fold or v2 Merkle — self-validating, §12 proposal 0019).
        from .merkle import store_head_scheme_matching  # noqa: PLC0415
        if store_head_scheme_matching(leaves, signed) is None:
            snapshot_invalid.append(str(seq))
            continue
        if corr not in leaves:
            continue  # this head did not witness the correlation
        witnessed_seqs.append(seq)
        leaf = leaves[corr]
        if seq >= as_of:
            if leaf == head_hash:
                confirmed_at = seq if confirmed_at is None else max(confirmed_at, seq)
            else:  # a witnessed tail at/after the claim that isn't the claimed one
                advanced_at = seq if advanced_at is None else min(advanced_at, seq)

    if snapshot_invalid:
        verdict = "snapshot_invalid"
    elif advanced_at is not None:
        verdict = "incomplete"
    elif confirmed_at is not None:
        verdict = "complete"
    else:
        verdict = "unwitnessed"
    return {"verdict": verdict, "correlation_id": corr, "as_of_sequence": as_of,
            "head_hash": head_hash, "confirmed_at": confirmed_at,
            "advanced_at": advanced_at, "snapshot_invalid": snapshot_invalid,
            "witnessed_sequences": sorted(witnessed_seqs)}


def audit_completeness_via_anchor(bundle: JSON, anchor: JSON, inclusion_proof: JSON) -> JSON:
    """Third-party, witness-free non-omission (§12, proposal 0019). A relying
    party holding only a bundle's completeness claim, an externally-anchored
    chp-store-head-v2 root, and an RFC 6962 inclusion proof — NO leaves snapshot,
    NO witness — proves the correlation's committed tail. The inclusion proof
    binds the ACTUAL anchored tail: a host that truncated its bundle cannot
    produce a proof for the truncated tail (it is not in the tree), so the
    anchored tail differs → `incomplete`.
    """
    from .signing import verify_store_head_anchor  # noqa: PLC0415
    from .merkle import verify_store_head_inclusion  # noqa: PLC0415

    claim = bundle.get("completeness")
    if not claim:
        return {"verdict": "no_claim"}
    corr = claim.get("correlation_id")
    as_of = claim.get("as_of_sequence")
    head_hash = claim.get("head_hash")

    if not verify_store_head_anchor(anchor).valid:
        return {"verdict": "anchor_invalid", "correlation_id": corr}
    root = str(anchor.get("store_head"))
    seq = anchor.get("sequence")
    anchored_tail = inclusion_proof.get("head_hash")
    # The proof must genuinely commit (corr, anchored_tail) under the anchored root.
    if inclusion_proof.get("correlation_id") != corr \
            or not verify_store_head_inclusion(root, corr, anchored_tail, inclusion_proof):
        return {"verdict": "proof_invalid", "correlation_id": corr}
    if seq is None or as_of is None or seq < as_of:
        return {"verdict": "unwitnessed", "correlation_id": corr, "anchored_at_sequence": seq}
    verdict = "complete" if anchored_tail == head_hash else "incomplete"
    return {"verdict": verdict, "correlation_id": corr, "as_of_sequence": as_of,
            "anchored_at_sequence": seq, "head_hash": head_hash,
            "anchored_tail": anchored_tail}


def verify_receipt_against_store(store, receipt: JSON) -> JSON:
    """The auditor act (§12): recompute the store head as-of the witnessed
    sequence and judge every leaf. Lawful retention and tampering are
    distinguishable:

    - leaf matches            → ``verified``
    - correlation absent      → ``purged``   (legal — purge deletes whole correlations)
    - head hash now NULL      → ``redacted`` (legal — redaction can only NULL, never forge)
    - head hash differs       → ``tampered``
    - store correlation at ≤N missing from the snapshot → ``tampered`` (inserted history)

    Returns {statement_valid, snapshot_valid, sequence, dispositions,
    tampered_correlations, verdict}."""
    from .signing import verify_chain_witness

    statement = receipt.get("statement") or {}
    snapshot: dict = receipt.get("leaves") or {}
    sv = verify_chain_witness(statement)
    sequence = statement.get("sequence")
    result: JSON = {
        "statement_valid": sv.valid,
        "sequence": sequence,
        "witness": (statement.get("witness") or {}).get("host_id"),
    }
    if not sv.valid:
        result.update({"snapshot_valid": False, "verdict": "invalid_statement",
                       "reason": sv.reason})
        return result

    # The snapshot must recompute to the SIGNED root under some known store-head
    # scheme (v1 fold or v2 Merkle — self-validating, §12 proposal 0019) — else
    # the snapshot itself was doctored and per-leaf dispositions are meaningless.
    from .merkle import store_head_scheme_matching  # noqa: PLC0415
    snapshot_valid = store_head_scheme_matching(snapshot, str(statement.get("store_head"))) is not None
    result["snapshot_valid"] = snapshot_valid
    if not snapshot_valid:
        result["verdict"] = "snapshot_invalid"
        return result

    # AUDIT-GRADE recompute: never the maintained cache — a store editor
    # could have edited correlation_heads too. Raw events only.
    current = store.get_store_head(at_sequence=int(sequence or 0), fresh=True)["leaves"]
    dispositions = {"verified": 0, "purged": 0, "redacted": 0, "tampered": 0}
    tampered: list[str] = []
    for correlation_id, witnessed_hash in snapshot.items():
        if correlation_id not in current:
            dispositions["purged"] += 1
        elif current[correlation_id] is None and witnessed_hash is not None:
            dispositions["redacted"] += 1
        elif current[correlation_id] == witnessed_hash:
            dispositions["verified"] += 1
        else:
            dispositions["tampered"] += 1
            tampered.append(correlation_id)
    for correlation_id in current:
        if correlation_id not in snapshot:
            dispositions["tampered"] += 1
            tampered.append(correlation_id)

    result["dispositions"] = dispositions
    result["tampered_correlations"] = tampered
    result["verdict"] = "tampered" if tampered else "intact"
    return result


def monitor_anchor_history(store, anchors: list[JSON], *, host_id: str,
                           monitor_key, monitor_id: str, monitored_at: str,
                           monitor_anchors: list[JSON] | None = None) -> JSON:
    """Walk a host's store-head-anchor history in ``sequence`` order and check the
    live store against each immutable external anchor (§12, proposal 0023). For
    each anchor ``(N, R, scheme)`` reconstruct the head as-of N from the live
    events — ``get_store_head(at_sequence=N, fresh=True, scheme=scheme)``, the
    audit path that never trusts the cache — and compare to the anchored ``R``. The
    first anchor whose reconstruction diverges is a provable REWRITE (an edited or
    dropped old event moves every root ≥ its sequence, but the anchor is
    immutable). Returns a signed ``store-head-monitor-report``: ``forked`` at that
    sequence, else ``consistent`` through the highest sequence. ``monitor_anchors``
    are the MONITOR's own identity anchors (for its attestation), distinct from the
    monitored host's history being checked."""
    from .merkle import CHP_STORE_HEAD_V1
    from .signing import build_store_head_monitor_report

    ordered = sorted(anchors, key=lambda a: int(a.get("sequence", 0)))
    last_good = 0
    for a in ordered:
        seq = int(a.get("sequence", 0))
        anchored_root = str(a.get("store_head", ""))
        scheme = a.get("store_head_scheme") or CHP_STORE_HEAD_V1
        reconstructed = store.get_store_head(
            at_sequence=seq, fresh=True, scheme=scheme)["store_head"]
        if reconstructed != anchored_root:
            return build_store_head_monitor_report(
                host_id, verdict="forked", verified_through_sequence=last_good,
                anchor_count=len(ordered), monitor_key=monitor_key,
                monitor_id=monitor_id, monitored_at=monitored_at,
                anchors=monitor_anchors,
                divergence={"sequence": seq, "anchored_root": anchored_root,
                            "reconstructed_root": reconstructed})
        last_good = seq
    return build_store_head_monitor_report(
        host_id, verdict="consistent", verified_through_sequence=last_good,
        anchor_count=len(ordered), monitor_key=monitor_key, monitor_id=monitor_id,
        monitored_at=monitored_at, anchors=monitor_anchors)
