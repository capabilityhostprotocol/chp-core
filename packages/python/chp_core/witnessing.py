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


def compute_root(leaves: dict) -> str:
    """chp-store-head-v1 over a leaves mapping (correlation_id -> head hash)."""
    digest = hashlib.sha256()
    for correlation_id in sorted(leaves):
        digest.update(f"{correlation_id}\x00{leaves[correlation_id] or ''}\n".encode())
    return digest.hexdigest()


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

    # The snapshot must recompute to the SIGNED root — else the snapshot
    # itself was doctored and per-leaf dispositions would be meaningless.
    snapshot_valid = compute_root(snapshot) == statement.get("store_head")
    result["snapshot_valid"] = snapshot_valid
    if not snapshot_valid:
        result["verdict"] = "snapshot_invalid"
        return result

    # AUDIT-GRADE recompute: never the maintained cache — a store editor
    # could have edited correlation_heads too. Raw events only.
    current = store.get_store_head(at_sequence=int(sequence), fresh=True)["leaves"]
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
