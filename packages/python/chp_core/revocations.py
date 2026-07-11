"""Mandate-revocation persistence (chp-v0.2.md §10, proposal 0007).

Received mandate revocations are host-runtime state about OTHER principals'
mandates — the ``~/.chp/witnesses/`` precedent, NOT ``<key_dir>/revocations.json``:
that file holds this host's own self-signed KEY revocations and is served
verbatim as ``revoked_keys`` in the identity document; mixing statement kinds
there would corrupt it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .types import JSON


def revocation_dir() -> Path:
    override = os.environ.get("CHP_REVOCATION_DIR")
    return Path(override) if override else Path.home() / ".chp" / "revocations"


def _load_json(path: Path, default: list) -> list:
    if not path.exists():
        return default
    try:
        loaded = json.loads(path.read_text())
        return loaded if isinstance(loaded, list) else default
    except Exception:
        return default


def record_mandate_revocation(statement: JSON) -> None:
    """Persist a verified received revocation (caller has already run
    ``verify_mandate_revocation``). Dedupes on (mandate_id, principal key)."""
    path = revocation_dir() / "mandates.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    revocations = _load_json(path, [])
    key = (statement.get("mandate_id"),
           (statement.get("principal") or {}).get("public_key"))
    if any((r.get("mandate_id"), (r.get("principal") or {}).get("public_key")) == key
           for r in revocations):
        return
    revocations.append(statement)
    path.write_text(json.dumps(revocations, indent=2, sort_keys=True) + "\n")


def load_mandate_revocations() -> list[JSON]:
    return _load_json(revocation_dir() / "mandates.json", [])


# ── Revocation freshness (chp-v0.2.md §12, proposal 0010) ────────────────────
#
# A digest of the held revocation set, bound into the witnessed store head so
# peers countersign "what revocation set this host held at sequence N". Digest
# the IDENTIFIERS (the §10 dedupe keys), never the statements — a re-serialized
# statement must not move the head.


def revocation_ids(mandate_revocations: list[JSON] | None = None,
                   key_revocations: list[JSON] | None = None) -> list[str]:
    """The stable revocation identifiers of the held set: one line per
    revocation, `m\\x00{mandate_id}\\x00{principal.public_key}` for a mandate
    revocation, `k\\x00{revoked_key_id}` for a key revocation. Sorted, deduped —
    the snapshot the witnessed head commits to."""
    ids: set[str] = set()
    for r in mandate_revocations or []:
        mid = str(r.get("mandate_id") or "")
        pub = str((r.get("principal") or {}).get("public_key") or "")
        ids.add(f"m\x00{mid}\x00{pub}")
    for r in key_revocations or []:
        ids.add(f"k\x00{str(r.get('revoked_key_id') or '')}")
    return sorted(ids)


def compute_revocation_head(ids: list[str]) -> str:
    """`chp-revocation-head-v1`: SHA-256 over the sorted revocation-id lines
    (each terminated with `\\n`). An empty set has a well-defined digest — a
    host must be able to prove it knew the empty set."""
    digest = hashlib.sha256()
    for line in sorted(ids):
        digest.update((line + "\n").encode())
    return digest.hexdigest()


def revocation_head(key_dir: str | None = None) -> str:
    """The current `chp-revocation-head-v1` of THIS host's held set (received
    mandate revocations + this host's own key revocations)."""
    from .signing import DEFAULT_KEY_DIR, load_revocations
    try:
        keys = load_revocations(key_dir or DEFAULT_KEY_DIR)
    except Exception:  # noqa: BLE001 — key dir may not exist
        keys = []
    return compute_revocation_head(
        revocation_ids(load_mandate_revocations(), keys))


def audit_revocation_freshness(receipts: list[JSON], current_ids: list[str]) -> JSON:
    """The auditor act (§12 Revocation freshness): for each received witness
    receipt carrying a revocation snapshot, recompute the digest and check it
    equals the peer-signed `revocation_head` (tamper-evidence). Then, because
    the held set is append-only, any identifier present in ANY witnessed
    snapshot but absent from the CURRENT held set is a **dropped** revocation —
    a provable denial of revocation."""
    current = set(current_ids)
    witnessed: set[str] = set()
    snapshot_invalid: list[str] = []
    checked = 0
    for receipt in receipts:
        snapshot = receipt.get("revocations")
        if snapshot is None:
            continue  # a pre-0010 receipt carries no revocation snapshot
        stmt = receipt.get("statement") or {}
        signed = stmt.get("revocation_head")
        if signed is None:
            continue
        checked += 1
        if compute_revocation_head(list(snapshot)) != signed:
            snapshot_invalid.append(str(stmt.get("sequence")))
            continue
        witnessed.update(snapshot)
    dropped = sorted(witnessed - current)
    verdict = ("snapshot_invalid" if snapshot_invalid
               else "dropped" if dropped else "fresh")
    return {"verdict": verdict, "receipts_checked": checked,
            "dropped": dropped, "snapshot_invalid": snapshot_invalid,
            "current_count": len(current), "witnessed_count": len(witnessed)}
