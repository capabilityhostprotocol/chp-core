"""Mandate-revocation persistence (chp-v0.2.md §10, proposal 0007).

Received mandate revocations are host-runtime state about OTHER principals'
mandates — the ``~/.chp/witnesses/`` precedent, NOT ``<key_dir>/revocations.json``:
that file holds this host's own self-signed KEY revocations and is served
verbatim as ``revoked_keys`` in the identity document; mixing statement kinds
there would corrupt it.
"""

from __future__ import annotations

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
