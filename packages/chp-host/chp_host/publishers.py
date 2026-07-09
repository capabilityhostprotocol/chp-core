"""Publisher key pinning for adapter provenance (chp-v0.2.md §9).

The ssh-known_hosts model mesh.py uses for peers, applied to the supply chain:
the first VERIFIED install of a package pins its publisher's signing key in
``~/.chp/publishers.json``; a later statement signed by a different key is a
hard mismatch until an operator deliberately resets the pin.

``trust`` records how the pin was earned: "tofu" (first verified statement),
"pinned" (operator supplied --publisher-key explicitly), or "anchored" (the
statement's attestation carried an anchor the operator asserted via
--publisher-domain). Publisher key rotation continuity is a named follow-up —
statements don't carry key history; recovery today is `publishers reset`.
"""

from __future__ import annotations

import json
from pathlib import Path


def publishers_path() -> Path:
    return Path.home() / ".chp" / "publishers.json"


def load_publishers() -> dict:
    p = publishers_path()
    if not p.exists():
        return {"publishers": {}}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"publishers": {}}


def save_publishers(data: dict) -> None:
    p = publishers_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def pin_or_check_publisher(package: str, key_id: str, public_key: str | None,
                           trust: str = "tofu") -> tuple[str, str | None]:
    """Returns (status, detail):
      - ("pinned", key_id)   first verified publisher for this package — recorded.
      - ("ok", key_id)       matches the pin.
      - ("mismatch", pinned) a DIFFERENT key signed this package's statement —
                             refuse; recover deliberately via reset_publisher.
    A trust upgrade (tofu → pinned/anchored) is recorded on match.
    """
    data = load_publishers()
    entry = data["publishers"].get(package)
    if entry is None:
        data["publishers"][package] = {
            "key_id": key_id,
            **({"public_key": public_key} if public_key else {}),
            "trust": trust,
        }
        save_publishers(data)
        return ("pinned", key_id)
    if entry.get("key_id") == key_id:
        rank = {"tofu": 0, "pinned": 1, "anchored": 2}
        if rank.get(trust, 0) > rank.get(entry.get("trust", "tofu"), 0):
            entry["trust"] = trust
            save_publishers(data)
        return ("ok", key_id)
    return ("mismatch", entry.get("key_id"))


def reset_publisher(package: str) -> bool:
    """Clear a package's publisher pin so the next verified install re-pins."""
    data = load_publishers()
    if package in data["publishers"]:
        del data["publishers"][package]
        save_publishers(data)
        return True
    return False
