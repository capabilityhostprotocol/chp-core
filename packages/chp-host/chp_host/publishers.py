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
                           trust: str = "tofu",
                           key_history: list | None = None) -> tuple[str, str | None]:
    """Returns (status, detail):
      - ("pinned", key_id)   first verified publisher for this package — recorded.
      - ("ok", key_id)       matches the pin.
      - ("rotated", key_id)  the key changed BUT a valid continuity chain (each
                             hop signed by the key we already trusted) links the
                             pinned key to the presented one — re-pinned.
      - ("mismatch", pinned) a DIFFERENT key with no valid continuity — refuse;
                             recover deliberately via reset_publisher.
    ``key_history`` is the publisher's rotation lineage from the statement
    (spec §3.2 applied to §9). The walk trusts each hop only when it verifies
    under the key ALREADY pinned — self-published history cannot self-vouch.
    """
    from chp_core.signing import verify_continuity

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
        rank = {"tofu": 0, "pinned": 1, "rotated": 1, "anchored": 2}
        if rank.get(trust, 0) > rank.get(entry.get("trust", "tofu"), 0):
            entry["trust"] = trust
            save_publishers(data)
        return ("ok", key_id)
    # Rotation path: walk pinned → presented, each hop verified under the key
    # trusted so far (starting from OUR pin — mesh.py's exact argument).
    trusted_id, trusted_pub = entry.get("key_id"), entry.get("public_key")
    for stmt in key_history or []:
        if (stmt.get("old_key_id") == trusted_id
                and (trusted_pub is None or stmt.get("old_public_key") == trusted_pub)
                and verify_continuity(stmt)):
            trusted_id = stmt.get("new_key_id")
            trusted_pub = stmt.get("new_public_key")
            if trusted_id == key_id:
                entry["key_id"] = key_id
                entry["public_key"] = trusted_pub
                entry["trust"] = "rotated"
                save_publishers(data)
                return ("rotated", key_id)
    return ("mismatch", entry.get("key_id"))


def reset_publisher(package: str) -> bool:
    """Clear a package's publisher pin so the next verified install re-pins."""
    data = load_publishers()
    if package in data["publishers"]:
        del data["publishers"][package]
        save_publishers(data)
        return True
    return False
