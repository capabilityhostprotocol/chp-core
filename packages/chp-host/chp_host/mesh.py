"""Mesh manifest management — ~/.chp/mesh.json.

The mesh manifest is a lightweight EnvironmentConfig-compatible JSON file that
chp-host gateway reads by default (zero-arg mode).  It tracks remote CHP nodes
joined via ``chp-host mesh invite`` / ``chp-host mesh add``.

Schema (subset of environments/*.json)::

    {
      "name": "mesh",
      "agent_remotes": [
        {
          "url":         "http://100.1.2.3:8803",
          "api_key_env": "CHP_PEER_0_KEY",
          "role":        "worker",
          "added":       "2026-06-18T10:00:00Z",
          "optional":    true
        }
      ],
      "gateway": {
        "port":    8800,
        "bind":    "0.0.0.0",
        "host_id": "chp-gateway-mesh"
      }
    }
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def mesh_path() -> Path:
    return Path.home() / ".chp" / "mesh.json"


def _empty_mesh() -> dict:
    return {
        "name": "mesh",
        "agent_remotes": [],
        "gateway": {
            "port": 8800,
            "bind": "0.0.0.0",
            "host_id": "chp-gateway-mesh",
        },
    }


def load_mesh() -> dict:
    p = mesh_path()
    if not p.exists():
        return _empty_mesh()
    with p.open() as f:
        return json.load(f)


def save_mesh(data: dict) -> None:
    p = mesh_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.parent / f".mesh.tmp.{os.getpid()}"
    try:
        tmp.write_text(json.dumps(data, indent=2) + "\n")
        tmp.replace(p)
    finally:
        if tmp.exists():
            tmp.unlink()


def next_peer_key_name(data: dict) -> str:
    remotes = data.get("agent_remotes") or []
    used_envs = {r.get("api_key_env", "") for r in remotes}
    n = 0
    while f"CHP_PEER_{n}_KEY" in used_envs:
        n += 1
    return f"CHP_PEER_{n}_KEY"


def add_remote(
    url: str,
    api_key_env: str,
    role: str = "worker",
    optional: bool = True,
) -> None:
    data = load_mesh()
    remotes: list[dict] = data.setdefault("agent_remotes", [])
    for r in remotes:
        if r.get("url") == url:
            raise ValueError(f"Remote {url!r} already in mesh manifest.")
    remotes.append({
        "url": url,
        "api_key_env": api_key_env,
        "role": role,
        "optional": optional,
        "added": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    save_mesh(data)


def remove_remote(url: str) -> str:
    data = load_mesh()
    remotes: list[dict] = data.get("agent_remotes") or []
    match = next((r for r in remotes if r.get("url") == url), None)
    if match is None:
        raise ValueError(f"Remote {url!r} not found in mesh manifest.")
    data["agent_remotes"] = [r for r in remotes if r.get("url") != url]
    save_mesh(data)
    return match.get("api_key_env", "")


def find_remote(url: str) -> dict | None:
    """Return the remote entry for *url*, or None."""
    for r in load_mesh().get("agent_remotes") or []:
        if r.get("url") == url:
            return r
    return None


def mark_stats(url: str, stats: dict) -> None:
    """Cache the latest capacity snapshot for the remote (fast stale-ok reads)."""
    data = load_mesh()
    for r in data.get("agent_remotes") or []:
        if r.get("url") == url:
            r["last_stats"] = stats
            r["last_stats_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            save_mesh(data)
            return


def pin_or_check_key(url: str, key_id: str, public_key: str | None,
                     trust: str = "tofu",
                     key_history: list | None = None) -> tuple[str, str | None]:
    """Trust-on-first-use for a remote's signing key (ssh known_hosts model).

    Returns (status, detail):
      - ("pinned", key_id)     first time we've seen a key for this remote — recorded.
      - ("ok", key_id)         the presented key matches the pinned one.
      - ("rotated", key_id)    the key changed BUT a valid continuity chain (each
                               hop signed by the key we already trusted) links the
                               pinned key to the presented one — re-pinned.
      - ("mismatch", pinned)   the key CHANGED with no valid continuity — a hard
                               error; needs manual reset.
      - ("no-remote", None)    url not in the mesh manifest.

    ``trust`` records HOW the key earned the pin: "tofu" (first-seen, unverified
    beyond the self-attestation), "anchored" (an external trust root vouched),
    or "rotated" (followed a continuity chain from a previously-pinned key).
    An anchored confirmation upgrades a tofu pin; never downgraded automatically.

    ``key_history`` is the remote's published rotation lineage (spec §3.2): a
    list of continuity statements, each signed by the OLD key it names. The
    chain walk trusts each hop only if it verifies under the key we ALREADY
    trust — the remote's self-published history cannot vouch for itself.
    """
    from chp_core.signing import verify_continuity

    data = load_mesh()
    for r in data.get("agent_remotes") or []:
        if r.get("url") != url:
            continue
        pinned = r.get("key_id")
        if not pinned:
            r["key_id"] = key_id
            if public_key:
                r["public_key"] = public_key
            r["trust"] = trust
            save_mesh(data)
            return ("pinned", key_id)
        if pinned == key_id:
            if trust == "anchored" and r.get("trust") != "anchored":
                r["trust"] = "anchored"
                save_mesh(data)
            return ("ok", key_id)
        # Rotation path: walk the continuity chain pinned → presented, each hop
        # verified under the key trusted so far (starting from OUR pinned pubkey).
        trusted_id, trusted_pub = pinned, r.get("public_key")
        for stmt in key_history or []:
            if (stmt.get("old_key_id") == trusted_id
                    and stmt.get("old_public_key") == trusted_pub
                    and verify_continuity(stmt)):
                trusted_id = stmt.get("new_key_id")
                trusted_pub = stmt.get("new_public_key")
                if trusted_id == key_id:
                    r["key_id"] = key_id
                    r["public_key"] = trusted_pub
                    r["trust"] = "rotated"
                    save_mesh(data)
                    return ("rotated", key_id)
        return ("mismatch", pinned)
    return ("no-remote", None)


def reset_key(url: str) -> bool:
    """Clear a remote's pinned key so the next verify re-pins (TOFU). Deliberate."""
    data = load_mesh()
    changed = False
    for r in data.get("agent_remotes") or []:
        if r.get("url") == url:
            r.pop("key_id", None)
            r.pop("public_key", None)
            changed = True
            break
    if changed:
        save_mesh(data)
    return changed


def mark_verified(url: str) -> None:
    """Stamp ``last_verified`` (UTC now) on the remote, if present.

    Called after a successful health probe so the mesh list can show which
    peers are actually reachable and when they were last seen.
    """
    data = load_mesh()
    changed = False
    for r in data.get("agent_remotes") or []:
        if r.get("url") == url:
            r["last_verified"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            changed = True
            break
    if changed:
        save_mesh(data)
