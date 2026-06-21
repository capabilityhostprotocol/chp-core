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
