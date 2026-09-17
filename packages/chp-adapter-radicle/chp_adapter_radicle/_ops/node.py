"""Node capabilities for the Radicle adapter."""
from __future__ import annotations

import re
from typing import Any

from chp_core import capability

from .._helpers import (
    _EMITS,
    _RAD_CLI_VERSION,
)


class NodeOps:
    @capability(
        id="chp.adapters.radicle.node_status",
        version=_RAD_CLI_VERSION,
        description="Radicle node status: running/stopped, connected peer count.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "node", "status"],
    )
    async def node_status(self, ctx: Any, payload: dict) -> dict:
        ctx.emit("radicle_request", {"operation": "node_status"})
        try:
            raw = self._backend().run("node", "status")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "node_status", "error": str(exc)})
            raise
        not_running = "not running" in raw.lower() or "stopped" in raw.lower()
        running = (("running" in raw.lower() or "started" in raw.lower()) and not not_running)
        peer_match = re.search(r"connected[:\s]+(\d+)", raw, re.IGNORECASE)
        peers = int(peer_match.group(1)) if peer_match else 0
        result = {"running": running, "peers": peers, "raw_status": raw[:120]}
        ctx.emit("radicle_response", {"operation": "node_status", "running": running, "peers": peers})
        return result

    @capability(
        id="chp.adapters.radicle.sync",
        version=_RAD_CLI_VERSION,
        description="Sync a Radicle repo to the network (push local state to seeds).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "sync", "network"],
    )
    async def sync(self, ctx: Any, payload: dict) -> dict:
        repo = self._repo(payload)
        ctx.emit("radicle_request", {"operation": "sync", "repo_path": repo})
        try:
            raw = self._rad("sync", repo=repo)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "sync", "error": str(exc)})
            raise
        ok = "error" not in raw.lower() and "✗" not in raw
        result = {"ok": ok, "message": raw[:200]}
        ctx.emit("radicle_response", {"operation": "sync", "ok": ok})
        return result

    @capability(
        id="chp.adapters.radicle.node_connect",
        version=_RAD_CLI_VERSION,
        description="Instruct the node to connect to a peer at nid@host:port (establishes replication link).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "nid": {"type": "string", "description": "Peer Node ID (z6Mk...)"},
                "address": {"type": "string", "description": "Peer address host:port (e.g. 100.x.y.z:8776)"},
            },
            "required": ["nid", "address"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "node", "connect", "peer"],
    )
    async def node_connect(self, ctx: Any, payload: dict) -> dict:
        nid = str(payload["nid"])
        address = str(payload["address"])
        ctx.emit("radicle_request", {"operation": "node_connect", "nid": nid})
        try:
            raw = self._backend().run("node", "connect", f"{nid}@{address}")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "node_connect", "error": str(exc)})
            raise
        ok = "✗" not in raw and "error" not in raw.lower()
        ctx.emit("radicle_response", {"operation": "node_connect", "nid": nid, "ok": ok})
        return {"nid": nid, "address": address, "ok": ok, "message": raw[:200]}

    @capability(
        id="chp.adapters.radicle.follow",
        version=_RAD_CLI_VERSION,
        description="Follow a peer node (replicate its refs for 'followed'-scope repos).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "nid": {"type": "string", "description": "Node ID (z6Mk...)"},
                "alias": {"type": "string", "description": "Optional local alias for the peer"},
            },
            "required": ["nid"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "follow", "peer", "network"],
    )
    async def follow(self, ctx: Any, payload: dict) -> dict:
        nid = str(payload["nid"])
        alias = payload.get("alias")
        args = ["follow", nid] + (["--alias", str(alias)] if alias else [])
        ctx.emit("radicle_request", {"operation": "follow", "nid": nid})
        try:
            raw = self._backend().run(*args)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "follow", "error": str(exc)})
            raise
        ok = "✗" not in raw and "error" not in raw.lower()
        ctx.emit("radicle_response", {"operation": "follow", "nid": nid, "ok": ok})
        return {"nid": nid, "ok": ok, "message": raw[:200]}
