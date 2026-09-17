"""Seed capabilities for the Radicle adapter."""
from __future__ import annotations

import re
from typing import Any

from chp_core import capability

from .._helpers import (
    _EMITS,
    _RAD_CLI_VERSION,
)


class SeedOps:
    @capability(
        id="chp.adapters.radicle.seed",
        version=_RAD_CLI_VERSION,
        description="Seed a repo on this node (create/update its replication policy). Scope 'followed' "
                    "(delegates + explicitly-followed peers) or 'all' (every remote).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {
                "rid": {"type": "string", "description": "Repository ID (rad:...)"},
                "scope": {"type": "string", "enum": ["followed", "all"],
                          "description": "Replication scope (default: followed)"},
            },
            "required": ["rid"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "seed", "network", "replication"],
    )
    async def seed(self, ctx: Any, payload: dict) -> dict:
        rid = str(payload["rid"])
        scope = payload.get("scope", "followed")
        ctx.emit("radicle_request", {"operation": "seed", "rid": rid, "scope": scope})
        try:
            raw = self._backend().run("seed", rid, "--scope", scope)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "seed", "error": str(exc)})
            raise
        ok = "✗" not in raw and "error" not in raw.lower()
        ctx.emit("radicle_response", {"operation": "seed", "rid": rid, "ok": ok})
        return {"rid": rid, "scope": scope, "ok": ok, "message": raw[:200]}

    @capability(
        id="chp.adapters.radicle.seed_policies",
        version=_RAD_CLI_VERSION,
        description="List this node's seeding policies (which repos it replicates + scope).",
        category="developer_tooling",
        risk="low",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        emits=_EMITS,
        tags=["radicle", "seed", "policy", "network"],
    )
    async def seed_policies(self, ctx: Any, payload: dict) -> dict:
        ctx.emit("radicle_request", {"operation": "seed_policies"})
        try:
            raw = self._backend().run("seed")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "seed_policies", "error": str(exc)})
            raise
        # `rad seed` rows have no ● marker; columns: Repository(rid)  Name  Policy  Scope.
        policies: list[dict] = []
        for line in raw.splitlines():
            inner = line.strip()
            if not inner.startswith("│"):
                continue
            inner = inner.strip("│").strip()
            fields = re.split(r"\s{2,}", inner)
            if len(fields) >= 4 and fields[0].startswith("rad:"):
                policies.append({"rid": fields[0], "name": fields[1],
                                 "policy": fields[2], "scope": fields[3]})
        ctx.emit("radicle_response", {"operation": "seed_policies", "count": len(policies)})
        return {"policies": policies, "count": len(policies)}

    @capability(
        id="chp.adapters.radicle.unseed",
        version=_RAD_CLI_VERSION,
        description="Remove this node's seeding policy for a repo (stop replicating it).",
        category="developer_tooling",
        risk="medium",
        input_schema={
            "type": "object",
            "properties": {"rid": {"type": "string", "description": "Repository ID (rad:...)"}},
            "required": ["rid"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "seed", "network"],
    )
    async def unseed(self, ctx: Any, payload: dict) -> dict:
        rid = str(payload["rid"])
        ctx.emit("radicle_request", {"operation": "unseed", "rid": rid})
        try:
            raw = self._backend().run("unseed", rid)
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "unseed", "error": str(exc)})
            raise
        ok = "✗" not in raw and "error" not in raw.lower()
        ctx.emit("radicle_response", {"operation": "unseed", "rid": rid, "ok": ok})
        return {"rid": rid, "ok": ok, "message": raw[:200]}
