"""Identity capabilities for the Radicle adapter."""
from __future__ import annotations

from typing import Any

from chp_core import capability

from .._helpers import (
    _EMITS,
    _RAD_CLI_VERSION,
    _parse_kv,
)


class IdentityOps:
    @capability(
        id="chp.adapters.radicle.identity",
        version=_RAD_CLI_VERSION,
        description="Local Radicle identity: DID public key only. Private key / NID never returned.",
        category="developer_tooling",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["radicle", "identity", "did"],
    )
    async def identity(self, ctx: Any, payload: dict) -> dict:
        ctx.emit("radicle_request", {"operation": "identity"})
        try:
            raw = self._backend().run("self")
        except RuntimeError as exc:
            ctx.emit("radicle_error", {"operation": "identity", "error": str(exc)})
            raise
        kv = _parse_kv(raw)
        # Expose DID only — never the NID (node key) or any private material
        did = kv.get("did", "")
        result = {"did": did}
        ctx.emit("radicle_response", {"operation": "identity"})
        # NID is intentionally not returned or emitted
        return result
