"""Wire (de)serialization for the Zenoh binding.

The wire OBJECTS are identical to the HTTP binding's — the same ``InvocationResult`` JSON — only the
carrier differs. Kept in one place so client and server share one codec.
"""

from __future__ import annotations

import json
from typing import Any

from chp_core.types import CorrelationContext, InvocationResult, JSON


def result_from_dict(data: JSON) -> InvocationResult:
    """Reconstruct an ``InvocationResult`` from its wire dict (mirrors the HTTP
    client's deserialization — the same object, a different carrier)."""
    from chp_core.types import DenialReason

    denial_raw = data.get("denial")
    denial = (DenialReason(
        code=str(denial_raw.get("code", "")),
        message=str(denial_raw.get("message", "")),
        retryable=bool(denial_raw.get("retryable", False)),
        details=dict(denial_raw.get("details") or {}),
    ) if denial_raw else None)
    return InvocationResult(
        invocation_id=str(data.get("invocation_id", "")),
        capability_id=str(data.get("capability_id", "")),
        capability_version=data.get("capability_version"),
        correlation=CorrelationContext.from_mapping(data.get("correlation")),
        outcome=data.get("outcome", "failure"),  # type: ignore[arg-type]
        success=bool(data.get("success", False)),
        data=data.get("data"),
        error=data.get("error"),
        denial=denial,
        evidence_ids=list(data.get("evidence_ids") or []),
        started_at=data.get("started_at"),
        completed_at=data.get("completed_at", ""),
    )


def first_reply(replies: Any) -> JSON:
    """Drain a Zenoh get() and return the first OK reply's JSON payload."""
    for reply in replies:
        ok = getattr(reply, "ok", None)
        if ok is not None:
            return json.loads(bytes(ok.payload))
    raise ConnectionError("no Zenoh reply (queryable unreachable or errored)")
