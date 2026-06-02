"""Deliberately broken hosts used to prove the conformance suite catches gaps."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class FakeResult:
    invocation_id: str
    capability_id: str
    capability_version: str | None
    correlation: dict[str, Any]
    outcome: str
    success: bool
    data: Any = None
    error: dict[str, Any] | None = None
    denial: dict[str, Any] | None = None
    evidence_ids: list[str] | None = None


class BrokenNoEvidenceHost:
    """Looks like a host but does not emit or replay evidence."""

    def discover(self) -> dict[str, Any]:
        return {
            "id": "broken-no-evidence",
            "version": "0.1.0",
            "protocol_version": "0.1",
            "kind": "test-broken",
            "evidence": {"store": "none", "append_only": False},
            "capabilities": [
                {
                    "id": "conformance.echo",
                    "version": "1.0.0",
                    "description": "Echo without evidence.",
                    "modes": ["sync"],
                    "emits": [],
                },
                {
                    "id": "conformance.fail",
                    "version": "1.0.0",
                    "description": "Fail without evidence.",
                    "modes": ["sync"],
                    "emits": [],
                },
                {
                    "id": "conformance.guarded",
                    "version": "1.0.0",
                    "description": "Deny without evidence.",
                    "modes": ["sync"],
                    "emits": [],
                },
            ],
        }

    async def invoke(
        self,
        capability_id: str,
        payload: dict[str, Any] | None = None,
        *,
        correlation: dict[str, Any] | None = None,
        **_kwargs: Any,
    ) -> FakeResult:
        corr = correlation or {"correlation_id": "generated-but-not-recorded"}
        if capability_id == "conformance.fail":
            return FakeResult("fake", capability_id, "1.0.0", corr, "failure", False, error={"message": "failed"}, evidence_ids=[])
        if capability_id == "conformance.guarded":
            return FakeResult("fake", capability_id, "1.0.0", corr, "denied", False, denial={"code": "denied"}, evidence_ids=[])
        return FakeResult("fake", capability_id, "1.0.0", corr, "success", True, data={"echo": (payload or {}).get("value")}, evidence_ids=[])

    def replay(self, _correlation_id: str) -> list[dict[str, Any]]:
        return []
