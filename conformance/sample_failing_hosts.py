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

    _KNOWN = {"conformance.echo", "conformance.fail", "conformance.guarded"}

    async def invoke(
        self,
        capability_id: str,
        payload: dict[str, Any] | None = None,
        *,
        correlation: dict[str, Any] | None = None,
        **_kwargs: Any,
    ) -> FakeResult:
        corr = correlation or {"correlation_id": "generated-but-not-recorded"}
        if capability_id not in self._KNOWN:
            return FakeResult("fake", capability_id, "1.0.0", corr, "denied", False, denial=type("D", (), {"code": "capability_not_found"})(), evidence_ids=[])
        if capability_id == "conformance.fail":
            return FakeResult("fake", capability_id, "1.0.0", corr, "failure", False, error={"message": "failed"}, evidence_ids=[])
        if capability_id == "conformance.guarded":
            return FakeResult("fake", capability_id, "1.0.0", corr, "denied", False, denial=type("D", (), {"code": "invariant_failed"})(), evidence_ids=[])
        return FakeResult("fake", capability_id, "1.0.0", corr, "success", True, data={"echo": (payload or {}).get("value")}, evidence_ids=[])

    def replay(self, _correlation_id: str) -> list[dict[str, Any]]:
        return []


class BrokenNonStandardCodesHost:
    """Emits evidence but uses non-standard denial codes (e.g. bare 'not_found')."""

    def discover(self) -> dict[str, Any]:
        return {
            "id": "broken-codes",
            "version": "0.1.0",
            "protocol_version": "0.1",
            "kind": "test-broken",
            "evidence": {"store": "memory", "append_only": True},
            "capabilities": [
                {"id": "conformance.echo", "version": "1.0.0", "description": "", "modes": ["sync"], "emits": ["execution_started", "execution_completed"]},
                {"id": "conformance.fail", "version": "1.0.0", "description": "", "modes": ["sync"], "emits": ["execution_started", "execution_failed"]},
                {"id": "conformance.guarded", "version": "1.0.0", "description": "", "modes": ["sync"], "emits": ["execution_denied"]},
            ],
        }

    def _make_event(self, event_type: str, capability_id: str, corr: dict, outcome: str | None = None, denial: dict | None = None) -> dict[str, Any]:
        return {
            "event_id": f"evt-{event_type}",
            "event_type": event_type,
            "invocation_id": "fake-inv",
            "capability_id": capability_id,
            "host_id": "broken-codes",
            "correlation": corr,
            "timestamp": "2026-01-01T00:00:00Z",
            "sequence": 1,
            "outcome": outcome,
            "payload": {},
            "redacted": False,
            "assurance": {"level": "S1"},
            "denial": denial,
        }

    async def invoke(
        self,
        capability_id: str,
        payload: dict[str, Any] | None = None,
        *,
        correlation: dict[str, Any] | None = None,
        **_kwargs: Any,
    ) -> FakeResult:
        corr = correlation or {"correlation_id": "broken-codes-gen"}
        if capability_id == "conformance.fail":
            ev = self._make_event("execution_failed", capability_id, corr, "failure")
            self._last_events = {corr.get("correlation_id", ""): [self._make_event("execution_started", capability_id, corr), ev]}
            return FakeResult("fake", capability_id, "1.0.0", corr, "failure", False, error={"message": "failed"}, evidence_ids=["evt-failed"])
        if capability_id == "conformance.guarded":
            # Uses non-standard denial code "not_found" instead of "capability_not_found"
            bad_denial = {"code": "not_found", "message": "not found", "retryable": False}
            ev = self._make_event("execution_denied", capability_id, corr, "denied", bad_denial)
            self._last_events = {corr.get("correlation_id", ""): [ev]}
            return FakeResult("fake", capability_id, "1.0.0", corr, "denied", False, denial=type("D", (), {"code": "not_found"})(), evidence_ids=["evt-denied"])
        if capability_id not in ("conformance.echo",):
            # Missing capability — returns non-standard code
            bad_denial = {"code": "not_found", "message": "not found", "retryable": False}
            ev = self._make_event("execution_denied", capability_id, corr, "denied", bad_denial)
            self._last_events = {corr.get("correlation_id", ""): [ev]}
            return FakeResult("fake", capability_id, "1.0.0", corr, "denied", False, denial=type("D", (), {"code": "not_found"})(), evidence_ids=["evt-denied"])
        ev_start = self._make_event("execution_started", capability_id, corr)
        ev_done = self._make_event("execution_completed", capability_id, corr, "success")
        self._last_events = {corr.get("correlation_id", ""): [ev_start, ev_done]}
        return FakeResult("fake", capability_id, "1.0.0", corr, "success", True, data={"echo": (payload or {}).get("value")}, evidence_ids=["evt-start", "evt-done"])

    def __init__(self) -> None:
        self._last_events: dict[str, list[dict]] = {}

    def replay(self, correlation_id: str) -> list[dict[str, Any]]:
        return self._last_events.get(correlation_id, [])


class BrokenNoHashChainHost:
    """Emits evidence events but never sets content_hash/prev_hash (no chain)."""

    def discover(self) -> dict[str, Any]:
        return {
            "id": "broken-no-chain",
            "version": "0.1.0",
            "protocol_version": "0.1",
            "kind": "test-broken",
            "evidence": {"store": "memory", "append_only": True},
            "capabilities": [
                {"id": "conformance.echo", "version": "1.0.0", "description": "", "modes": ["sync"], "emits": ["execution_started", "execution_completed"]},
                {"id": "conformance.fail", "version": "1.0.0", "description": "", "modes": ["sync"], "emits": ["execution_started", "execution_failed"]},
                {"id": "conformance.guarded", "version": "1.0.0", "description": "", "modes": ["sync"], "emits": ["execution_denied"]},
            ],
        }

    def _make_event(self, event_type: str, capability_id: str, corr: dict, seq: int, outcome: str | None = None, denial: dict | None = None) -> dict[str, Any]:
        return {
            "event_id": f"evt-{seq}",
            "event_type": event_type,
            "invocation_id": "fake-inv",
            "capability_id": capability_id,
            "host_id": "broken-no-chain",
            "correlation": corr,
            "timestamp": "2026-01-01T00:00:00Z",
            "sequence": seq,
            "outcome": outcome,
            "payload": {},
            "redacted": False,
            "assurance": {"level": "S1"},
            "denial": denial,
            # Deliberately omits content_hash and prev_hash
        }

    def __init__(self) -> None:
        self._last_events: dict[str, list[dict]] = {}

    _KNOWN = {"conformance.echo", "conformance.fail", "conformance.guarded"}

    async def invoke(
        self,
        capability_id: str,
        payload: dict[str, Any] | None = None,
        *,
        correlation: dict[str, Any] | None = None,
        **_kwargs: Any,
    ) -> FakeResult:
        corr = correlation or {"correlation_id": "no-chain-gen"}
        cid = corr.get("correlation_id", "no-chain-gen")
        if capability_id not in self._KNOWN:
            denial = {"code": "capability_not_found", "message": "not found", "retryable": False}
            evs = [self._make_event("execution_denied", capability_id, corr, 1, "denied", denial)]
            self._last_events[cid] = evs
            return FakeResult("fake", capability_id, "1.0.0", corr, "denied", False, denial=type("D", (), {"code": "capability_not_found"})(), evidence_ids=["evt-1"])
        if capability_id == "conformance.fail":
            evs = [self._make_event("execution_started", capability_id, corr, 1), self._make_event("execution_failed", capability_id, corr, 2, "failure")]
            self._last_events[cid] = evs
            return FakeResult("fake", capability_id, "1.0.0", corr, "failure", False, evidence_ids=["evt-1", "evt-2"])
        if capability_id == "conformance.guarded":
            denial = {"code": "invariant_failed", "message": "missing field", "retryable": False}
            evs = [self._make_event("execution_denied", capability_id, corr, 1, "denied", denial)]
            self._last_events[cid] = evs
            return FakeResult("fake", capability_id, "1.0.0", corr, "denied", False, denial=type("D", (), {"code": "invariant_failed"})(), evidence_ids=["evt-1"])
        evs = [self._make_event("execution_started", capability_id, corr, 1), self._make_event("execution_completed", capability_id, corr, 2, "success")]
        self._last_events[cid] = evs
        return FakeResult("fake", capability_id, "1.0.0", corr, "success", True, data={"echo": (payload or {}).get("value")}, evidence_ids=["evt-1", "evt-2"])

    def replay(self, correlation_id: str) -> list[dict[str, Any]]:
        return self._last_events.get(correlation_id, [])

    def by_correlation_with_hashes(self, correlation_id: str) -> list[dict[str, Any]]:
        # Returns events without content_hash — the check should detect the absence
        return self._last_events.get(correlation_id, [])
