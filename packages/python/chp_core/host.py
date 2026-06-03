"""Reference local capability host for CHP v0.1."""

from __future__ import annotations

import asyncio
import inspect
import traceback
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .store import SQLiteEvidenceStore
from .decorators import adapt_callable, get_capability_descriptor
from .redaction import redact_payload
from .types import (
    AssuranceMetadata,
    CapabilityDescriptor,
    CorrelationContext,
    DenialReason,
    ExecutionEvidence,
    HostDescriptor,
    InvariantDescriptor,
    InvocationEnvelope,
    InvocationResult,
    JSON,
    ReplayQuery,
    ReplayResult,
    new_id,
    utc_now,
)

CapabilityHandler = Callable[["CapabilityExecutionContext", JSON], Any | Awaitable[Any]]


@dataclass(slots=True)
class RegisteredCapability:
    descriptor: CapabilityDescriptor
    handler: CapabilityHandler
    enabled: bool = True


class CapabilityExecutionContext:
    """Context passed to capability handlers."""

    def __init__(self, host: "LocalCapabilityHost", envelope: InvocationEnvelope) -> None:
        self.host = host
        self.envelope = envelope
        self._evidence_ids: list[str] = []

    @property
    def correlation_id(self) -> str:
        return self.envelope.correlation.correlation_id

    @property
    def subject(self) -> JSON:
        return self.envelope.subject

    def emit(
        self,
        event_type: str,
        payload: JSON | None = None,
        *,
        outcome: str | None = None,
        redacted: bool = True,
    ) -> ExecutionEvidence:
        event = self.host.emit_evidence(
            event_type=event_type,
            envelope=self.envelope,
            payload=redact_payload(payload or {}) if redacted else (payload or {}),
            outcome=outcome,
            redacted=redacted,
        )
        self._evidence_ids.append(event.event_id)
        return event

    def replay(self, correlation_id: str | None = None) -> list[JSON]:
        return self.host.replay(correlation_id or self.correlation_id)


class LocalCapabilityHost:
    """Small local capability host.

    This host is transport-neutral. It provides declaration, discovery,
    governed invocation, evidence emission, correlation propagation, and
    replay against an append-only local SQLite event store.
    """

    def __init__(
        self,
        host_id: str = "local-chp-host",
        *,
        version: str = "0.1.0",
        store: SQLiteEvidenceStore | None = None,
        metadata: JSON | None = None,
    ) -> None:
        self.host_id = host_id
        self.version = version
        self.store = store or SQLiteEvidenceStore()
        self.metadata = metadata or {}
        self._capabilities: dict[str, RegisteredCapability] = {}

    def register(
        self,
        descriptor: CapabilityDescriptor | CapabilityHandler,
        handler: CapabilityHandler | None = None,
        *,
        enabled: bool = True,
    ) -> CapabilityDescriptor:
        if handler is None and callable(descriptor):
            fn = descriptor
            discovered = get_capability_descriptor(fn)
            if discovered is None:
                raise ValueError("decorated capability is missing __chp_descriptor__")
            descriptor = discovered
            handler = adapt_callable(fn)
        if handler is None:
            raise ValueError("capability handler is required")
        assert isinstance(descriptor, CapabilityDescriptor)
        if not descriptor.id:
            raise ValueError("capability descriptor id is required")
        if not descriptor.version:
            raise ValueError("capability descriptor version is required")
        self._capabilities[descriptor.capability_uri] = RegisteredCapability(
            descriptor=descriptor,
            handler=handler,
            enabled=enabled,
        )
        return descriptor

    def descriptor(self) -> HostDescriptor:
        return HostDescriptor(
            id=self.host_id,
            version=self.version,
            capabilities=[entry.descriptor for entry in self._capabilities.values()],
            metadata=self.metadata,
        )

    def discover(
        self,
        *,
        category: str | None = None,
        namespace: str | None = None,
        tags: list[str] | None = None,
        status: str | None = None,
        risk: str | None = None,
    ) -> JSON:
        """Return the host descriptor as a dict, with optional capability filtering.

        All filter arguments are keyword-only and default to ``None`` (no filter).

        Args:
            category: Return only capabilities whose ``category`` matches exactly.
                Use ``CapabilityCategory`` constants or ``"domain.<name>"``.
            namespace: Return only capabilities whose ``id`` starts with this prefix
                (e.g. ``"crm."`` for all CRM capabilities).
            tags: Return only capabilities that carry ALL of the supplied tags.
            status: Return only capabilities at this maturity status
                (``"draft"``, ``"experimental"``, ``"certified"``, ``"deprecated"``).
            risk: Return only capabilities at this risk tier
                (``"low"``, ``"medium"``, ``"high"``, ``"critical"``).
        """
        caps = [entry.descriptor for entry in self._capabilities.values()]

        if category is not None:
            caps = [c for c in caps if c.category == category]
        if namespace is not None:
            caps = [c for c in caps if c.id.startswith(namespace)]
        if tags is not None:
            tag_set = set(tags)
            caps = [c for c in caps if tag_set.issubset(set(c.tags))]
        if status is not None:
            caps = [c for c in caps if c.status == status]
        if risk is not None:
            caps = [c for c in caps if c.risk == risk]

        base = self.descriptor().to_dict()
        base["capabilities"] = [c.to_dict() for c in caps]
        return base

    def replay(self, correlation_id: str) -> list[JSON]:
        return self.store.by_correlation(correlation_id)

    def replay_result(self, query: ReplayQuery | JSON | str) -> ReplayResult:
        if isinstance(query, str):
            query = ReplayQuery(correlation_id=query)
        elif isinstance(query, dict):
            query = ReplayQuery.from_mapping(query)

        events = self.store.by_correlation(query.correlation_id)
        if query.since_sequence is not None:
            events = [event for event in events if event["sequence"] > query.since_sequence]
        if not query.include_payloads:
            events = [{**event, "payload": {}} for event in events]
        if query.limit is not None:
            events = events[: query.limit]
        return ReplayResult(
            correlation_id=query.correlation_id,
            events=events,
            event_count=len(events),
        )

    def query_evidence(
        self,
        *,
        capability_id: str | None = None,
        outcome: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int | None = None,
    ) -> list[JSON]:
        return self.store.query(
            capability_id=capability_id,
            outcome=outcome,
            since=since,
            until=until,
            limit=limit,
        )

    def evidence_count(self, correlation_id: str) -> int:
        return self.store.count_by_correlation(correlation_id)

    def invoke(
        self,
        capability_id: str,
        payload: JSON | None = None,
        *,
        version: str | None = None,
        correlation_id: str | None = None,
        correlation: CorrelationContext | JSON | None = None,
        subject: JSON | None = None,
        mode: str = "sync",
        metadata: JSON | None = None,
    ) -> InvocationResult:
        if correlation_id is not None:
            if correlation is not None:
                raise ValueError("provide correlation_id or correlation, not both")
            correlation = {"correlation_id": correlation_id}
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "LocalCapabilityHost.invoke() cannot run inside an active event loop; use await host.ainvoke()."
            )
        return asyncio.run(
            self.ainvoke(
                capability_id,
                payload,
                version=version,
                correlation=correlation,
                subject=subject,
                mode=mode,
                metadata=metadata,
            )
        )

    async def ainvoke(
        self,
        capability_id: str,
        payload: JSON | None = None,
        *,
        version: str | None = None,
        correlation: CorrelationContext | JSON | None = None,
        subject: JSON | None = None,
        mode: str = "sync",
        metadata: JSON | None = None,
    ) -> InvocationResult:
        if isinstance(correlation, CorrelationContext):
            corr = correlation
        else:
            corr = CorrelationContext.from_mapping(correlation)
        envelope = InvocationEnvelope(
            capability_id=capability_id,
            version=version,
            payload=payload or {},
            mode=mode,
            correlation=corr,
            subject=subject or {"id": "local", "type": "user"},
            metadata=metadata or {},
        )
        return await self.ainvoke_envelope(envelope)

    async def invoke_envelope(self, envelope: InvocationEnvelope | JSON) -> InvocationResult:
        return await self.ainvoke_envelope(envelope)

    async def ainvoke_envelope(self, envelope: InvocationEnvelope | JSON) -> InvocationResult:
        if isinstance(envelope, dict):
            envelope = InvocationEnvelope.from_mapping(envelope)

        entry = self._resolve(envelope.capability_id, envelope.version)
        if entry is None:
            return self._deny(
                envelope,
                DenialReason(
                    code="capability_not_found",
                    message=f"Capability not found: {envelope.capability_id}",
                    retryable=False,
                ),
            )

        descriptor = entry.descriptor
        envelope.capability_id = descriptor.id
        envelope.version = descriptor.version

        if not entry.enabled:
            return self._skip(
                envelope,
                {
                    "code": "capability_disabled",
                    "message": f"Capability disabled: {descriptor.capability_uri}",
                },
            )

        if envelope.mode not in descriptor.modes:
            return self._deny(
                envelope,
                DenialReason(
                    code="unsupported_mode",
                    message=f"Capability {descriptor.capability_uri} does not support mode {envelope.mode}",
                    retryable=False,
                ),
            )

        invariant_denial = self._check_host_invariants(descriptor, envelope)
        if invariant_denial is not None:
            return self._deny(envelope, invariant_denial)

        started = self.emit_evidence(
            "execution_started",
            envelope,
            payload={"capability_uri": descriptor.capability_uri},
            outcome=None,
        )
        ctx = CapabilityExecutionContext(self, envelope)

        try:
            raw = entry.handler(ctx, envelope.payload)
            data = await raw if inspect.isawaitable(raw) else raw
            completed = self.emit_evidence(
                "execution_completed",
                envelope,
                payload={"capability_uri": descriptor.capability_uri},
                outcome="success",
            )
            return InvocationResult(
                invocation_id=envelope.invocation_id,
                capability_id=descriptor.id,
                capability_version=descriptor.version,
                correlation=envelope.correlation,
                outcome="success",
                success=True,
                data=data,
                evidence_ids=[started.event_id, *ctx._evidence_ids, completed.event_id],
                started_at=started.timestamp,
            )
        except Exception as exc:
            failed = self.emit_evidence(
                "execution_failed",
                envelope,
                payload={"capability_uri": descriptor.capability_uri},
                outcome="failure",
                error={
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(limit=3),
                },
            )
            return InvocationResult(
                invocation_id=envelope.invocation_id,
                capability_id=descriptor.id,
                capability_version=descriptor.version,
                correlation=envelope.correlation,
                outcome="failure",
                success=False,
                error={"type": exc.__class__.__name__, "message": str(exc)},
                evidence_ids=[started.event_id, *ctx._evidence_ids, failed.event_id],
                started_at=started.timestamp,
            )

    def emit_evidence(
        self,
        event_type: str,
        envelope: InvocationEnvelope,
        payload: JSON | None = None,
        *,
        outcome: str | None = None,
        redacted: bool = True,
        error: JSON | None = None,
        denial: DenialReason | None = None,
    ) -> ExecutionEvidence:
        event = ExecutionEvidence(
            event_id=new_id("evt"),
            event_type=event_type,
            invocation_id=envelope.invocation_id,
            capability_id=envelope.capability_id,
            capability_version=envelope.version,
            host_id=self.host_id,
            correlation=envelope.correlation,
            timestamp=utc_now(),
            outcome=outcome,  # type: ignore[arg-type]
            payload=redact_payload(payload or {}) if redacted else (payload or {}),
            redacted=redacted,
            error=error,
            denial=denial,
            assurance=AssuranceMetadata(),
        )
        return self.store.append(event)

    def _resolve(self, capability_id: str, version: str | None) -> RegisteredCapability | None:
        if ":" in capability_id and version is None:
            return self._capabilities.get(capability_id)
        if version is not None:
            return self._capabilities.get(f"{capability_id}:{version}")
        matches = [
            entry
            for uri, entry in self._capabilities.items()
            if uri.startswith(f"{capability_id}:")
        ]
        if len(matches) == 1:
            return matches[0]
        return None

    def _deny(self, envelope: InvocationEnvelope, denial: DenialReason) -> InvocationResult:
        denied = self.emit_evidence(
            "execution_denied",
            envelope,
            payload={"reason": denial.code},
            outcome="denied",
            denial=denial,
        )
        return InvocationResult(
            invocation_id=envelope.invocation_id,
            capability_id=envelope.capability_id,
            capability_version=envelope.version,
            correlation=envelope.correlation,
            outcome="denied",
            success=False,
            denial=denial,
            evidence_ids=[denied.event_id],
            started_at=denied.timestamp,
        )

    def _skip(self, envelope: InvocationEnvelope, reason: JSON) -> InvocationResult:
        skipped = self.emit_evidence(
            "execution_skipped",
            envelope,
            payload={"reason": reason["code"]},
            outcome="skipped",
        )
        return InvocationResult(
            invocation_id=envelope.invocation_id,
            capability_id=envelope.capability_id,
            capability_version=envelope.version,
            correlation=envelope.correlation,
            outcome="skipped",
            success=False,
            error=reason,
            evidence_ids=[skipped.event_id],
            started_at=skipped.timestamp,
        )

    def _check_host_invariants(
        self,
        descriptor: CapabilityDescriptor,
        envelope: InvocationEnvelope,
    ) -> DenialReason | None:
        for invariant in descriptor.invariants:
            if invariant.enforcement != "host":
                continue
            violation = evaluate_invariant_against_payload(invariant, envelope.payload)
            if violation and invariant.failure_behavior == "deny":
                return DenialReason(
                    code="invariant_failed",
                    message=violation,
                    invariant_id=invariant.id,
                    retryable=False,
                    details={"kind": invariant.kind},
                )
        return None


def evaluate_invariant_against_payload(
    invariant: InvariantDescriptor,
    payload: JSON,
) -> str | None:
    if invariant.kind == "required_payload_fields":
        missing = [
            field
            for field in invariant.parameters.get("fields", [])
            if field not in payload or payload[field] in (None, "")
        ]
        if missing:
            return f"Missing required payload fields: {', '.join(missing)}"

    if invariant.kind == "max_payload_bytes":
        max_bytes = int(invariant.parameters.get("max_bytes", 0))
        if max_bytes > 0 and len(str(payload).encode("utf-8")) > max_bytes:
            return f"Payload exceeds {max_bytes} bytes"

    return None


def evaluate_invariant_against_event(
    invariant: InvariantDescriptor,
    event: JSON,
) -> str | None:
    payload = event.get("payload") or {}

    if invariant.kind == "deny_external_event_type":
        denied_type = invariant.parameters.get("event_type")
        if payload.get("external_event_type") == denied_type:
            return f"External event type would be denied: {denied_type}"

    if invariant.kind == "payload_field_equals":
        field = invariant.parameters.get("field")
        expected = invariant.parameters.get("value")
        if field and payload.get(field) == expected:
            return f"Payload field {field} equals denied value {expected!r}"

    if invariant.kind == "capability_id_matches":
        expected = invariant.parameters.get("capability_id")
        if event.get("capability_id") == expected:
            return f"Capability would be denied: {expected}"

    payload_violation = evaluate_invariant_against_payload(invariant, payload)
    if payload_violation:
        return payload_violation

    return None
