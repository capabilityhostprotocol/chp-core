"""Reference local capability host for CHP v0.1."""

from __future__ import annotations

import asyncio
import inspect
import os
import threading
import traceback
import warnings
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

MAX_REPLAY_LIMIT = 10_000

from .store import SQLiteEvidenceStore
from .decorators import adapt_callable, get_capability_descriptor
from .policy import PolicyConfig, evaluate_policy, load_policy
from .redaction import redact_payload
from .types import (
    AssuranceMetadata,
    AutonomyProfile,
    AUTONOMY_EVIDENCE_TYPES,
    CapabilityDescriptor,
    CORE_EVIDENCE_TYPES,
    ConversationEvent,
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


def _stringify_floats(value: Any) -> Any:
    """Represent every float in an evidence payload as its string form.

    chp-stable-v1 (spec/chp-v0.2.md §2) forbids non-integer numbers in
    canonicalized content: Python `json.dumps(0.0)` → `0.0` but an ECMAScript
    `Number.toString` → `0`, so the same value would hash differently across
    languages and silently break cross-language verification. `bool` (an `int`
    subclass) and `int` pass through unchanged."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, dict):
        return {k: _stringify_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stringify_floats(v) for v in value]
    return value


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
        # Host-owned lifecycle events (execution_started/completed/failed/
        # denied/skipped) are emitted by the host wrapper around every
        # invocation. A capability emitting them too produces duplicate,
        # outcome-less terminal events (the "outcome: unknown" bug). Warn so the
        # capability gets migrated to a domain event, but still record it —
        # silently dropping a downstream consumer's events is a breaking change.
        # (A future major version may drop instead.) chp-core's own capabilities
        # no longer emit these; the audit adapter is robust to any that remain.
        if event_type in CORE_EVIDENCE_TYPES:
            warnings.warn(
                f"capability emitted host-reserved lifecycle event {event_type!r}; "
                "the host owns these — emit a domain-specific event instead.",
                stacklevel=2,
            )
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

    def child_correlation(self) -> "CorrelationContext":
        """Correlation for work CAUSED BY this invocation: same correlation_id,
        ``causation_id`` = this invocation_id.

        Pass this to any remote or router ``ainvoke`` to extend the causal tree
        ACROSS hosts — the wire carries the full correlation, and
        chp-causal-order-v1 uses the edge to order the federated timeline::

            await remote.ainvoke("cap.id", payload,
                                 correlation=ctx.child_correlation())
        """
        from dataclasses import replace
        return replace(self.envelope.correlation, causation_id=self.envelope.invocation_id)

    def declare_participants(self, host_ids: list[str]) -> None:
        """Declare which hosts participate in this task (chp-v0.2.md §8).

        Emits the reserved ``task_participants_declared`` event on THIS host's
        signed chain — the task bundle's ``participation`` check then proves no
        declared member was silently omitted from the assembly. Call before (or
        while) fanning out to the declared hosts::

            ctx.declare_participants([ctx.host.host_id, "worker-b", "worker-ts"])
        """
        self.emit("task_participants_declared",
                  {"participants": sorted(set(host_ids))}, redacted=False)

    async def ainvoke(
        self,
        capability_id: str,
        payload: "JSON | None" = None,
        *,
        subject: "JSON | None" = None,
    ) -> "InvocationResult":
        """Invoke another capability governed through the host, propagating correlation.

        Records the causal edge: the child inherits the same correlation_id but
        its ``causation_id`` points at THIS invocation, so the evidence stream is
        a real call tree (group by invocation_id; child.causation_id == parent
        invocation_id) — not just a flat sequence. Exports directly to OTel's
        parent_span_id. For CROSS-host children use ``child_correlation()`` with
        a RemoteCapabilityHost/router."""
        return await self.host.ainvoke(
            capability_id,
            payload,
            correlation=self.child_correlation(),
            subject=subject,
        )


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
        policy: PolicyConfig | None = None,
        safety_evaluator: Any = None,
    ) -> None:
        self.host_id = host_id
        self.version = version
        self.store = store or SQLiteEvidenceStore()
        self.metadata = metadata or {}
        self._capabilities: dict[str, RegisteredCapability] = {}
        self._registry_lock = threading.RLock()
        # Governance: enforce policy on every invocation path (not just the
        # Claude Code hook). None → load from CHP_POLICY_FILE/.chp/~/.chp;
        # still None (no policy file) means no enforcement.
        self.policy = policy if policy is not None else load_policy()
        # Safety: when a RuleBasedSafetyEvaluator is configured, every invocation
        # is assessed (assessment events emitted as evidence) and its guardrails
        # enforced. None (default) = no safety gate — opt-in, like policy.
        self.safety_evaluator = safety_evaluator

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
        with self._registry_lock:
            if descriptor.capability_uri in self._capabilities:
                warnings.warn(
                    f"Capability '{descriptor.capability_uri}' already registered — overwriting.",
                    stacklevel=2,
                )
            self._capabilities[descriptor.capability_uri] = RegisteredCapability(
                descriptor=descriptor,
                handler=handler,
                enabled=enabled,
            )
        return descriptor

    def descriptor(self) -> HostDescriptor:
        with self._registry_lock:
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
        effective_limit = min(query.limit, MAX_REPLAY_LIMIT) if query.limit is not None else MAX_REPLAY_LIMIT
        total_available = len(events)
        events = events[:effective_limit]
        return ReplayResult(
            correlation_id=query.correlation_id,
            events=events,
            event_count=len(events),
            truncated=len(events) < total_available,
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

    def grant_approval(
        self,
        correlation_id: str,
        capability_uri: str,
        *,
        granted_by: str | None = None,
        note: str | None = None,
    ) -> "ExecutionEvidence":
        """Record that an external approver granted a pending approval_requested event."""
        corr = CorrelationContext.from_mapping({"correlation_id": correlation_id})
        envelope = InvocationEnvelope(
            capability_id=capability_uri,
            version=None,
            payload={},
            mode="sync",
            correlation=corr,
        )
        payload: JSON = {"capability_uri": capability_uri}
        if granted_by is not None:
            payload["decided_by"] = granted_by
        if note is not None:
            payload["note"] = note
        return self.emit_evidence("approval_granted", envelope, payload=payload, redacted=False)

    def deny_approval(
        self,
        correlation_id: str,
        capability_uri: str,
        *,
        denied_by: str | None = None,
        reason: str | None = None,
    ) -> "ExecutionEvidence":
        """Record that an external approver denied a pending approval_requested event."""
        corr = CorrelationContext.from_mapping({"correlation_id": correlation_id})
        envelope = InvocationEnvelope(
            capability_id=capability_uri,
            version=None,
            payload={},
            mode="sync",
            correlation=corr,
        )
        payload: JSON = {"capability_uri": capability_uri}
        if denied_by is not None:
            payload["decided_by"] = denied_by
        if reason is not None:
            payload["reason"] = reason
        return self.emit_evidence("approval_denied", envelope, payload=payload, redacted=False)

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
        _KNOWN_MODES = {"sync", "async", "stream", "fire_and_forget"}
        if envelope.mode not in _KNOWN_MODES:
            return self._deny(
                envelope,
                DenialReason(
                    code="unsupported_mode",
                    message=f"Unknown invocation mode {envelope.mode!r}. Standard modes: {sorted(_KNOWN_MODES)}",
                    retryable=False,
                ),
            )
        return await self.ainvoke_envelope(envelope)

    async def invoke_envelope(self, envelope: InvocationEnvelope | JSON) -> InvocationResult:
        return await self.ainvoke_envelope(envelope)

    async def ainvoke_envelope(self, envelope: InvocationEnvelope | JSON) -> InvocationResult:
        if isinstance(envelope, dict):
            envelope = InvocationEnvelope.from_mapping(envelope)

        if not envelope.capability_id or not envelope.capability_id.strip():
            return self._deny(
                envelope,
                DenialReason(
                    code="capability_not_found",
                    message="capability_id must be a non-empty string",
                    retryable=False,
                ),
            )

        entry = self._resolve(envelope.capability_id, envelope.version)
        if entry is None:
            # A governed denial that also TEACHES: closest registered ids ride
            # in details (wire-safe — DenialReason.details serializes today).
            import difflib
            registered = sorted({rc.descriptor.id for rc in self._capabilities.values()})
            suggestions = difflib.get_close_matches(
                envelope.capability_id, registered, n=3, cutoff=0.4)
            return self._deny(
                envelope,
                DenialReason(
                    code="capability_not_found",
                    message=f"Capability not found: {envelope.capability_id}",
                    retryable=False,
                    details={
                        "suggestions": suggestions,
                        "hint": "GET /capabilities lists every registered capability",
                    },
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

        # Governance gate — enforced on every invocation path (host.invoke,
        # ctx.ainvoke, HTTP /invoke), not just the Claude Code hook. Blocks by
        # allowlist / capability id / risk tier / input pattern.
        if self.policy is not None:
            verdict = evaluate_policy(
                descriptor.id,
                envelope.payload if isinstance(envelope.payload, dict) else {},
                self.policy,
                capability_risk=descriptor.risk,
            )
            if verdict.should_block:
                return self._deny(
                    envelope,
                    DenialReason(
                        code="policy_blocked",
                        message=verdict.reason or "blocked by policy",
                        retryable=False,
                    ),
                )

        invariant_denial = self._check_host_invariants(descriptor, envelope)
        if invariant_denial is not None:
            return self._deny(envelope, invariant_denial)

        autonomy_denial = self._check_autonomy_budget(descriptor, envelope)
        if autonomy_denial is not None:
            return self._deny(envelope, autonomy_denial)

        if descriptor.input_schema:
            try:
                import jsonschema
                jsonschema.validate(envelope.payload, descriptor.input_schema)
            except jsonschema.ValidationError as exc:
                return self._deny(
                    envelope,
                    DenialReason(
                        code="input_schema_validation_failed",
                        message=exc.message,
                        retryable=False,
                        details={
                            "schema_id": descriptor.input_schema.get("$id"),
                            "path": list(exc.absolute_path) or None,
                        },
                    ),
                )
            except Exception as exc:
                return self._deny(
                    envelope,
                    DenialReason(
                        code="input_schema_validation_failed",
                        message=f"Schema validation error: {exc}",
                        retryable=False,
                        details={"schema_id": descriptor.input_schema.get("$id")},
                    ),
                )

        safety_denial = self._check_safety(descriptor, envelope)
        if safety_denial is not None:
            return self._deny(envelope, safety_denial)

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
                    "error_type": exc.__class__.__name__,
                    "message": str(exc),
                    # Full traceback is NOT persisted — it leaks local paths and
                    # variable reprs (incl. secrets) into the evidence store and
                    # /replay. Opt in for debugging only.
                    **(
                        {"traceback": traceback.format_exc()}
                        if os.environ.get("CHP_EVIDENCE_TRACEBACKS") == "1"
                        else {}
                    ),
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
            # chp-stable-v1 forbids floats in canonicalized (hashed) content —
            # float serialization diverges across languages (Python 0.0 vs JS 0),
            # which would silently break cross-language verification. Normalize any
            # float to its string form at the single emission boundary so no
            # emitter can produce unverifiable evidence. Non-hashed surfaces
            # (InvocationResult.data, OTel attrs) keep the float.
            payload=_stringify_floats(
                redact_payload(payload or {}) if redacted else (payload or {})
            ),
            redacted=redacted,
            error=error,
            denial=denial,
            subject=envelope.subject,
            assurance=AssuranceMetadata(),
        )
        return self.store.append(event)  # type: ignore[return-value]

    def record_turn(
        self,
        correlation_id: str,
        role: str,
        content: Any,
        *,
        agent: str = "",
        include_content: bool = False,
        subject: JSON | None = None,
    ) -> ConversationEvent:
        """Record a conversation turn into the evidence chain.

        The turn is hash-chained with all other events in the same
        correlation_id, making it part of the tamper-evident session record.
        Set include_content=True to store the full text in the evidence payload
        (appropriate for private/local use only).
        """
        import hashlib as _hashlib
        import json as _json

        serialised = _json.dumps(content, sort_keys=True, default=str)
        content_hash = _hashlib.sha256(serialised.encode()).hexdigest()

        def _word_count(text: Any) -> int:
            if isinstance(text, str):
                return len(text.split())
            if isinstance(text, list):
                return sum(_word_count(item) for item in text)
            if isinstance(text, dict):
                return _word_count(text.get("text", ""))
            return 0

        event = ConversationEvent(
            event_id=new_id("conv"),
            correlation=CorrelationContext(correlation_id=correlation_id),
            role=role,
            agent=agent or self.host_id,
            content=content if include_content else None,
            content_hash=content_hash,
            word_count=_word_count(content),
            subject=subject,
        )
        return self.store.append(event)  # type: ignore[return-value]

    def _resolve(self, capability_id: str, version: str | None) -> RegisteredCapability | None:
        with self._registry_lock:
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

    def _emit_autonomy_event(
        self,
        event_type: str,
        envelope: InvocationEnvelope,
        descriptor: CapabilityDescriptor,
        *,
        detail: JSON | None = None,
    ) -> ExecutionEvidence:
        autonomy = descriptor.autonomy
        payload: JSON = {
            "capability_uri": descriptor.capability_uri,
            "autonomy": autonomy.to_dict() if autonomy is not None else None,
        }
        if detail:
            payload.update(detail)
        outcome: str | None = (
            "denied" if event_type in ("budget_exceeded", "approval_requested") else None
        )
        return self.emit_evidence(event_type, envelope, payload=payload, outcome=outcome)

    def _check_autonomy_budget(
        self,
        descriptor: CapabilityDescriptor,
        envelope: InvocationEnvelope,
    ) -> DenialReason | None:
        """Check AutonomyProfile budget and tier gates. Returns DenialReason or None.

        Called after _check_host_invariants(), before execution_started is emitted.
        Emits budget_exceeded or approval_requested as a side-effect before returning.
        """
        autonomy = descriptor.autonomy
        if autonomy is None:
            return None

        corr = envelope.correlation.correlation_id

        # 1. action_limit — count only execution_started events, not denials or autonomy events
        if autonomy.action_limit is not None:
            taken = self.store.count_by_correlation_event_type(corr, "execution_started")
            if taken >= autonomy.action_limit:
                self._emit_autonomy_event(
                    "budget_exceeded", envelope, descriptor,
                    detail={
                        "limit_type": "action_limit",
                        "action_limit": autonomy.action_limit,
                        "actions_taken": taken,
                        "rollback_policy": autonomy.rollback_policy,
                    },
                )
                return DenialReason(
                    code="budget_exceeded",
                    message=(
                        f"action_limit {autonomy.action_limit} reached "
                        f"for correlation {corr} (actions_taken={taken})"
                    ),
                    retryable=False,
                    details={
                        "limit_type": "action_limit",
                        "action_limit": autonomy.action_limit,
                        "actions_taken": taken,
                        "rollback_policy": autonomy.rollback_policy,
                    },
                )

        # 2. spend_limit — spend = execution_started_count × spend_units
        if autonomy.spend_limit is not None:
            taken = self.store.count_by_correlation_event_type(corr, "execution_started")
            spend_so_far = taken * autonomy.spend_units
            if spend_so_far >= autonomy.spend_limit:
                self._emit_autonomy_event(
                    "budget_exceeded", envelope, descriptor,
                    detail={
                        "limit_type": "spend_limit",
                        "spend_limit": autonomy.spend_limit,
                        "spend_units": autonomy.spend_units,
                        "spend_so_far": spend_so_far,
                        "rollback_policy": autonomy.rollback_policy,
                    },
                )
                return DenialReason(
                    code="budget_exceeded",
                    message=(
                        f"spend_limit {autonomy.spend_limit} reached "
                        f"for correlation {corr} (spend_so_far={spend_so_far})"
                    ),
                    retryable=False,
                    details={
                        "limit_type": "spend_limit",
                        "spend_limit": autonomy.spend_limit,
                        "spend_units": autonomy.spend_units,
                        "spend_so_far": spend_so_far,
                    },
                )

        # 3. tier == "approval_required" — gate every invocation
        if autonomy.tier == "approval_required":
            self._emit_autonomy_event(
                "approval_requested", envelope, descriptor,
                detail={
                    "tier": autonomy.tier,
                    "rollback_policy": autonomy.rollback_policy,
                },
            )
            return DenialReason(
                code="approval_required",
                message=f"Capability {descriptor.capability_uri} requires explicit approval",
                retryable=True,
                details={"tier": autonomy.tier},
            )

        return None

    def _emit_safety_event(
        self,
        event_type: str,
        envelope: InvocationEnvelope,
        descriptor: CapabilityDescriptor,
        *,
        detail: JSON | None = None,
    ) -> ExecutionEvidence:
        payload: JSON = {"capability_uri": descriptor.capability_uri}
        if detail:
            payload.update(detail)
        outcome = "denied" if event_type == "safety_action_blocked" else None
        return self.emit_evidence(event_type, envelope, payload=payload, outcome=outcome)

    def _check_safety(
        self,
        descriptor: CapabilityDescriptor,
        envelope: InvocationEnvelope,
    ) -> DenialReason | None:
        """Assess the invocation and enforce safety guardrails, if an evaluator is
        configured (chp-governance-v0.2.md §4.2). The assessment is ALWAYS recorded
        as evidence (safety_assessment_started/completed) — a signed safety verdict
        on every governed invocation is the differentiator; a guardrail block then
        denies with the reserved 'safety_blocked' code. No evaluator → no-op."""
        evaluator = self.safety_evaluator
        if evaluator is None:
            return None
        payload = envelope.payload if isinstance(envelope.payload, dict) else {}
        self._emit_safety_event("safety_assessment_started", envelope, descriptor)
        report = evaluator.report(descriptor.id, payload)
        assessment = report.assessment
        self._emit_safety_event(
            "safety_assessment_completed", envelope, descriptor,
            detail={"level": assessment.level, "score": assessment.score,
                    "approved": report.approved},
        )
        if not report.approved:
            self._emit_safety_event(
                "safety_guardrail_triggered", envelope, descriptor,
                detail={"reason": report.block_reason,
                        "guardrails_evaluated": report.guardrails_evaluated},
            )
            self._emit_safety_event(
                "safety_action_blocked", envelope, descriptor,
                detail={"reason": report.block_reason},
            )
            return DenialReason(
                code="safety_blocked",
                message=report.block_reason or "blocked by safety guardrail",
                retryable=False,
                details={"level": assessment.level, "score": assessment.score},
            )
        self._emit_safety_event(
            "safety_action_approved", envelope, descriptor,
            detail={"level": assessment.level, "recommendation": assessment.recommendation},
        )
        return None

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
