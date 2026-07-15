"""Reference local capability host for CHP v0.1."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import threading
import traceback
import warnings
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

MAX_REPLAY_LIMIT = 10_000


def chunk_seq_digest(deltas: list) -> str:
    """`chp-chunk-seq-v1` (spec §13.1): SHA-256 over the ordered stream chunk
    deltas, each canonicalized with chp-stable-v1 and newline-terminated — the
    §12 store-head line scheme, so the digest is byte-exact across
    implementations. Committed into a stream's `execution_completed` evidence so
    the delivered sequence is tamper-evident."""
    digest = hashlib.sha256()
    for delta in deltas:
        digest.update((json.dumps(delta, sort_keys=True) + "\n").encode())
    return digest.hexdigest()


def lookup_recorded_result(store: Any, invocation_id: str) -> "InvocationResult | None":
    """§13 idempotent-replay lookup: read the recorded result for *invocation_id*
    off *store* and rebuild it with ``replayed=True`` (or None). Best-effort — a
    cache error means a fresh execution. Shared by ``LocalCapabilityHost`` gate 0
    and the routing gateway's cross-owner gate 0 (§13.2, proposal 0014)."""
    from .types import CorrelationContext, DenialReason, InvocationResult
    lookup = getattr(store, "lookup_result", None)
    if lookup is None:
        return None
    try:
        data = lookup(invocation_id)
    except Exception:  # noqa: BLE001 — cache trouble must not block invokes
        return None
    if not isinstance(data, dict):
        return None
    denial_raw = data.get("denial")
    denial = None
    if isinstance(denial_raw, dict):
        denial = DenialReason(
            code=str(denial_raw.get("code", "")),
            message=str(denial_raw.get("message", "")),
            invariant_id=denial_raw.get("invariant_id"),
            retryable=bool(denial_raw.get("retryable", False)),
            details=denial_raw.get("details") or {},
        )
    return InvocationResult(
        invocation_id=str(data.get("invocation_id", invocation_id)),
        capability_id=str(data.get("capability_id", "")),
        capability_version=data.get("capability_version"),
        correlation=CorrelationContext.from_mapping(data.get("correlation")),
        outcome=data.get("outcome", "success"),
        success=bool(data.get("success", False)),
        data=data.get("data"),
        error=data.get("error"),
        denial=denial,
        evidence_ids=list(data.get("evidence_ids") or []),
        started_at=data.get("started_at"),
        completed_at=str(data.get("completed_at") or ""),
        replayed=True,
    )

from .store import EVENT_HASH_V2, SQLiteEvidenceStore, _payload_commitment
from .decorators import adapt_callable, get_capability_descriptor
from .policy import PolicyConfig, evaluate_policy, load_policy
from .redaction import redact_payload
from .types import (
    Actor,
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

# Policy decision (policy.py) → reserved denial code at the governance gate
# (proposal 0036). sandbox_only fails closed to policy_blocked — there is no
# sandbox execution mode yet (deferred); a decision the host cannot honor denies.
_POLICY_DECISION_CODE: dict[str, str] = {
    "deny": "policy_blocked",
    "requires_approval": "approval_required",
    "requires_escalation": "escalation_required",
    "requires_more_evidence": "evidence_required",
    "sandbox_only": "policy_blocked",
}


def _usage_of(data: Any) -> JSON:
    """Token-usage fields lifted from a handler result into the terminal
    evidence payload (proposal 0006) — ints/strs only (chp-stable-v1 floats)."""
    if not isinstance(data, dict):
        return {}
    return {k: data[k] for k in ("prompt_tokens", "completion_tokens",
                                 "total_tokens", "model")
            if k in data and isinstance(data[k], (int, str))}


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
        strict_output_schema: bool = False,
    ) -> None:
        self.host_id = host_id
        # When True, a result violating a capability's output_schema is DENIED
        # host-wide (proposal 0029); default validate-and-warn. A caller can also
        # force strict per-invocation via envelope.require_output_schema.
        self._strict_output = strict_output_schema
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
        caller: str | None = None,
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
            caller: Authorized discovery (proposal 0035): the verified caller
                identity. When set, capabilities whose ``policy.allowed_actors`` is
                non-empty and excludes the caller are HIDDEN — a caller sees only
                what it may invoke. ``None`` (anonymous / unnamed) = unfiltered,
                today's behavior. Hiding is least-disclosure; the invocation gate
                (``policy_blocked``, proposal 0034) remains the security backstop.
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
        if caller is not None:
            def _visible(c: CapabilityDescriptor) -> bool:
                allowed = c.policy.allowed_actors if c.policy is not None else None
                return not allowed or caller in allowed  # empty/absent = open
            caps = [c for c in caps if _visible(c)]

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
        actor: JSON | None = None,
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
                actor=actor,
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
        requested_capability_version: str | None = None,
        correlation: CorrelationContext | JSON | None = None,
        subject: JSON | None = None,
        actor: JSON | None = None,
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
            requested_capability_version=requested_capability_version,
            payload=payload or {},
            mode=mode,
            correlation=corr,
            subject=subject or {"id": "local", "type": "user"},
            # First-class actor (proposal 0034): validate/normalize at construction
            # so a wrong-shaped actor fails clean; None = today's behavior.
            actor=(Actor.from_mapping(actor).to_dict() if actor else None),
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

    def _prepare(
        self, envelope: InvocationEnvelope | JSON
    ) -> "tuple[InvocationEnvelope, RegisteredCapability | None, InvocationResult | None]":
        """Run the ENTIRE gate pipeline (chp-invocation-pipeline.md gates 1–10)
        and return ``(envelope, entry, early_result)``.

        ``early_result`` is the denial/skip InvocationResult when a gate fired
        (entry is None); when every gate passed, ``entry`` is the resolved
        registration and ``early_result`` is None. This is the ONE gate
        implementation shared by ``ainvoke_envelope`` (sync) and
        ``ainvoke_stream`` (SSE, proposal 0006) — a second gate copy on the
        stream path would drift, and a drifted gate is a security bug."""
        if isinstance(envelope, dict):
            envelope = InvocationEnvelope.from_mapping(envelope)

        # Gate 0 — idempotent replay (spec §13, proposal 0008): an already-
        # recorded invocation_id replays its recorded result; no gate below
        # runs and no events are emitted for an execution that did not happen.
        # Streams replay too (§13.1, proposal 0012) — ainvoke_stream re-streams
        # the recorded chunks before yielding this result.
        cached = self._lookup_recorded_result(envelope.invocation_id)
        if cached is not None:
            # Resume-aware replay (proposal 0037): a cached `approval_required` denial
            # does NOT replay if the caller now presents a valid approver grant for this
            # exact invocation + payload — delete the stale denial row (the cache is
            # otherwise first-writer-wins) and fall through to execute exactly once (the
            # gate-8 grant check accepts it). Any other cached result replays as usual.
            resuming = (cached.outcome == "denied" and cached.denial is not None
                        and cached.denial.retryable
                        and cached.denial.code == "approval_required"
                        and self._valid_approval_for(envelope))
            if resuming:
                self.store.delete_result(envelope.invocation_id)
            else:
                from .metrics import record_idempotent_replay
                record_idempotent_replay()
                return envelope, None, cached

        if not envelope.capability_id or not envelope.capability_id.strip():
            return envelope, None, self._deny(
                envelope,
                DenialReason(
                    code="capability_not_found",
                    message="capability_id must be a non-empty string",
                    retryable=False,
                ),
            )

        entry = self._resolve(envelope.capability_id, envelope.version)

        # Capability-version negotiation (§1.1, proposal 0028): when the envelope
        # requests a semver range, resolve to the highest registered version that
        # satisfies it. A registered id with NO satisfying version is
        # capability_version_unsupported — the capability EXISTS (distinct from
        # capability_not_found); an unregistered id still falls through below.
        rcv = envelope.requested_capability_version
        if rcv:
            with self._registry_lock:
                versions = sorted({rc.descriptor.version for rc in self._capabilities.values()
                                   if rc.descriptor.id == envelope.capability_id})
            if versions:
                from .semver import best_satisfying
                picked = best_satisfying(versions, rcv)
                if picked is None:
                    return envelope, None, self._deny(
                        envelope,
                        DenialReason(
                            code="capability_version_unsupported",
                            message=f"no version of {envelope.capability_id!r} "
                                    f"satisfies {rcv!r}",
                            retryable=False,
                            details={"requested": rcv, "available": versions,
                                     "capability_id": envelope.capability_id},
                        ),
                    )
                entry = self._resolve(envelope.capability_id, picked)

        if entry is None:
            # A governed denial that also TEACHES: closest registered ids ride
            # in details (wire-safe — DenialReason.details serializes today).
            import difflib
            registered = sorted({rc.descriptor.id for rc in self._capabilities.values()})
            suggestions = difflib.get_close_matches(
                envelope.capability_id, registered, n=3, cutoff=0.4)
            return envelope, None, self._deny(
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
            return envelope, None, self._skip(
                envelope,
                {
                    "code": "capability_disabled",
                    "message": f"Capability disabled: {descriptor.capability_uri}",
                },
            )

        if envelope.mode not in descriptor.modes:
            return envelope, None, self._deny(
                envelope,
                DenialReason(
                    code="unsupported_mode",
                    message=f"Capability {descriptor.capability_uri} does not support mode {envelope.mode}",
                    retryable=False,
                ),
            )

        # Mandate gate (chp-v0.2.md §10): presented authority must verify —
        # signature, principal attestation, validity window AT HOST TIME (never
        # the client-asserted requested_at), and, when transport auth already
        # verified a caller, that the mandate names THAT caller as delegate.
        # Invalid/expired/tampered/wrong-delegate → processed mandate_invalid
        # denial; a valid mandate binds the subject to "delegate under
        # principal's mandate" and narrows the invocation to its scope
        # (out-of-scope = policy_blocked, the §2 semantics).
        if envelope.mandate is not None:
            from .revocations import load_mandate_revocations
            from .signing import mandate_root_principal, scope_allows, verify_mandate
            from .types import utc_now
            subj = envelope.subject if isinstance(envelope.subject, dict) else {}
            verified_caller = subj.get("id") if subj.get("verified") else None
            mv = verify_mandate(
                envelope.mandate, at_time=utc_now(),
                delegate_id=verified_caller,
                revocations=load_mandate_revocations())
            if not mv.valid:
                return envelope, None, self._deny(
                    envelope,
                    DenialReason(
                        code="mandate_invalid",
                        message=mv.reason or "mandate failed verification",
                        retryable=False,
                        details={"checks": mv.checks,
                                 "mandate_id": envelope.mandate.get("mandate_id")},
                    ),
                )
            if not scope_allows(envelope.mandate.get("scope") or [], descriptor.id):
                return envelope, None, self._deny(
                    envelope,
                    DenialReason(
                        code="policy_blocked",
                        message=f"capability {descriptor.id!r} is outside mandate "
                                f"{envelope.mandate.get('mandate_id')!r}'s scope",
                        retryable=False,
                    ),
                )
            # Use-count cap (§10, proposal 0026): count the distinct invocations
            # already recorded under this mandate_id and deny once the signed
            # max_invocations is reached. Keyed on invocation_id (the replay key),
            # so a re-run of the same invocation does not consume a new use.
            max_inv = envelope.mandate.get("max_invocations")
            store = getattr(self, "store", None)
            if max_inv is not None and store is not None and hasattr(store, "count_mandate_uses"):
                mid = envelope.mandate.get("mandate_id")
                inv_id = envelope.invocation_id
                already = store.mandate_use_recorded(mid, inv_id)
                used = store.count_mandate_uses(mid)
                if not already and used >= int(max_inv):
                    return envelope, None, self._deny(
                        envelope,
                        DenialReason(
                            code="mandate_exhausted",
                            message=f"mandate {mid!r} exhausted "
                                    f"({used}/{max_inv} invocations used)",
                            retryable=False,
                            details={"used": used, "max_invocations": int(max_inv),
                                     "mandate_id": mid},
                        ),
                    )
                store.record_mandate_use(mid, inv_id, utc_now())

            immediate = (envelope.mandate.get("principal") or {}).get("host_id")
            root = mandate_root_principal(envelope.mandate)
            envelope.subject = {
                "id": envelope.mandate.get("delegate_id"),
                "type": "mandate",
                "verified": True,
                "mandate_id": envelope.mandate.get("mandate_id"),
                "principal": immediate,
                # Sub-delegation (§10, proposal 0009): the chain's ultimate
                # authority. Equals `principal` for a single-hop mandate.
                "root_principal": root,
            }

        # Per-actor allowlist (proposal 0034): a capability MAY restrict which
        # actors may invoke it via descriptor.policy.allowed_actors. Enforced
        # after the mandate gate finalizes the subject. The EFFECTIVE actor is the
        # verified subject id when the subject is verified (accountability wins),
        # else the asserted actor.id, else the subject id. An empty/absent
        # allowlist is open — today's behavior. Denies policy_blocked (no new code).
        pol = descriptor.policy
        allowed = pol.allowed_actors if pol is not None else None
        if allowed:
            subj = envelope.subject if isinstance(envelope.subject, dict) else {}
            actor = envelope.actor if isinstance(envelope.actor, dict) else {}
            effective = subj.get("id") if subj.get("verified") else (
                actor.get("id") or subj.get("id"))
            if effective not in allowed:
                return envelope, None, self._deny(
                    envelope,
                    DenialReason(
                        code="policy_blocked",
                        message=f"actor {effective!r} is not in allowed_actors "
                                f"for {descriptor.id!r}",
                        retryable=False,
                        details={"allowed_actors": list(allowed), "actor": effective},
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
                # Map the policy decision to its reserved code (proposal 0036) and
                # attach the versioned decision record. requires_approval/escalation/
                # more_evidence are retryable — the caller can take the required next
                # action and re-invoke. deny and sandbox_only (fail-closed) are not.
                code = _POLICY_DECISION_CODE.get(verdict.decision, "policy_blocked")
                return envelope, None, self._deny(
                    envelope,
                    DenialReason(
                        code=code,
                        message=verdict.reason or "blocked by policy",
                        retryable=verdict.decision in (
                            "requires_approval", "requires_escalation", "requires_more_evidence"),
                        details={
                            "decision": verdict.decision,
                            "matched_rule": verdict.matched_rule,
                            "policy_version": verdict.policy_version,
                            "explanation": verdict.reason,
                            "required_next_action": verdict.required_next_action,
                        },
                    ),
                )

        invariant_denial = self._check_host_invariants(descriptor, envelope)
        if invariant_denial is not None:
            return envelope, None, self._deny(envelope, invariant_denial)

        autonomy_denial = self._check_autonomy_budget(descriptor, envelope)
        if autonomy_denial is not None:
            return envelope, None, self._deny(envelope, autonomy_denial)

        if descriptor.input_schema:
            try:
                import jsonschema
                jsonschema.validate(envelope.payload, descriptor.input_schema)
            except jsonschema.ValidationError as exc:
                return envelope, None, self._deny(
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
                return envelope, None, self._deny(
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
            return envelope, None, self._deny(envelope, safety_denial)

        return envelope, entry, None

    def _lookup_recorded_result(self, invocation_id: str) -> "InvocationResult | None":
        """Gate 0 lookup: rebuild the recorded InvocationResult (replayed=True),
        or None. Best-effort — a cache error means a fresh execution."""
        return lookup_recorded_result(self.store, invocation_id)

    def _record_result(self, result: InvocationResult,
                       chunks: list | None = None) -> InvocationResult:
        """Record a processed result for idempotent replay (spec §13).
        Best-effort: recording trouble never fails the invocation. For a stream
        (§13.1) the ordered chunk deltas ride under a serving-only ``_chunks``
        key so a retried id can re-stream them; capped by
        ``CHP_STREAM_CACHE_MAX_CHUNKS`` (default 10000) — over the cap the stream
        is recorded non-resumable (replay degrades to the terminal result)."""
        if result.replayed:
            return result
        record = getattr(self.store, "record_result", None)
        if record is not None:
            payload = result.to_dict()
            if chunks is not None:
                cap = int(os.environ.get("CHP_STREAM_CACHE_MAX_CHUNKS", "10000"))
                if len(chunks) <= cap:
                    payload = {**payload, "_chunks": chunks}
            try:
                record(result.invocation_id, payload)
            except Exception:  # noqa: BLE001
                pass
        return result

    def _lookup_recorded_chunks(self, invocation_id: str) -> list | None:
        """The recorded stream chunk deltas for a replayed streaming id, or None
        (never cached, over the cap, or TTL-expired). Serving state — read off
        the same §13 result cache row as ``_lookup_recorded_result``."""
        lookup = getattr(self.store, "lookup_result", None)
        if lookup is None:
            return None
        try:
            data = lookup(invocation_id)
        except Exception:  # noqa: BLE001
            return None
        return data.get("_chunks") if isinstance(data, dict) else None

    async def ainvoke_envelope(self, envelope: InvocationEnvelope | JSON) -> InvocationResult:
        envelope, entry, early = self._prepare(envelope)
        if early is not None:
            return self._record_result(early)
        assert entry is not None  # _prepare contract: no early result ⇒ resolved entry
        descriptor = entry.descriptor

        started = self.emit_evidence(
            "execution_started",
            envelope,
            payload={"capability_uri": descriptor.capability_uri},
            outcome=None,
        )
        ctx = CapabilityExecutionContext(self, envelope)

        try:
            raw = entry.handler(ctx, envelope.payload)
            if inspect.isasyncgen(raw):
                # A STREAMING handler invoked in sync mode: collect the chunks
                # and return the terminal StreamResult's data (graceful degrade
                # — proposal 0006; the handler assembles the complete result).
                from .types import StreamResult
                data = None
                async for item in raw:
                    if isinstance(item, StreamResult):
                        data = item.data
            elif inspect.isawaitable(raw) and descriptor.timeout_s:
                # Declared execution timeout (proposal 0038): exceed it → a
                # TimeoutError caught below as execution_failed (a failure, not a
                # governance denial — the capability didn't refuse, it ran too long).
                data = await asyncio.wait_for(raw, descriptor.timeout_s)
            else:
                data = await raw if inspect.isawaitable(raw) else raw
            odeny, ometa = self._validate_output(descriptor, data, envelope)
            if odeny is not None:
                return self._deny(envelope, odeny)
            completed = self.emit_evidence(
                "execution_completed",
                envelope,
                # Host-constructed payload only (uri + lifted usage ints) —
                # unredacted so token accounting survives (the redactor would
                # scrub *_tokens keys as secrets). ometa records an output-schema
                # violation in warn mode (proposal 0029).
                payload={"capability_uri": descriptor.capability_uri,
                         **_usage_of(data), **ometa},
                outcome="success",
                redacted=False,
            )
            return self._record_result(InvocationResult(
                invocation_id=envelope.invocation_id,
                capability_id=descriptor.id,
                capability_version=descriptor.version,
                correlation=envelope.correlation,
                outcome="success",
                success=True,
                data=data,
                evidence_ids=[started.event_id, *ctx._evidence_ids, completed.event_id],
                started_at=started.timestamp,
            ))
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
            return self._record_result(InvocationResult(
                invocation_id=envelope.invocation_id,
                capability_id=descriptor.id,
                capability_version=descriptor.version,
                correlation=envelope.correlation,
                outcome="failure",
                success=False,
                error={"type": exc.__class__.__name__, "message": str(exc)},
                evidence_ids=[started.event_id, *ctx._evidence_ids, failed.event_id],
                started_at=started.timestamp,
            ))

    async def ainvoke_stream(self, envelope: InvocationEnvelope | JSON,
                             resume_from: int = -1):
        """Streaming invocation (proposal 0006): an async generator that yields
        ``{"chunk": <delta>}`` items and finally ``{"result": InvocationResult}``.

        The SAME gate pipeline as ``ainvoke_envelope`` runs first (via
        ``_prepare``); any denial/skip yields the result IMMEDIATELY with no
        prior chunks — the HTTP binding uses that to answer plain JSON without
        committing to an SSE response. Evidence brackets the stream:
        ``execution_started`` at open, ``execution_completed`` (with lifted
        usage + the §13.1 chunk-sequence digest) or ``execution_failed`` at
        close. A non-generator handler in stream mode degrades to a single
        terminal result.

        ``resume_from`` (§13.1): on an idempotent-replay hit the recorded chunk
        deltas are re-streamed starting AFTER this 0-based index (default -1 =
        from the start); an SSE `Last-Event-ID` reconnect passes the last chunk
        id it saw. Resume is replay-from-offset."""
        envelope, entry, early = self._prepare(envelope)
        if early is not None:
            # Streaming replay (§13.1): re-stream the recorded chunks from the
            # resume offset, then the recorded terminal result (replayed=True).
            for delta in (self._lookup_recorded_chunks(envelope.invocation_id)
                          or [])[resume_from + 1:]:
                yield {"chunk": delta}
            yield {"result": early}
            return
        assert entry is not None  # _prepare contract: no early result ⇒ resolved entry
        descriptor = entry.descriptor

        started = self.emit_evidence(
            "execution_started",
            envelope,
            payload={"capability_uri": descriptor.capability_uri},
            outcome=None,
        )
        ctx = CapabilityExecutionContext(self, envelope)
        from .types import StreamResult

        try:
            raw = entry.handler(ctx, envelope.payload)
            data = None
            chunks: list = []
            if inspect.isasyncgen(raw):
                async for item in raw:
                    if isinstance(item, StreamResult):
                        data = item.data
                    else:
                        chunks.append(item)
                        yield {"chunk": item}
            else:
                data = await raw if inspect.isawaitable(raw) else raw
            # §13.1 chunk-sequence evidence: commit a digest of the delivered
            # deltas (omit-when-absent — a non-stream/zero-chunk completion is
            # byte-identical). The chunks themselves are serving state (recorded
            # below for replay/resume), never hashed into the chain.
            odeny, ometa = self._validate_output(descriptor, data, envelope)
            if odeny is not None:
                yield {"result": self._deny(envelope, odeny)}
                return
            stream_meta = ({"chunk_count": len(chunks),
                            "chunk_seq_digest": chunk_seq_digest(chunks)}
                           if chunks else {})
            completed = self.emit_evidence(
                "execution_completed",
                envelope,
                # Host-constructed payload only (uri + lifted usage ints) —
                # unredacted so token accounting survives (the redactor would
                # scrub *_tokens keys as secrets). ometa records an output-schema
                # violation in warn mode (proposal 0029).
                payload={"capability_uri": descriptor.capability_uri,
                         **_usage_of(data), **stream_meta, **ometa},
                outcome="success",
                redacted=False,
            )
            result = InvocationResult(
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
            # Record for idempotent streaming replay (§13.1) — with the ordered
            # chunks so a retried id (or a Last-Event-ID reconnect) re-streams.
            self._record_result(result, chunks=chunks or None)
            yield {"result": result}
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
                    **(
                        {"traceback": traceback.format_exc()}
                        if os.environ.get("CHP_EVIDENCE_TRACEBACKS") == "1"
                        else {}
                    ),
                },
            )
            fail_result = InvocationResult(
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
            # Record the failure for idempotent replay (§13.1) — a retried id
            # replays the same failure, no partial chunks re-streamed.
            self._record_result(fail_result)
            yield {"result": fail_result}

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
        # chp-stable-v1 forbids floats in canonicalized (hashed) content — float
        # serialization diverges across languages (Python 0.0 vs JS 0), which
        # would silently break cross-language verification. Normalize any float to
        # its string form at the single emission boundary so no emitter can produce
        # unverifiable evidence. Non-hashed surfaces (InvocationResult.data, OTel
        # attrs) keep the float.
        final_payload = _stringify_floats(
            redact_payload(payload or {}) if redacted else (payload or {})
        )
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
            payload=final_payload,
            redacted=redacted,
            error=error,
            denial=denial,
            subject=envelope.subject,
            actor=envelope.actor,  # first-class actor recorded in evidence (0034)
            assurance=AssuranceMetadata(),
            # Selective disclosure (chp-v0.2.md §14): new events are born under
            # chp-event-hash-v2 — the content_hash commits to sha256(payload) so
            # this payload can later be withheld from a bundle without breaking
            # verification. Existing v1 events are untouched.
            hash_scheme=EVENT_HASH_V2,
            payload_commitment=_payload_commitment(final_payload),
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

    def _validate_output(
        self, descriptor: CapabilityDescriptor, data: JSON, envelope: InvocationEnvelope,
    ) -> tuple[DenialReason | None, JSON]:
        """Validate a handler result against ``descriptor.output_schema`` (proposal 0029).

        Mirror of the input-schema gate (``_prepare``), but AFTER execution.
        Returns ``(denial, meta)``:
          - ``denial``: a DenialReason iff the result violates the schema AND
            strict is requested (``envelope.require_output_schema`` or the host's
            ``strict_output_schema``); the caller returns/yields ``_deny``.
          - ``meta``: ``{"output_schema_valid": False, "output_schema_error": …}``
            to fold into the ``execution_completed`` evidence in the default
            validate-and-WARN mode (still a success, but the violation is on the
            chain); ``{}`` when valid or no schema is declared.

        Default is warn so existing capabilities with loose output_schema don't
        start failing on a strict result contract they never enforced."""
        if not descriptor.output_schema:
            return None, {}
        try:
            import jsonschema
            jsonschema.validate(data, descriptor.output_schema)
            return None, {}
        except jsonschema.ValidationError as exc:
            msg: str = exc.message
            path = list(exc.absolute_path) or None
        except Exception as exc:  # invalid schema, etc. — treat as a violation
            msg, path = f"Schema validation error: {exc}", None
        if bool(envelope.require_output_schema) or self._strict_output:
            return DenialReason(
                code="output_schema_validation_failed",
                message=msg,
                retryable=False,
                details={"schema_id": descriptor.output_schema.get("$id"), "path": path},
            ), {}
        return None, {"output_schema_valid": False, "output_schema_error": msg}

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
            # Resumable invocation (proposal 0037): a valid approver-signed grant for
            # THIS invocation + payload lets it proceed past the approval gate. Record
            # the verified grant on the chain, then execute (exactly once — the resume
            # gate 0 cleared any prior approval_required denial).
            if self._valid_approval_for(envelope):
                grant = envelope.approval_ref or {}
                self._emit_autonomy_event(
                    "approval_grant_verified", envelope, descriptor,
                    detail={"approval_id": grant.get("approval_id"),
                            "approver": grant.get("approver")})
                return None
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

    def _valid_approval_for(self, envelope: InvocationEnvelope) -> bool:
        """A presented approval grant (proposal 0037) authorizes THIS invocation to
        resume: it verifies (approver signature, not expired), its `decision` is
        `granted`, and it binds this exact `invocation_id` AND the request's payload
        commitment — so an approved invocation cannot swap its payload after approval.
        An optional `CHP_HOST_APPROVER_KEYS` (comma-separated key_ids) pins which
        approver keys the host trusts. Absent grant / any failure → False (fail-closed)."""
        grant = envelope.approval_ref
        if not isinstance(grant, dict):
            return False
        from .signing import verify_approval_grant
        pinned = os.environ.get("CHP_HOST_APPROVER_KEYS")
        approvers = {k.strip() for k in pinned.split(",") if k.strip()} if pinned else None
        if approvers is not None and grant.get("approver") not in approvers:
            return False
        v = verify_approval_grant(grant, at_time=utc_now())
        if not v.valid or grant.get("decision") != "granted":
            return False
        if grant.get("invocation_id") != envelope.invocation_id:
            return False
        payload = envelope.payload if isinstance(envelope.payload, dict) else {}
        commitment = _payload_commitment(_stringify_floats(payload))
        return grant.get("payload_commitment") == commitment

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
