"""Protocol objects for the CHP v0.1 reference implementation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar, Literal
from uuid import uuid4

JSON = dict[str, Any]

CORE_EVIDENCE_TYPES = {
    "execution_started",
    "execution_completed",
    "execution_failed",
    "execution_denied",
    "execution_skipped",
}

SESSION_EVIDENCE_TYPES = {
    "agent_session_started",
    "agent_session_resumed",
    "agent_session_completed",
}

COGNITION_EVIDENCE_TYPES = {
    # memory (v0.3.1)
    "memory_read",
    "memory_written",
    "memory_deleted",
    # planning (v0.3.2)
    "plan_created",
    "plan_step_started",
    "plan_step_completed",
    "plan_revised",
    "plan_completed",
    "plan_failed",
    # reflection (v0.3.2)
    "reflection_started",
    "reflection_completed",
    "outcome_scored",
    # delegation (v0.3.3)
    "delegation_created",
    "delegation_accepted",
    "delegation_completed",
    "delegation_rejected",
    "delegation_reassigned",
}

AUTONOMY_EVIDENCE_TYPES = {
    "budget_exceeded",
    "approval_requested",
    "approval_granted",
    "approval_denied",
}

# Host-SELF evidence (spec §3.2 / governance §4.4): the host's own key/identity
# lifecycle, emitted on its own hash-chained store — which thereby serves as the
# host's key-transparency log (tamper-evident, ordered, exportable like any
# bundle). The first evidence family describing the host rather than an invocation.
IDENTITY_EVIDENCE_TYPES = {
    "key_generated",
    "key_rotated",
    "key_revoked",
    "identity_anchored",
}

RETRIEVAL_EVIDENCE_TYPES = {
    "retrieval_started",
    "retrieval_completed",
    "retrieval_failed",
}

INGESTION_EVIDENCE_TYPES = {
    "ingestion_started",
    "ingestion_completed",
    "ingestion_failed",
}

TRANSFORMATION_EVIDENCE_TYPES = {
    "transformation_started",
    "transformation_completed",
    "transformation_failed",
}

GRAPH_EVIDENCE_TYPES = {
    "graph_entity_added",
    "graph_relation_added",
    "graph_queried",
    "graph_traversed",
    "graph_operation_failed",
}

WORKFLOW_EVIDENCE_TYPES = {
    "workflow_started",
    "workflow_step_started",
    "workflow_step_completed",
    "workflow_step_failed",
    "workflow_completed",
    "workflow_failed",
}

DOMAIN_EVENT_EVIDENCE_TYPES = {
    "domain_event_emitted",
    "domain_events_queried",
    "domain_event_operation_failed",
}

METRICS_EVIDENCE_TYPES = {
    "execution_started",
    "execution_completed",
    "execution_failed",
    "execution_denied",
}

VERSION_CONTROL_EVIDENCE_TYPES = {
    "version_control_repo_inspected",
    "version_control_diff_summarized",
    "version_control_precommit_checked",
    "version_control_release_bundle_generated",
    "version_control_merge_readiness_verified",
    "version_bumped",
    "rc_tag_pushed",
    "release_tag_pushed",
}

STATE_MACHINE_EVIDENCE_TYPES = {
    "state_machine_created",
    "state_machine_transition_started",
    "state_machine_transition_completed",
    "state_machine_blocked",
    "state_machine_completed",
    "state_machine_failed",
    "state_machine_cancelled",
}

INCIDENT_EVIDENCE_TYPES = {
    "incident_opened",
    "incident_escalated",
    "incident_remediation_applied",
    "incident_resolved",
    "incident_closed",
    "incident_trigger_fired",
}

SAFETY_EVIDENCE_TYPES = {
    "safety_assessment_started",
    "safety_assessment_completed",
    "safety_guardrail_triggered",
    "safety_action_blocked",
    "safety_action_approved",
}

COMPLIANCE_EVIDENCE_TYPES = {
    "retention_policy_applied",
    "evidence_purged",
    "evidence_redacted",
    "compliance_report_generated",
}

MemoryScope = Literal["session", "project", "user"]
AutonomyTier = Literal["automated", "supervised", "approval_required", "human_driven"]
RollbackPolicy = Literal["none", "checkpoint", "full"]
PlanStepStatus = Literal["pending", "running", "completed", "failed", "skipped"]
DelegationStatus = Literal["pending", "accepted", "completed", "rejected", "reassigned"]
StateMachineStatus = Literal["queued", "running", "blocked", "done", "failed", "cancelled"]
RiskLevel = Literal["low", "medium", "high", "critical"]
IncidentSeverity = Literal["P1", "P2", "P3", "P4"]
IncidentStatus = Literal["open", "investigating", "escalated", "resolved", "closed"]

ExecutionOutcome = Literal["success", "failure", "denied", "skipped"]

CapabilityStatus = Literal["draft", "experimental", "certified", "deprecated"]
CapabilityLocality = Literal["local", "edge", "cloud", "hybrid", "any"]
CapabilityIdempotency = Literal["required", "optional", "not_supported"]


class CapabilityCategory:
    """Standard catalog category strings for ``CapabilityDescriptor.category``.

    Use these constants when declaring which section of the CHP Capability
    Catalog a capability belongs to. Domain capabilities follow the
    ``domain.<name>`` convention (e.g. ``domain.crm``, ``domain.engineering``).
    """

    HOST_SUBSTRATE = "host_substrate"
    AGENT_OPERATIONS = "agent_operations"
    DATA_KNOWLEDGE = "data_knowledge"
    PROCESS_WORKFLOW = "process_workflow"
    INTERFACE = "interface"
    GOVERNANCE = "governance"
    OBSERVABILITY = "observability"
    ECONOMICS = "economics"
    DEVELOPER = "developer"
    CROSS_DOMAIN = "cross_domain"
    ENGINEERING = "domain.engineering"


def utc_now() -> str:
    """Return an RFC 3339 UTC timestamp."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


@dataclass(slots=True)
class CorrelationContext:
    correlation_id: str = field(default_factory=lambda: new_id("corr"))
    causation_id: str | None = None
    parent_correlation_id: str | None = None
    trace_id: str | None = None
    baggage: JSON = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: JSON | None) -> "CorrelationContext":
        if not value:
            return cls()
        correlation_id = value.get("correlation_id") or new_id("corr")
        return cls(
            correlation_id=str(correlation_id),
            causation_id=value.get("causation_id"),
            parent_correlation_id=value.get("parent_correlation_id"),
            trace_id=value.get("trace_id"),
            baggage=dict(value.get("baggage") or {}),
        )

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class InvariantDescriptor:
    id: str
    kind: str
    description: str = ""
    enforcement: Literal["declarative", "host", "runtime"] = "declarative"
    failure_behavior: Literal["deny", "warn", "degrade"] = "deny"
    parameters: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class AssuranceMetadata:
    level: Literal["S1", "S2", "S3"] = "S1"
    evidence_policy: str = "local-append-only"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class HostRequirements:
    """Declared host-side requirements for a capability.

    All fields are optional. Only populated fields carry meaning — a ``None``
    value means no constraint is declared, not that the resource is unavailable.
    """

    compute: str | None = None
    storage: str | None = None
    inference: str | None = None
    runtime: str | None = None
    network: str | None = None
    isolation: str | None = None
    locality: CapabilityLocality = "any"

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class PolicyDescriptor:
    """Declared policy surface for a capability.

    Extends the flat ``risk`` field on ``CapabilityDescriptor`` with richer
    policy semantics. When present, ``risk_tier`` takes precedence over the
    top-level ``risk`` shortcut.
    """

    risk_tier: Literal["low", "medium", "high", "critical"] = "low"
    auth_required: bool = False
    approval_required: bool = False
    data_classification: str | None = None
    allowed_actors: list[str] = field(default_factory=list)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class CostHint:
    """Declared cost and performance expectations for a capability (§7.2)."""

    token_estimate: int | None = None
    latency_ms_p50: int | None = None
    idempotent: bool = True

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class SafetyHint:
    """Declared safety characteristics for a capability (§7.2)."""

    reversible: bool = True
    destructive: bool = False
    requires_human_review: bool = False
    blast_radius: Literal["local", "session", "user", "system"] = "local"

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class StateMachineDefinition:
    """Blueprint for a state machine instance (§6.3)."""

    states: list[str]
    transitions: dict[str, list[str]]  # from_state -> list[to_state]
    initial_state: str
    terminal_states: list[str]

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class StateMachineRecord:
    """Persistent state machine instance (§6.3)."""

    machine_id: str
    name: str
    definition: StateMachineDefinition
    current_state: str
    status: StateMachineStatus
    context: JSON
    created_at: str
    updated_at: str
    history: list[JSON]  # [{from, to, event, at}]

    def to_dict(self) -> JSON:
        data = asdict(self)
        return data


@dataclass(slots=True)
class StateMachineTransitionResult:
    """Result of a state machine transition attempt (§6.3)."""

    machine_id: str
    from_state: str
    to_state: str
    event: str
    allowed: bool
    reason: str | None
    updated_at: str

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class RiskAssessment:
    """Structured risk evaluation result for a capability invocation (§8.6)."""

    level: RiskLevel
    score: float
    factors: list[str]
    recommendation: Literal["allow", "warn", "require_approval", "block"]
    assessed_at: str

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class GuardrailDefinition:
    """Rule that caps the allowed risk level for a capability ID pattern (§8.6)."""

    id: str
    capability_id_pattern: str
    max_risk_level: RiskLevel
    requires_human_for: list[str] = field(default_factory=list)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class SafetyReport:
    """Full safety evaluation including guardrail outcomes for an invocation (§8.6)."""

    report_id: str
    capability_id: str
    payload_hash: str
    assessment: RiskAssessment
    guardrails_evaluated: list[str]
    approved: bool
    block_reason: str | None
    generated_at: str

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class RetentionPolicy:
    """Evidence retention and payload-redaction rule for a capability pattern (§8.5)."""

    policy_id: str
    retain_days: int
    applies_to: list[str]
    redact_payload_after_days: int | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class ComplianceReport:
    """Result of applying retention policies to the evidence store (§8.5)."""

    report_id: str
    policy_ids: list[str]
    store_path: str
    events_inspected: int
    events_purged: int
    events_redacted: int
    generated_at: str

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class IncidentTrigger:
    """Pattern that auto-opens an incident when threshold events appear in a window (§9.5)."""

    pattern: str
    threshold: int
    window_seconds: int

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class Incident:
    """Named event with an explicit lifecycle: open → investigating → resolved → closed (§9.5)."""

    incident_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    trigger: IncidentTrigger | None
    correlation_ids: list[str]
    detected_at: str
    resolved_at: str | None
    timeline: list[JSON]

    def to_dict(self) -> JSON:
        data = asdict(self)
        return data


@dataclass(slots=True)
class RemediationAction:
    """A single remediation step linked to an incident (§9.5)."""

    action_id: str
    incident_id: str
    action_type: Literal["auto", "manual", "escalate"]
    description: str
    executed_at: str
    outcome: str | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class AutonomyProfile:
    """Autonomy control surface for a CapabilityDescriptor (v0.3.4).

    tier:            Invocation mode constraint.  ``approval_required`` gates every
                     invocation until an external ``approval_granted`` event is recorded.
    spend_limit:     Maximum cumulative spend per correlation_id (spend_units × invocations).
                     None = unlimited.
    spend_units:     Cost per invocation (default 1.0). Multiply by execution_started count
                     to compute cumulative spend for spend_limit comparison.
    action_limit:    Maximum execution_started events per correlation_id. None = unlimited.
    rollback_policy: Governance intent — declared in evidence but not mechanically enforced
                     in v0.3.4.
    """

    tier: AutonomyTier = "supervised"
    spend_limit: float | None = None
    spend_units: float = 1.0
    action_limit: int | None = None
    rollback_policy: RollbackPolicy = "none"

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class CapabilityDescriptor:
    # ── Core identity (required) ──────────────────────────────────────────
    id: str
    version: str
    description: str

    # ── Extended identity (optional catalog alignment) ────────────────────
    name: str | None = None
    category: str | None = None
    provider: str | None = None
    status: CapabilityStatus = "draft"

    # ── Invocation contract ───────────────────────────────────────────────
    modes: list[str] = field(default_factory=lambda: ["sync"])
    input_schema: JSON = field(default_factory=dict)
    output_schema: JSON = field(default_factory=dict)
    idempotency: CapabilityIdempotency = "optional"
    side_effects: list[str] = field(default_factory=list)

    # ── Governance ────────────────────────────────────────────────────────
    invariants: list[InvariantDescriptor] = field(default_factory=list)
    risk: Literal["low", "medium", "high", "critical"] = "low"

    # ── Observability ─────────────────────────────────────────────────────
    emits: list[str] = field(
        default_factory=lambda: [
            "execution_started",
            "execution_completed",
            "execution_failed",
            "execution_denied",
        ]
    )
    assurance: AssuranceMetadata = field(default_factory=AssuranceMetadata)

    # ── Organization ──────────────────────────────────────────────────────
    owner: str | None = None
    tags: list[str] = field(default_factory=list)
    metadata: JSON = field(default_factory=dict)

    # ── Composability ─────────────────────────────────────────────────────
    depends_on: list[str] | None = None

    # ── Structured optional sub-objects ───────────────────────────────────
    host_requirements: HostRequirements | None = None
    policy: PolicyDescriptor | None = None
    autonomy: AutonomyProfile | None = None
    cost_hint: CostHint | None = None       # §7.2 agent interface
    safety_hint: SafetyHint | None = None   # §7.2 agent interface

    @property
    def capability_uri(self) -> str:
        return f"{self.id}:{self.version}"

    def to_dict(self) -> JSON:
        data = asdict(self)
        data["capability_uri"] = self.capability_uri
        # omit null optional sub-objects to keep serialised output lean
        for key in ("depends_on", "host_requirements", "policy", "autonomy", "cost_hint", "safety_hint"):
            if data.get(key) is None:
                data.pop(key, None)
        return data


@dataclass(slots=True)
class HostDescriptor:
    id: str
    version: str = "0.1.0"
    protocol_version: str = "0.1"
    kind: str = "local"
    capabilities: list[CapabilityDescriptor] = field(default_factory=list)
    evidence: JSON = field(default_factory=lambda: {"store": "sqlite", "append_only": True})
    metadata: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return {
            "id": self.id,
            "version": self.version,
            "protocol_version": self.protocol_version,
            "kind": self.kind,
            "capabilities": [cap.to_dict() for cap in self.capabilities],
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class DenialReason:
    code: str
    message: str
    invariant_id: str | None = None
    retryable: bool = False
    details: JSON = field(default_factory=dict)

    # Normative registry: the reserved denial codes a conforming host emits at the
    # governed boundary (spec/chp-governance-v0.2.md §2). The runtime, the schema
    # examples, and the spec MUST agree on this set — guarded by protocol_checks.
    # Vendor-specific codes MUST be reverse-DNS namespaced (e.g. "com.acme.quota").
    RESERVED_CODES: ClassVar[frozenset[str]] = frozenset({
        "capability_not_found",           # no capability with that id/version
        "capability_disabled",            # registered but disabled by the host
        "unsupported_mode",               # invoke mode the host doesn't support
        "policy_blocked",                 # PolicyConfig rule (pattern or risk tier) blocked it
        "input_schema_validation_failed", # payload failed the capability's input schema
        "invariant_failed",               # a declared invariant did not hold
        "budget_exceeded",                # AutonomyProfile budget (calls/tokens/cost) exhausted
        "approval_required",              # human approval gate not satisfied
        "safety_blocked",                 # a safety guardrail blocked the invocation
    })

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class InvocationEnvelope:
    capability_id: str
    payload: JSON = field(default_factory=dict)
    version: str | None = None
    invocation_id: str = field(default_factory=lambda: new_id("inv"))
    mode: str = "sync"
    correlation: CorrelationContext = field(default_factory=CorrelationContext)
    subject: JSON = field(default_factory=lambda: {"id": "local", "type": "user"})
    requested_at: str = field(default_factory=utc_now)
    metadata: JSON = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: JSON) -> "InvocationEnvelope":
        return cls(
            invocation_id=value.get("invocation_id") or new_id("inv"),
            capability_id=value["capability_id"],
            version=value.get("version"),
            mode=value.get("mode", "sync"),
            correlation=CorrelationContext.from_mapping(value.get("correlation")),
            subject=dict(value.get("subject") or {"id": "local", "type": "user"}),
            payload=dict(value.get("payload") or value.get("arguments") or {}),
            requested_at=value.get("requested_at") or utc_now(),
            metadata=dict(value.get("metadata") or {}),
        )

    def to_dict(self) -> JSON:
        data = asdict(self)
        data["correlation"] = self.correlation.to_dict()
        return data


@dataclass(slots=True)
class ExecutionEvidence:
    event_id: str
    event_type: str
    invocation_id: str
    capability_id: str
    capability_version: str | None
    host_id: str
    correlation: CorrelationContext
    timestamp: str = field(default_factory=utc_now)
    sequence: int = 0
    outcome: ExecutionOutcome | None = None
    payload: JSON = field(default_factory=dict)
    redacted: bool = True
    error: JSON | None = None
    denial: DenialReason | None = None
    subject: JSON | None = None
    assurance: AssuranceMetadata = field(default_factory=AssuranceMetadata)

    def to_dict(self) -> JSON:
        data = asdict(self)
        data["correlation"] = self.correlation.to_dict()
        data["assurance"] = self.assurance.to_dict()
        if self.denial is not None:
            data["denial"] = self.denial.to_dict()
        if self.subject is None:
            data.pop("subject", None)
        return data


@dataclass(slots=True)
class ConversationEvent:
    """A conversation turn stored as a first-class event in the evidence chain.

    Slots into evidence_events alongside ExecutionEvidence using the same
    hash-chaining fields. invocation_id is set to the event's own ID and
    capability_id uses the sentinel "chp.core.conversation.turn".
    """

    event_id: str                          # "conv_<uuid>"
    correlation: CorrelationContext
    role: str                              # "user" | "assistant" | "system"
    agent: str                             # "claude-code" | "codex" | "gemini" | "chp-agent"
    event_type: str = "conversation_turn"
    timestamp: str = field(default_factory=utc_now)
    sequence: int = 0                      # assigned by store.append()
    content: Any = None                    # full text/blocks; None when redacted
    content_hash: str = ""                 # SHA256 of content — always present
    word_count: int = 0
    subject: JSON | None = None

    def to_dict(self) -> JSON:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "invocation_id": self.event_id,          # sentinel: turn is its own invocation
            "capability_id": "chp.core.conversation.turn",
            "host_id": "",
            "correlation": self.correlation.to_dict(),
            "role": self.role,
            "agent": self.agent,
            "timestamp": self.timestamp,
            "sequence": self.sequence,
            "content": self.content,
            "content_hash": self.content_hash,
            "word_count": self.word_count,
            "subject": self.subject,
        }


@dataclass(slots=True)
class InvocationResult:
    invocation_id: str
    capability_id: str
    capability_version: str | None
    correlation: CorrelationContext
    outcome: ExecutionOutcome
    success: bool
    data: Any = None
    error: JSON | None = None
    denial: DenialReason | None = None
    evidence_ids: list[str] = field(default_factory=list)
    started_at: str | None = None
    completed_at: str = field(default_factory=utc_now)

    def to_dict(self) -> JSON:
        data = asdict(self)
        data["correlation"] = self.correlation.to_dict()
        if self.denial is not None:
            data["denial"] = self.denial.to_dict()
        return data


@dataclass(slots=True)
class ReplayQuery:
    correlation_id: str
    limit: int | None = None
    since_sequence: int | None = None
    include_payloads: bool = True

    @classmethod
    def from_mapping(cls, value: JSON) -> "ReplayQuery":
        return cls(
            correlation_id=str(value["correlation_id"]),
            limit=value.get("limit"),
            since_sequence=value.get("since_sequence"),
            include_payloads=bool(value.get("include_payloads", True)),
        )

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class AgentSessionDescriptor:
    """Describes the identity and context of an agent session.

    Enriches an ``AgentSession`` with structured intent, memory scope,
    autonomy tier, and tool manifest — the prerequisite for planning events
    and delegation in later protocol versions.
    """

    session_id: str
    intent: str
    model: str | None = None
    memory_scope: MemoryScope = "session"
    autonomy_tier: AutonomyTier = "supervised"
    tool_manifest: list[str] = field(default_factory=list)
    parent_session_id: str | None = None
    metadata: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return asdict(self)

    @classmethod
    def from_mapping(cls, value: JSON) -> "AgentSessionDescriptor":
        return cls(
            session_id=str(value["session_id"]),
            intent=str(value["intent"]),
            model=value.get("model"),
            memory_scope=value.get("memory_scope", "session"),  # type: ignore[arg-type]
            autonomy_tier=value.get("autonomy_tier", "supervised"),  # type: ignore[arg-type]
            tool_manifest=list(value.get("tool_manifest") or []),
            parent_session_id=value.get("parent_session_id"),
            metadata=dict(value.get("metadata") or {}),
        )


@dataclass(slots=True)
class PlanStep:
    """One step within a plan."""

    step_id: str
    description: str
    capability_id: str | None = None
    status: PlanStepStatus = "pending"
    metadata: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class PlanDescriptor:
    """Describes an agent plan: intent, ordered steps, and optional parent session link."""

    plan_id: str
    intent: str
    steps: list[PlanStep] = field(default_factory=list)
    parent_correlation_id: str | None = None
    metadata: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return asdict(self)

    @classmethod
    def from_mapping(cls, value: JSON) -> "PlanDescriptor":
        raw_steps = value.get("steps") or []
        steps = [
            PlanStep(
                step_id=str(s["step_id"]),
                description=str(s["description"]),
                capability_id=s.get("capability_id"),
                status=s.get("status", "pending"),  # type: ignore[arg-type]
                metadata=dict(s.get("metadata") or {}),
            )
            for s in raw_steps
        ]
        return cls(
            plan_id=str(value["plan_id"]),
            intent=str(value["intent"]),
            steps=steps,
            parent_correlation_id=value.get("parent_correlation_id"),
            metadata=dict(value.get("metadata") or {}),
        )


@dataclass(slots=True)
class EvaluationResult:
    """Structured outcome of an agent reflection or evaluation pass."""

    score: float              # normalised 0.0–1.0
    rubric: str               # what was measured / the scoring criteria
    evaluator: str            # "model" | "human" | "automated"
    evidence_refs: list[str] = field(default_factory=list)  # event IDs cited
    notes: str = ""
    passed: bool | None = None  # optional binary gate for policy enforcement

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class DelegationEnvelope:
    """Describes a governed work handoff between agents, services, or humans."""

    delegation_id: str
    from_session: str               # session_id of the delegating agent
    to_agent: str                   # agent name / capability_id receiving the work
    work_parcel: str                # natural-language description of what is delegated
    acceptance_criteria: list[str] = field(default_factory=list)
    context_ref: str | None = None  # correlation_id of prior context to carry forward
    metadata: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return asdict(self)

    @classmethod
    def from_mapping(cls, value: JSON) -> "DelegationEnvelope":
        return cls(
            delegation_id=str(value["delegation_id"]),
            from_session=str(value["from_session"]),
            to_agent=str(value["to_agent"]),
            work_parcel=str(value["work_parcel"]),
            acceptance_criteria=list(value.get("acceptance_criteria") or []),
            context_ref=value.get("context_ref"),
            metadata=dict(value.get("metadata") or {}),
        )


@dataclass(slots=True)
class ReplayResult:
    correlation_id: str
    events: list[JSON]
    event_count: int
    truncated: bool = False
    replayed_at: str = field(default_factory=utc_now)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class SourceRef:
    """Pointer to a retrieved document or chunk."""

    source_id: str
    title: str | None = None
    score: float | None = None
    excerpt: str | None = None
    uri: str | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class RetrievalResult:
    """Result returned by a RetrievalCapability.retrieve() call."""

    query: str
    source_refs: list[SourceRef]
    result_count: int
    latency_ms: float | None = None
    retrieval_type: Literal["keyword", "vector", "hybrid"] = "keyword"

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class IngestionRecord:
    """Provenance record for a single ingested document."""

    source_id: str
    content_hash: str
    byte_count: int
    content_type: str = "text/plain"
    title: str | None = None
    uri: str | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class IngestionResult:
    """Result returned by IngestionCapability.ingest()."""

    source_uri: str | None
    records: list[IngestionRecord]
    record_count: int
    total_bytes: int
    latency_ms: float | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class TransformationRecord:
    """Provenance record for a single transformation pass."""

    transform_type: str
    input_hash: str
    output_hash: str
    input_byte_count: int
    output_byte_count: int
    params: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class TransformationResult:
    """Result returned by TransformationCapability.transform()."""

    content: str
    transform_type: str
    record: TransformationRecord
    latency_ms: float | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class EntityRecord:
    """A node in the knowledge graph."""

    entity_id: str
    entity_type: str
    label: str | None = None
    properties: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class RelationRecord:
    """A directed edge in the knowledge graph."""

    from_entity_id: str
    to_entity_id: str
    relation_type: str
    properties: JSON = field(default_factory=dict)

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class GraphQueryResult:
    """Result returned by a knowledge graph query or traversal."""

    entities: list[EntityRecord]
    entity_count: int
    query_type: str
    latency_ms: float | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class WorkflowStepResult:
    """Result of a single step within a workflow execution."""

    step_id: str
    capability_id: str
    success: bool
    data: JSON = field(default_factory=dict)
    error: str | None = None
    duration_ms: float | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class WorkflowResult:
    """Result returned by a workflow.run invocation."""

    workflow_id: str
    name: str | None
    steps: list[WorkflowStepResult]
    completed_steps: int
    failed_steps: int
    total_duration_ms: float | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class DomainEventRecord:
    """A domain event stored in the event bus."""

    event_id: str
    event_type: str
    source: str
    data: JSON          # full data — in invocation result only, never in evidence payload
    data_hash: str      # "sha256:<hex>" of json.dumps(data, sort_keys=True)
    emitted_at: str
    correlation_id: str | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class DomainEventQueryResult:
    """Result returned by an events.query invocation."""

    events: list[DomainEventRecord]
    event_count: int
    event_type_filter: str | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class CapabilityMetrics:
    """Aggregated invocation statistics for a single capability (§9.3)."""

    capability_id: str
    invocations: int
    successes: int
    failures: int
    denied: int
    avg_duration_ms: float | None = None
    p50_duration_ms: float | None = None
    p95_duration_ms: float | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class SessionMetricsReport:
    """Full metrics report for a session (correlation_id) (§9.3)."""

    session_id: str
    total_invocations: int
    total_successes: int
    total_failures: int
    capabilities: dict[str, "CapabilityMetrics"]

    def to_dict(self) -> JSON:
        return {
            "session_id": self.session_id,
            "total_invocations": self.total_invocations,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "capabilities": {k: v.to_dict() for k, v in self.capabilities.items()},
        }


@dataclass(slots=True)
class MaturityCriterion:
    """One criterion in a capability maturity assessment (§11.4)."""

    level: int
    id: str
    name: str
    passed: bool
    detail: str | None = None

    def to_dict(self) -> JSON:
        return asdict(self)


@dataclass(slots=True)
class MaturityAssessment:
    """Result of assess_maturity() — level 1–7 score with per-criterion detail (§11.4)."""

    capability_id: str
    level: int
    criteria: list[MaturityCriterion]
    evidence_count: int
    assessed_at: str

    def to_dict(self) -> JSON:
        return {
            "capability_id": self.capability_id,
            "level": self.level,
            "criteria": [c.to_dict() for c in self.criteria],
            "evidence_count": self.evidence_count,
            "assessed_at": self.assessed_at,
        }


@dataclass(slots=True)
class CertificationRecord:
    """Formal attestation that a capability meets a declared maturity level (§11.4)."""

    capability_id: str
    level: int
    granted_by: str
    certified_at: str
    notes: str | None = None

    def to_dict(self) -> JSON:
        return asdict(self)
