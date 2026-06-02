"""Protocol objects for the CHP v0.1 reference implementation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

JSON = dict[str, Any]

CORE_EVIDENCE_TYPES = {
    "execution_started",
    "execution_completed",
    "execution_failed",
    "execution_denied",
    "execution_skipped",
}

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

    # ── Structured optional sub-objects ───────────────────────────────────
    host_requirements: HostRequirements | None = None
    policy: PolicyDescriptor | None = None

    @property
    def capability_uri(self) -> str:
        return f"{self.id}:{self.version}"

    def to_dict(self) -> JSON:
        data = asdict(self)
        data["capability_uri"] = self.capability_uri
        # omit null optional sub-objects to keep serialised output lean
        if data.get("host_requirements") is None:
            del data["host_requirements"]
        if data.get("policy") is None:
            del data["policy"]
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
            payload=dict(value.get("payload") or {}),
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
    assurance: AssuranceMetadata = field(default_factory=AssuranceMetadata)

    def to_dict(self) -> JSON:
        data = asdict(self)
        data["correlation"] = self.correlation.to_dict()
        data["assurance"] = self.assurance.to_dict()
        if self.denial is not None:
            data["denial"] = self.denial.to_dict()
        return data


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
class ReplayResult:
    correlation_id: str
    events: list[JSON]
    event_count: int
    replayed_at: str = field(default_factory=utc_now)

    def to_dict(self) -> JSON:
        return asdict(self)
