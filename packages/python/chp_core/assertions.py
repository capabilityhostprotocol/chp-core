"""Evidence-semantics kernel — ClaimType, Assertion, VerificationResult (proposal 0044,
Tier B). The foundation the entity/readiness layers derive from.

An Assertion is an evidence-backed claim BY an issuer ABOUT a subject — it is NOT truth. A
VerificationResult records per-check four-state outcomes plus the verifier's provenance; a
valid signature proves attribution/integrity, NOT truth (CHP-VER-002), and integrity
verification is SEPARATE from trust-policy acceptance (CHP-VER-011). Trust is decided by a
relying policy, not here — there is no global trusted:true fact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar

from .types import JSON, new_id, utc_now

# The four-state used across CHP admission/verification (shared with InvariantEvaluation).
_STATUSES = frozenset({"satisfied", "unsatisfied", "unknown", "error"})


@dataclass(slots=True)
class ClaimType:
    """A canonical, versioned claim type with a value schema and a namespace authority
    (proposal 0044; CHP-SEM-002/CHP-CAP-002). The authority owns the definition it publishes."""

    id: str
    version: str
    value_schema: JSON
    description: str
    subject_kinds: list[str] = field(default_factory=list)
    namespace_authority: JSON | None = None

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.namespace_authority is None:
            data.pop("namespace_authority", None)
        if not data.get("subject_kinds"):
            data.pop("subject_kinds", None)
        return data


@dataclass(slots=True)
class Assertion:
    """An evidence-backed claim: issuer asserts claim_type about subject with value
    (proposal 0044; CHP-SEM-001/011). Not truth — a VerificationResult evaluates it and a
    relying policy decides trust. Immutable; supersede/revoke create NEW records rather than
    mutating (CHP-SEM-008)."""

    claim_type: str
    issuer: JSON  # {id}
    subject: JSON  # {kind, id}
    value: Any
    id: str = field(default_factory=lambda: new_id("asrt"))
    issued_at: str = field(default_factory=utc_now)
    valid_from: str | None = None
    valid_until: str | None = None
    evidence: list[str] = field(default_factory=list)
    supersedes: str | None = None
    revokes: str | None = None

    def to_dict(self) -> JSON:
        data = asdict(self)
        for k in ("valid_from", "valid_until", "supersedes", "revokes"):
            if data.get(k) is None:
                data.pop(k, None)
        if not data.get("evidence"):
            data.pop("evidence", None)
        return data


@dataclass(slots=True)
class VerificationResult:
    """Structured, immutable outcome of verifying one Assertion (proposal 0044,
    schemas/verification-result.schema.json, CHP-VER-001..010). Preserves per-check
    four-state results, the verifier's provenance, and an overall result.

    None of this is TRUST. A valid signature proves attribution/integrity, not truth
    (CHP-VER-002); integrity verification is SEPARATE from trust-policy acceptance
    (CHP-VER-011). is_verified() reports integrity/structure only — a relying TrustPolicy
    decides acceptance from this result. There is no global trusted:true."""

    assertion: str  # the verified Assertion's id
    verifier: JSON  # {id} — verifier provenance (CHP-VER-009)
    checks: JSON  # {check_name: four-state}
    result: str  # overall four-state
    id: str = field(default_factory=lambda: new_id("vres"))
    verified_at: str = field(default_factory=utc_now)
    valid_until: str | None = None
    details: JSON = field(default_factory=dict)

    CHECKS: ClassVar[tuple[str, ...]] = (
        "schema", "integrity", "issuer_identity", "subject_binding",
        "value_binding", "freshness", "revocation",
    )

    def __post_init__(self) -> None:
        if self.result not in _STATUSES:
            raise ValueError(f"verification result must be one of {sorted(_STATUSES)}")
        bad = {k: v for k, v in self.checks.items() if v not in _STATUSES}
        if bad:
            raise ValueError(f"check statuses must be four-state; got {bad}")

    @staticmethod
    def derive_result(checks: dict[str, str]) -> str:
        """Overall result from per-check four-state. NEVER silently 'satisfied' when any
        check is unsatisfied/error/unknown (CHP-VER-007) — only all-satisfied → satisfied."""
        vals = set(checks.values())
        if "unsatisfied" in vals:
            return "unsatisfied"
        if "error" in vals:
            return "error"
        if "unknown" in vals or not checks:
            return "unknown"
        return "satisfied"

    def is_verified(self) -> bool:
        """Integrity/structure verified (result satisfied) — NOT trust acceptance
        (CHP-VER-011). A relying policy decides whether to accept."""
        return self.result == "satisfied"

    def to_dict(self) -> JSON:
        data = asdict(self)
        if self.valid_until is None:
            data.pop("valid_until", None)
        if not data.get("details"):
            data.pop("details", None)
        return data


def active_assertions(assertions: list[Assertion]) -> list[Assertion]:
    """The ACTIVE subset of a set of assertions (CHP-SEM-008): an assertion is superseded if a
    later assertion supersedes its id, or revoked if any assertion revokes its id. Superseded and
    revoked assertions are PRESERVED in history but excluded from the active set — supersession
    and revocation create NEW records, they never mutate an existing one (immutability)."""
    superseded = {a.supersedes for a in assertions if a.supersedes}
    revoked = {a.revokes for a in assertions if a.revokes}
    inactive = superseded | revoked
    return [a for a in assertions if a.id not in inactive]


def validate_assertion_value(assertion: Assertion, claim_type: ClaimType) -> str:
    """Four-state validation of an assertion's value against its ClaimType.value_schema
    (CHP-SEM-010): satisfied (valid), unsatisfied (invalid), unknown (jsonschema not installed —
    validation could not run, never silently satisfied), error (the value_schema itself is
    invalid). Raises ValueError if the claim_type does not match the assertion's claim_type."""
    if assertion.claim_type != claim_type.id:
        raise ValueError(
            f"claim_type mismatch: assertion={assertion.claim_type!r} claim_type={claim_type.id!r}"
        )
    try:
        import jsonschema
    except ImportError:
        return "unknown"
    try:
        jsonschema.validate(assertion.value, claim_type.value_schema)
        return "satisfied"
    except jsonschema.ValidationError:
        return "unsatisfied"
    except jsonschema.SchemaError:
        return "error"
