"""Capability maturity assessment and formal certification (§11.4)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .types import JSON, MaturityAssessment, MaturityCriterion, utc_now

if TYPE_CHECKING:
    from .registry import RegistryEntry
    from .types import CapabilityDescriptor


_CORE_EMITS: frozenset[str] = frozenset({
    "execution_started",
    "execution_completed",
    "execution_failed",
    "execution_denied",
    "execution_skipped",
})


def assess_maturity(
    capability_id: str,
    *,
    descriptor: "CapabilityDescriptor | None" = None,
    events: list[JSON],
    registry_entry: "RegistryEntry | None" = None,
) -> MaturityAssessment:
    """Evaluate capability maturity criteria L1–L7 and return the highest passing level.

    Levels are cumulative: the returned level N means criteria 1 through N all
    passed and criterion N+1 (if any) did not. A gap in passing (e.g. L3 fails
    while L4 would pass) caps the result at L2.
    """
    event_types = {e.get("event_type") for e in events}
    execution_completed_count = sum(
        1 for e in events if e.get("event_type") == "execution_completed"
    )
    execution_started_count = sum(
        1 for e in events if e.get("event_type") == "execution_started"
    )

    criteria: list[MaturityCriterion] = []

    # L1 — descriptor registered with non-empty id, version, description
    l1 = (
        descriptor is not None
        and bool(descriptor.id)
        and bool(descriptor.version)
        and bool(descriptor.description)
    )
    criteria.append(MaturityCriterion(
        level=1, id="has_descriptor", name="Descriptor registered",
        passed=l1,
        detail=None if l1 else "descriptor is missing or has empty id/version/description",
    ))

    # L2 — at least one successful invocation in evidence
    l2 = execution_completed_count >= 1
    criteria.append(MaturityCriterion(
        level=2, id="has_evidence", name="Successfully invoked",
        passed=l2,
        detail=None if l2 else f"{execution_completed_count} execution_completed events found",
    ))

    # L3 — emits list declares at least one domain-specific (non-core) event type
    declared_domain = (
        [e for e in (descriptor.emits if descriptor else []) if e not in _CORE_EMITS]
        if descriptor else []
    )
    l3 = bool(declared_domain)
    criteria.append(MaturityCriterion(
        level=3, id="declares_domain_events", name="Declares domain events",
        passed=l3,
        detail=None if l3 else "emits list is empty or contains only core execution events",
    ))

    # L4 — category set and tags non-empty
    l4 = (
        descriptor is not None
        and descriptor.category is not None
        and bool(getattr(descriptor, "tags", None))
    )
    criteria.append(MaturityCriterion(
        level=4, id="has_taxonomy", name="Taxonomy complete",
        passed=l4,
        detail=None if l4 else "category or tags not set on descriptor",
    ))

    # L5 — all declared domain emits appear in evidence
    if declared_domain:
        missing = [et for et in declared_domain if et not in event_types]
        l5 = len(missing) == 0
        l5_detail = None if l5 else f"declared emits missing from evidence: {missing}"
    else:
        l5 = False
        l5_detail = "no domain events declared (L3 required)"
    criteria.append(MaturityCriterion(
        level=5, id="emits_complete", name="Emits complete",
        passed=l5, detail=l5_detail,
    ))

    # L6 — measured use: ≥10 execution_started events across evidence
    l6 = execution_started_count >= 10
    criteria.append(MaturityCriterion(
        level=6, id="measured_use", name="Measured use (≥10 invocations)",
        passed=l6,
        detail=None if l6 else f"{execution_started_count} execution_started events found",
    ))

    # L7 — certification_level ≥ 7 recorded in registry
    cert_level = getattr(registry_entry, "certification_level", None) or 0
    l7 = bool(registry_entry is not None and cert_level >= 7)
    criteria.append(MaturityCriterion(
        level=7, id="certified", name="Formally certified",
        passed=l7,
        detail=None if l7 else "no certification_level ≥ 7 in registry",
    ))

    # Level = highest N where criteria[0..N-1] all pass (stop at first failure)
    level = 0
    for c in criteria:
        if c.passed:
            level = c.level
        else:
            break

    return MaturityAssessment(
        capability_id=capability_id,
        level=level,
        criteria=criteria,
        evidence_count=len(events),
        assessed_at=utc_now(),
    )
