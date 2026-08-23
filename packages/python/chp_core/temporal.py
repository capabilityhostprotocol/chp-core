"""Temporal-truth kernel — the temporal invariants a verifier must agree on (CHP-TEMP).

Time is not one number. An assertion is *issued* at one instant, *observed* at another, *verified*
at a third, holds *validity* over a fourth interval, and is *recorded* at a fifth — collapsing these
loses truth. This kernel keeps the dimensions distinct (TEMP-001), derives freshness from an explicit
policy rather than from the issuer's validity interval (TEMP-002), bounds a grant by the authority it
rests on (TEMP-003), and lets security-relevant ordering decline to order two readings whose clock
uncertainty overlaps (TEMP-004). Pure types + functions; the evaluation SERVICES and the negative
conformance VECTORS layer on top. (TEMP-005 — earlier records are never rewritten — is upheld by the
append-only store + frozen reassessment, not here.)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from .types import JSON

# CHP-TEMP-001: the distinct temporal dimensions. An implementation preserves whichever are present
# rather than silently substituting one for another.
TEMPORAL_DIMENSIONS: tuple[str, ...] = (
    "event", "observation", "retrieval", "verification", "evaluation", "recording", "validity",
)

# Freshness is a three-state: never silently "fresh" when it cannot be determined.
FRESH, STALE, UNKNOWN = "fresh", "stale", "unknown"


def _parse(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp (accepting a trailing 'Z') to an aware datetime."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def temporal_envelope(**times: str | None) -> JSON:
    """Keep only the named temporal dimensions actually supplied — never substitute one for another
    (CHP-TEMP-001). An unknown dimension name is rejected so a caller cannot smuggle a wrong time in
    under a right-sounding key; a None value is simply omitted (the dimension is absent, not zero)."""
    unknown = set(times) - set(TEMPORAL_DIMENSIONS)
    if unknown:
        raise ValueError(f"unknown temporal dimension(s) {sorted(unknown)}; use {TEMPORAL_DIMENSIONS}")
    return {k: times[k] for k in TEMPORAL_DIMENSIONS if times.get(k) is not None}


def assess_freshness(issued_at: str | None, at_time: str | None, max_age_seconds: float | None) -> str:
    """Policy-derived freshness (CHP-TEMP-002): FRESH iff the evidence is no older than the policy
    max-age at at_time. The max-age is a POLICY input, deliberately SEPARATE from the issuer's
    validity interval — evidence can sit well inside its validity window yet be stale by policy, and
    that distinction is the point. Missing any input → UNKNOWN, never silently FRESH."""
    if not issued_at or not at_time or max_age_seconds is None:
        return UNKNOWN
    age = (_parse(at_time) - _parse(issued_at)).total_seconds()
    return FRESH if 0 <= age <= max_age_seconds else STALE


def grant_outlives_bound(grant_valid_until: str, depended_bounds: list[str]) -> str | None:
    """Return the first depended-on validity bound the grant OUTLIVES (grant_valid_until strictly
    after it), else None (CHP-TEMP-003). A grant MUST NOT outlive any mandatory evidence or authority
    validity bound its admission depends on."""
    g = _parse(grant_valid_until)
    for b in depended_bounds:
        if b and g > _parse(b):
            return b
    return None


def clamp_grant_validity(requested_valid_until: str, depended_bounds: list[str]) -> str:
    """The largest valid_until a grant may carry: min(requested, *depended-on bounds) (CHP-TEMP-003)
    — so the minted grant can never outlive the authority it rests on."""
    candidates = [requested_valid_until, *[b for b in depended_bounds if b]]
    return min(candidates, key=_parse)


@dataclass(frozen=True)
class ClockReading:
    """A timestamp WITH its clock source and uncertainty (CHP-TEMP-004), so security-relevant
    ordering can decline to assert a strict order between two readings whose uncertainty windows
    overlap instead of inventing one from skewed wall clocks."""

    time: str
    source: str = "unknown"
    uncertainty_s: float = 0.0

    def interval(self) -> tuple[datetime, datetime]:
        t = _parse(self.time)
        d = timedelta(seconds=self.uncertainty_s)
        return (t - d, t + d)

    def to_dict(self) -> JSON:
        return {"time": self.time, "source": self.source, "uncertainty_s": self.uncertainty_s}


def concurrent(a: ClockReading, b: ClockReading) -> bool:
    """True when a and b CANNOT be strictly ordered — their uncertainty windows overlap (CHP-TEMP-004).
    Callers preserve both/mark concurrent rather than forcing a false order."""
    (a0, a1), (b0, b1) = a.interval(), b.interval()
    return a0 <= b1 and b0 <= a1
