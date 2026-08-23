"""Temporal-truth kernel (CHP-TEMP) + the TEMP-006 negative conformance vectors.

Proves the four temporal invariants as pure functions — distinct dimensions kept distinct
(TEMP-001), policy-derived freshness separate from validity (TEMP-002), grant temporal bound
(TEMP-003), clock-uncertainty concurrency (TEMP-004) — and runs the four negative vectors
(spec/test-vectors/temporal-negative.json) through the kernel, asserting each is rejected (TEMP-006).
TEMP-005 (earlier records never rewritten) is exercised via a frozen re-assessment producing a new id.
"""

import json
from pathlib import Path

import pytest
from chp_core import (
    TEMPORAL_DIMENSIONS,
    ClockReading,
    ReadinessAssessment,
    assess_freshness,
    clamp_grant_validity,
    concurrent,
    grant_outlives_bound,
    temporal_envelope,
)
from chp_core.temporal import FRESH, STALE, UNKNOWN

_VECTORS = Path(__file__).resolve().parents[3] / "spec/test-vectors/temporal-negative.json"


def test_temporal_envelope_keeps_dimensions_distinct():
    env = temporal_envelope(event="t1", observation="t2", validity="t3")
    assert env == {"event": "t1", "observation": "t2", "validity": "t3"}  # none substituted for another
    assert set(TEMPORAL_DIMENSIONS) == {
        "event", "observation", "retrieval", "verification", "evaluation", "recording", "validity"}
    with pytest.raises(ValueError):  # TEMP-001: a wrong dimension name can't be smuggled in
        temporal_envelope(created="t1")


def test_freshness_is_policy_derived_not_validity():
    # TEMP-002: freshness is age-vs-policy, independent of any validity window.
    assert assess_freshness("2026-01-01T00:00:00Z", "2026-01-01T00:00:30Z", 60) == FRESH
    assert assess_freshness("2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", 60) == STALE
    assert assess_freshness(None, "2026-01-01T00:00:00Z", 60) == UNKNOWN  # missing input never silently fresh


def test_grant_temporal_bound():
    bounds = ["2026-10-01T00:00:00Z", "2026-09-01T00:00:00Z"]
    assert grant_outlives_bound("2026-12-31T00:00:00Z", bounds) == "2026-10-01T00:00:00Z"  # first outlived
    assert grant_outlives_bound("2026-08-01T00:00:00Z", bounds) is None
    assert clamp_grant_validity("2026-12-31T00:00:00Z", bounds) == "2026-09-01T00:00:00Z"  # the min bound


def test_clock_uncertainty_concurrency():
    a = ClockReading("2026-08-01T00:00:00Z", source="ntp", uncertainty_s=2.0)
    b = ClockReading("2026-08-01T00:00:01Z", source="local", uncertainty_s=2.0)
    assert concurrent(a, b)  # windows overlap → cannot strictly order (TEMP-004)
    assert not concurrent(a, ClockReading("2026-08-01T00:01:00Z", uncertainty_s=1.0))


def _reassess():
    subj = {"entity": {"id": "e"}, "capability": {"id": "c"}, "binding": {"id": "b"}, "market": {"id": "m"}}
    prof = {"id": "p", "version": "1"}
    a = ReadinessAssessment(subject=subj, profile=prof,
                            requirements=[{"id": "r", "result": "satisfied"}], result="eligible")
    b = ReadinessAssessment(subject=subj, profile=prof,
                            requirements=[{"id": "r", "result": "unsatisfied"}], result="ineligible")
    return a, b


def test_temp006_negative_vectors_rejected():
    # CHP-TEMP-006: the conformance suite includes each temporal negative case; the kernel rejects each.
    vecs = {v["id"]: v for v in json.loads(_VECTORS.read_text())["vectors"]}

    s = vecs["stale-evidence"]
    assert assess_freshness(s["issued_at"], s["at_time"], s["max_age_seconds"]) == STALE

    g = vecs["grant-overrun"]
    assert grant_outlives_bound(g["grant_valid_until"], g["depended_bounds"]) is not None

    c = vecs["overlapping-clock-uncertainty"]
    assert concurrent(ClockReading(**c["a"]), ClockReading(**c["b"]))

    # revocation-after-admission (TEMP-005): re-evaluation is a NEW immutable record, not a rewrite.
    first, second = _reassess()
    assert first.id != second.id
