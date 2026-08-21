"""Readiness historical non-rewrite + re-evaluation (proposal 0053; CHP-RDY-008/005).

A historical ReadinessAssessment is immutable — it can never be rewritten in place; re-evaluation
constructs a NEW record and leaves the prior one untouched. This is the readiness analogue of the
append-only evidence thesis: readiness over time is a sequence of records, not a mutated verdict.
"""

import dataclasses

import pytest

from chp_core import ReadinessAssessment

_SUBJECT = {"entity": "urn:chp:entity:jane", "capability": "legal.review", "binding": "b1", "market": "legal"}
_PROFILE = {"id": "p", "version": "1"}


def _assess(reqs):
    return ReadinessAssessment(subject=_SUBJECT, profile=_PROFILE, requirements=reqs,
                               result=ReadinessAssessment.derive_result(reqs))


def test_assessment_is_frozen_cannot_be_rewritten():
    # CHP-RDY-008: a historical assessment MUST NOT be rewritten in place.
    a = _assess([{"id": "r1", "result": "satisfied"}])
    assert a.result == "eligible"
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.result = "ineligible"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.requirements.clear() or setattr(a, "requirements", [])  # type: ignore[misc]


def test_reevaluation_is_a_new_record_prior_preserved():
    # CHP-RDY-005: re-evaluation as inputs change produces a DISTINCT new assessment; the prior
    # record is unchanged (append, don't mutate).
    first = _assess([{"id": "r1", "result": "satisfied"}])          # eligible
    second = _assess([{"id": "r1", "result": "unsatisfied"}])       # ineligible — input went stale
    assert first.result == "eligible" and second.result == "ineligible"
    assert first.id != second.id                                    # distinct records
    assert first.requirements == [{"id": "r1", "result": "satisfied"}]  # prior untouched


def test_bad_result_still_rejected_under_frozen():
    with pytest.raises(ValueError):
        ReadinessAssessment(subject=_SUBJECT, profile=_PROFILE, requirements=[], result="maybe")
