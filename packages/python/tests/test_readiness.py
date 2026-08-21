"""Readiness kernel — ReadinessAssessment + VerificationPlan (proposal 0044, Tier B).

Proves readiness is derived from per-requirement four-state (never 'eligible' unless all
satisfied, CHP-RDY-007), is contextual (subject = entity+capability+binding+market, not a
global boolean, CHP-ENT-007), never implies admission (CHP-RDY-003), serializes under schema,
and that an incomplete assessment yields a VerificationPlan of what's outstanding (CHP-RDY-010).
"""

import json
from pathlib import Path

import jsonschema
import pytest

from chp_core import ReadinessAssessment, VerificationPlan

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _schema(name: str) -> dict:
    return json.loads((_SCHEMAS / name).read_text())


_SUBJECT = {"entity": {"id": "e1"}, "capability": {"id": "c1"}, "binding": {"id": "b1"},
            "market": {"id": "internal"}}
_PROFILE = {"id": "prof.migrate", "version": "1"}


def _assess(reqs, **kw):
    return ReadinessAssessment(subject=_SUBJECT, profile=_PROFILE, requirements=reqs,
                               result=ReadinessAssessment.derive_result(reqs, **kw))


def test_derive_never_eligible_unless_all_satisfied():
    reqs = [{"id": "r1", "result": "satisfied"}, {"id": "r2", "result": "satisfied"}]
    assert ReadinessAssessment.derive_result(reqs) == "eligible"
    assert ReadinessAssessment.derive_result([{"id": "r1", "result": "unsatisfied"}]) == "ineligible"
    assert ReadinessAssessment.derive_result([{"id": "r1", "result": "unknown"}]) == "incomplete"
    assert ReadinessAssessment.derive_result([{"id": "r1", "result": "error"}]) == "incomplete"
    assert ReadinessAssessment.derive_result([]) == "incomplete"  # no requirements → not eligible
    assert ReadinessAssessment.derive_result(reqs, stale=True) == "stale"       # expiry override
    assert ReadinessAssessment.derive_result(reqs, suspended=True) == "suspended"


def test_eligible_assessment_serializes_and_is_not_admission():
    a = _assess([{"id": "r1", "result": "satisfied",
                  "assertions": ["asrt_1"], "verification_results": ["vres_1"]}])
    jsonschema.validate(a.to_dict(), _schema("readiness-assessment.schema.json"))
    assert a.is_eligible() is True
    # CHP-RDY-003: readiness is not admission — the type carries no admitted/grant field.
    assert not ({"admitted", "grant", "admission"} & set(a.to_dict()))


def test_contextual_not_global_boolean():
    # CHP-ENT-007/CHP-RDY-001: readiness is per (entity, capability, binding, market),
    # not a boolean on the entity.
    a = _assess([{"id": "r1", "result": "satisfied"}])
    d = a.to_dict()
    assert set(d["subject"]) == {"entity", "capability", "binding", "market"}


def test_incomplete_yields_verification_plan():
    a = _assess([{"id": "r1", "result": "satisfied"}, {"id": "r2", "result": "unknown"}])
    assert a.result == "incomplete"
    plan = VerificationPlan.from_assessment(a, unmet=[{
        "requirement_id": "r2", "claim_type": "chp.migrate.backup_state",
        "acceptable_evidence": ["backup-attestation"], "completion": "pending",
    }])
    out = plan.to_dict()
    jsonschema.validate(out, _schema("verification-plan.schema.json"))
    assert out["outstanding"][0]["requirement_id"] == "r2"


def test_bad_result_rejected():
    with pytest.raises(ValueError):
        ReadinessAssessment(subject=_SUBJECT, profile=_PROFILE, requirements=[], result="ready")
