"""Four-state InvariantEvaluation (proposal 0043, CHP-CORE-028/017).

Proves the four states are distinct, only 'satisfied' satisfies (unknown/error/unsatisfied
never do), a bad state is rejected at construction, the live binary/None gate maps to the
four states without collapsing uncertainty, and the type slots into AdmissionDecision.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from chp_core import AdmissionDecision, InvariantEvaluation

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "schemas/invariant-evaluation.schema.json").read_text()
)


def _ive(result: str) -> InvariantEvaluation:
    return InvariantEvaluation(invocation_id="inv1", invariant_id="policy.blocklist", result=result)


def test_only_satisfied_satisfies():
    assert _ive("satisfied").is_satisfied()
    for bad in ("unsatisfied", "unknown", "error"):
        assert not _ive(bad).is_satisfied()  # CHP-CORE-017: never treated as satisfied


def test_bad_state_rejected():
    with pytest.raises(ValueError):
        _ive("maybe")


def test_status_from_bridge_never_collapses_uncertainty():
    assert InvariantEvaluation.status_from(True) == "satisfied"
    assert InvariantEvaluation.status_from(False) == "unsatisfied"
    assert InvariantEvaluation.status_from(None) == "unknown"   # can't determine != satisfied
    assert InvariantEvaluation.status_from(True, errored=True) == "error"  # raised != satisfied


def test_serializes_under_schema_for_every_state():
    for state in ("satisfied", "unsatisfied", "unknown", "error"):
        jsonschema.validate(_ive(state).to_dict(), _SCHEMA)


def test_slots_into_admission_decision():
    evals = [_ive("satisfied"), _ive("unknown")]
    d = AdmissionDecision(
        invocation_id="inv1",
        invocation_digest="sha256:" + "0" * 64,
        result="denied",  # an unknown mandatory invariant blocks admission, not admits it
        invariant_evaluations=[e.to_admission_ref() for e in evals],
    )
    out = d.to_dict()
    assert out["invariant_evaluations"] == [
        {"id": "policy.blocklist", "status": "satisfied"},
        {"id": "policy.blocklist", "status": "unknown"},
    ]
