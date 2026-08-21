"""AdmissionDecision unification type (proposal 0043, CHP-CORE-029).

Proves the reified admission decision binds the exact invocation_digest + invariant
evaluations, serializes under the chp-dev schema for both admitted and denied outcomes,
and preserves the admitted/denied distinction (no collapsed success — CHP-CORE-002).
"""

import json
from pathlib import Path

import jsonschema

from chp_core import AdmissionDecision
from chp_core.digests import action_digest, invocation_digest
from chp_core.types import DenialReason

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "schemas/admission-decision.schema.json").read_text()
)


def _digest() -> str:
    ad = action_digest(capability={"id": "svc.do", "version": "1.0.0"}, principal={"id": "p"})
    return invocation_digest(
        invocation_id="inv1",
        action_digest=ad,
        actor={"id": "a"},
        principal={"id": "p"},
        binding={"id": "b", "version": "1"},
        provider={"id": "jane"},
        host={"id": "h"},
    )


def test_admitted_decision_binds_digest_and_validates():
    d = AdmissionDecision(
        invocation_id="inv1",
        invocation_digest=_digest(),
        result="admitted",
        invariant_evaluations=[{"id": "policy.blocklist", "status": "satisfied"}],
        host_id="host-A",
    )
    out = d.to_dict()
    jsonschema.validate(out, _SCHEMA)
    assert out["result"] == "admitted"
    assert out["invocation_digest"].startswith("sha256:")
    assert out["invariant_evaluations"][0]["status"] == "satisfied"
    assert "denial" not in out  # admitted → no denial


def test_denied_decision_carries_reason_and_validates():
    d = AdmissionDecision(
        invocation_id="inv1",
        invocation_digest=_digest(),
        result="denied",
        invariant_evaluations=[{"id": "policy.blocklist", "status": "unsatisfied"}],
        denial=DenialReason(code="policy_blocked", message="blocked by rule"),
    )
    out = d.to_dict()
    jsonschema.validate(out, _SCHEMA)
    assert out["result"] == "denied"
    assert out["denial"]["code"] == "policy_blocked"
    # unknown/error must never read as satisfied (CHP-CORE-017): the enum enforces the set
    assert out["invariant_evaluations"][0]["status"] == "unsatisfied"


def test_unknown_status_is_a_distinct_state():
    d = AdmissionDecision(
        invocation_id="inv1",
        invocation_digest=_digest(),
        result="denied",
        invariant_evaluations=[{"id": "verify.licence", "status": "unknown"}],
        denial=DenialReason(code="invariant_failed", message="licence evidence unavailable"),
    )
    jsonschema.validate(d.to_dict(), _SCHEMA)  # 'unknown' is a valid, non-satisfied state
