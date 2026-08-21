"""Resolver evidence fit (proposal 0053; CHP-RES-005).

The resolver computes whether a candidate's EvidenceContract satisfies a requirement's evidence
needs — an EvidenceContract is a PROMISE, not evidence, so a satisfied evidence-fit means ELIGIBLE
to resolve, not that the evidence exists. Unknown fit is preserved (CHP-RES-011): a candidate whose
evidence cannot be judged is never silently selected.
"""

from chp_core import (
    CapabilityRequirement,
    ResolvedCandidate,
    evidence_fit,
    resolve,
)
from chp_core.contract import SATISFIED, UNKNOWN, UNSATISFIED
from chp_core.supply import EvidenceContract


def test_evidence_fit_four_state():
    c = EvidenceContract(id="ec", execution_produces=["signed_result", "effect_observation"])
    assert evidence_fit(["signed_result"], c) == SATISFIED           # promised
    assert evidence_fit(["signed_result", "audit_log"], c) == UNSATISFIED  # audit_log not promised
    assert evidence_fit([], c) == SATISFIED                          # nothing required → satisfied
    assert evidence_fit(["signed_result"], None) == UNKNOWN          # no contract → cannot judge


def test_resolve_excludes_candidate_without_promised_evidence():
    # CHP-RES-005 + CHP-RES-011: a candidate lacking the required evidence (or with no contract) is
    # NOT selected; unknown evidence-fit is never silently promoted.
    req = CapabilityRequirement(capability={"id": "legal.review"}, required_evidence=["signed_opinion"])
    good = ResolvedCandidate(binding={"id": "b-good"}, score=1,
                             evidence_contract=EvidenceContract(id="e1", execution_produces=["signed_opinion"]))
    wrong = ResolvedCandidate(binding={"id": "b-wrong"}, score=9,   # higher score cannot compensate
                              evidence_contract=EvidenceContract(id="e2", execution_produces=["draft"]))
    no_contract = ResolvedCandidate(binding={"id": "b-none"}, score=9)  # unknown → excluded
    res = resolve(req, [good, wrong, no_contract])
    assert res.result == "resolved" and res.selected == {"id": "b-good"}
    assert len(res.candidates) == 1
    assert res.candidates[0]["evidence_fit"] == SATISFIED


def test_no_required_evidence_is_a_no_op():
    # Backward compatible: a requirement with no required_evidence gates nothing on evidence.
    req = CapabilityRequirement(capability={"id": "x"})
    c = ResolvedCandidate(binding={"id": "b"}, score=1)
    res = resolve(req, [c])
    assert res.selected == {"id": "b"} and "evidence_fit" not in res.candidates[0]
