"""Assurance vector + conflict preservation (CHP-TRUST-004 / CHP-TRUST-008).

Proves assurance is kept multi-dimensional — the vector carries every dimension and offers NO scalar
rollup (TRUST-004) — and that unresolvable conflicting evidence is PRESERVED as a conflict rather than
silently resolved into certainty (TRUST-008).
"""

from chp_core import (
    Assertion,
    AssuranceVector,
    VerificationResult,
    assurance_from,
    conflicting_assertions,
)

_CHECKS = {"schema": "satisfied", "integrity": "satisfied", "issuer_identity": "satisfied",
           "subject_binding": "satisfied", "value_binding": "satisfied", "freshness": "satisfied",
           "revocation": "satisfied"}


def _vr(**over):
    checks = {**_CHECKS, **over}
    return VerificationResult(assertion="asrt_1", verifier={"id": "v"}, checks=checks,
                              result=VerificationResult.derive_result(checks))


def test_assurance_vector_preserves_dimensions_and_has_no_scalar():
    v = assurance_from(_vr(), issuer_authority="satisfied", corroboration=3, effect="confirmed")
    # every dimension is carried SEPARATELY (TRUST-004) — checks verbatim + the four extra axes
    assert v.checks["integrity"] == "satisfied" and v.checks["freshness"] == "satisfied"
    assert v.issuer_authority == "satisfied"      # a TRUST decision, distinct from integrity
    assert v.corroboration == 3
    assert v.effect == "confirmed"
    # NO scalar rollup exists — that would be the forbidden normative scalar (TRUST-004)
    assert not hasattr(v, "score") and not hasattr(v, "level")
    d = v.to_dict()
    assert set(AssuranceVector.DIMENSIONS) - ({"corroboration", "effect", "issuer_authority"} | set(d["checks"])) == set()


def test_low_integrity_does_not_hide_behind_other_dimensions():
    # A vector with failed integrity still reports fresh/corroborated axes — nothing is averaged away.
    v = assurance_from(_vr(integrity="unsatisfied"), corroboration=5, effect="confirmed")
    assert v.checks["integrity"] == "unsatisfied"
    assert v.corroboration == 5 and v.effect == "confirmed"   # the good axes are NOT what makes it OK


def _asrt(value, issuer="iss", subject_id="jane", ct="chp.identity.licence", **kw):
    return Assertion(claim_type=ct, issuer={"id": issuer},
                     subject={"kind": "person", "id": subject_id}, value=value, **kw)


def test_conflict_is_preserved_not_resolved():
    # CHP-TRUST-008: two active assertions, same subject+claim_type, DIFFERENT values → conflict kept.
    a1 = _asrt({"no": "P-1"})
    a2 = _asrt({"no": "P-2"})               # a contradicting claim from another issuer's projection
    conflicts = conflicting_assertions([a1, a2])
    assert len(conflicts) == 1
    assert conflicts[0]["claim_type"] == "chp.identity.licence"
    assert {v["no"] for v in conflicts[0]["values"]} == {"P-1", "P-2"}   # both kept, neither chosen
    # agreement is NOT a conflict
    assert conflicting_assertions([_asrt({"no": "P-1"}), _asrt({"no": "P-1"})]) == []


def test_superseded_assertion_does_not_conflict():
    # A superseded assertion is not active, so it cannot create a false conflict (CHP-SEM-008).
    a1 = _asrt({"no": "P-1"})
    a2 = _asrt({"no": "P-2"}, supersedes=a1.id)   # a2 supersedes a1 → only a2 is active
    assert conflicting_assertions([a1, a2]) == []


def test_vector_carries_conflicts():
    a1 = _asrt({"no": "P-1"})
    a2 = _asrt({"no": "P-2"})
    v = assurance_from(_vr(), conflicts=conflicting_assertions([a1, a2]))
    assert v.to_dict()["conflicts"][0]["claim_type"] == "chp.identity.licence"
