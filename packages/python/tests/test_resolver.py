"""Resolver — CapabilityRequirement / CapabilityResolution / resolve() (proposal 0045, Tier C).

Proves the hard-filter invariant (no preference score compensates for an unsatisfied mandatory
requirement, CHP-RES-002), that ranking happens only among eligible candidates, that resolution
is deterministic + immutable + provenance-bearing and NOT admission (CHP-RES-007/008/009/016),
and that no eligible candidate yields an explicit unresolved record.
"""

import json
from pathlib import Path

import jsonschema

from chp_core import CapabilityRequirement, ResolvedCandidate, resolve

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _schema(name: str) -> dict:
    return json.loads((_SCHEMAS / name).read_text())


def _req():
    return CapabilityRequirement(capability={"id": "database.schema.migrate"},
                                 hard=["deployment_authority", "backup_state"])


def test_hard_filter_dominates_score():
    req = _req()
    # a high-score candidate MISSING a hard constraint must lose to a low-score eligible one.
    strong_but_ineligible = ResolvedCandidate(binding={"id": "b_fast"}, score=1000,
                                              satisfied_hard=["deployment_authority"])  # no backup_state
    weak_but_eligible = ResolvedCandidate(binding={"id": "b_safe"}, score=1,
                                          satisfied_hard=["deployment_authority", "backup_state"])
    res = resolve(req, [strong_but_ineligible, weak_but_eligible])
    assert res.selected == {"id": "b_safe"}          # CHP-RES-002: score never compensates
    assert [c["binding"]["id"] for c in res.candidates] == ["b_safe"]  # ineligible not even ranked


def test_ranking_only_among_eligible_and_serializes():
    req = _req()
    a = ResolvedCandidate(binding={"id": "a"}, score=5, satisfied_hard=req.hard)
    b = ResolvedCandidate(binding={"id": "b"}, score=9, satisfied_hard=req.hard)
    res = resolve(req, [a, b], provenance={"policy": "prod-migrate-v1"})
    assert res.selected == {"id": "b"}               # higher score wins among eligible
    out = res.to_dict()
    jsonschema.validate(out, _schema("capability-resolution.schema.json"))
    jsonschema.validate(req.to_dict(), _schema("capability-requirement.schema.json"))
    assert out["provenance"]["policy"] == "prod-migrate-v1"   # CHP-RES-009
    assert not ({"admitted", "grant", "admission"} & set(out))  # CHP-RES-008: not admission


def test_deterministic_same_inputs_same_result():
    req = _req()
    cands = [ResolvedCandidate(binding={"id": "x"}, score=3, satisfied_hard=req.hard),
             ResolvedCandidate(binding={"id": "y"}, score=3, satisfied_hard=req.hard)]
    r1 = resolve(req, cands)
    r2 = resolve(req, cands)
    # same selection + same candidate order (score tie broken deterministically by id).
    assert r1.selected == r2.selected == {"id": "x"}
    assert [c["binding"]["id"] for c in r1.candidates] == [c["binding"]["id"] for c in r2.candidates]


def test_no_eligible_candidate_is_explicitly_unresolved():
    req = _req()
    only_partial = ResolvedCandidate(binding={"id": "b"}, score=999,
                                     satisfied_hard=["deployment_authority"])  # missing backup_state
    res = resolve(req, [only_partial])
    assert res.result == "unresolved"
    assert res.selected is None
    assert "selected" not in res.to_dict()
    jsonschema.validate(res.to_dict(), _schema("capability-resolution.schema.json"))


def test_qualification_is_a_hard_constraint_excluding_high_score():
    # CHP-RES-004: a qualification is a hard constraint — a high-score candidate lacking it is excluded;
    # only the qualified (lower-score) candidate resolves. No score compensates a missing qualification.
    req = CapabilityRequirement(capability={"id": "legal.review"}, hard=["licensed_professional"])
    unqualified = ResolvedCandidate(binding={"id": "cheap"}, satisfied_hard=[], score=999)
    qualified = ResolvedCandidate(binding={"id": "pro"}, satisfied_hard=["licensed_professional"], score=1)
    res = resolve(req, [unqualified, qualified])
    assert res.result == "resolved" and res.selected["id"] == "pro"


def test_resolution_records_durable_binding_not_display():
    # CHP-RES-010: distinct durable binding ids stay distinct even with an identical display name; the
    # resolution records the durable id, never a display string.
    a = ResolvedCandidate(binding={"id": "bind-A", "display": "Acme"}, satisfied_hard=[], score=5)
    b = ResolvedCandidate(binding={"id": "bind-B", "display": "Acme"}, satisfied_hard=[], score=3)
    res = resolve(CapabilityRequirement(capability={"id": "c"}), [a, b])
    assert [c["binding"]["id"] for c in res.candidates] == ["bind-A", "bind-B"]  # durable ids preserved
    assert res.selected["id"] == "bind-A"


def test_evidence_first_excludes_before_ranking():
    # CHP-RES-015: a top-score candidate whose required evidence is unknown/unsatisfied is excluded
    # BEFORE score is consulted — satisfaction gates optimization.
    from chp_core import EvidenceContract
    req = CapabilityRequirement(capability={"id": "c"}, required_evidence=["signed_opinion"])
    no_ev = ResolvedCandidate(binding={"id": "top"}, satisfied_hard=[], score=999)  # no contract → unknown fit
    with_ev = ResolvedCandidate(
        binding={"id": "ok"}, satisfied_hard=[], score=1,
        evidence_contract=EvidenceContract(id="ec", execution_produces=["signed_opinion"]).to_dict())
    res = resolve(req, [no_ev, with_ev])
    assert res.result == "resolved" and res.selected["id"] == "ok"


def test_resolution_pins_the_exact_offer_version():
    # CHP-SUP-006: the exact offer id+version is preserved through resolution, so a bumped-version
    # offer is a distinct, auditable selection and a mutable offer can't be swapped after selection.
    from chp_core import CapabilityOffer, EvidenceContract, offer_to_candidate
    offer = CapabilityOffer(binding={"id": "b1"}, provider={"id": "p"}, version="3",
                            evidence_contract=EvidenceContract(id="ec", execution_produces=["x"]).to_dict())
    cand = offer_to_candidate(offer, satisfied_hard=[], score=5)
    assert cand.offer == {"id": offer.id, "version": "3"}
    res = resolve(CapabilityRequirement(capability={"id": "c"}), [cand])
    assert res.candidates[0]["offer"] == {"id": offer.id, "version": "3"}


def test_soft_fit_ranks_eligible_but_never_waives_hard():
    # CHP-RES-006: operational/commercial soft fit ranks AMONG the eligible — but a soft-superior
    # candidate that fails a hard constraint is still excluded (CHP-RES-002 dominant).
    from chp_core import soft_fit
    req = CapabilityRequirement(capability={"id": "c"}, hard=["licence"],
                                preferences=["fast", "cheap", "local"])
    poor = ResolvedCandidate(binding={"id": "poor", "meets": ["fast"]}, satisfied_hard=["licence"], score=0)
    rich = ResolvedCandidate(binding={"id": "rich", "meets": ["fast", "cheap", "local"]},
                             satisfied_hard=["licence"], score=0)
    assert soft_fit(req, rich) == 3 and soft_fit(req, poor) == 1
    res = resolve(req, [poor, rich], rank_bonus=lambda c: soft_fit(req, c))
    assert res.selected["id"] == "rich"  # better soft fit wins among eligible
    # a soft-perfect but UNLICENSED candidate is still excluded — soft fit never waives the hard gate
    unlicensed = ResolvedCandidate(binding={"id": "x", "meets": ["fast", "cheap", "local"]},
                                   satisfied_hard=[], score=0)
    res2 = resolve(req, [poor, unlicensed], rank_bonus=lambda c: soft_fit(req, c))
    assert res2.selected["id"] == "poor"


def test_history_rank_is_signal_only_never_waives_evidence():
    # CHP-RES-014: execution history is a ranking signal, but MUST NOT waive a hard constraint or
    # required evidence — a high-history candidate that fails eligibility is still excluded.
    from chp_core import history_rank
    hist = [{"outcome": "success"}] * 5
    assert history_rank(hist) == 5 and history_rank([{"outcome": "failure"}]) == 0
    req = CapabilityRequirement(capability={"id": "c"}, hard=["licence"])
    veteran = ResolvedCandidate(binding={"id": "veteran"}, satisfied_hard=[], score=0)   # great history, UNLICENSED
    rookie = ResolvedCandidate(binding={"id": "rookie"}, satisfied_hard=["licence"], score=0)
    res = resolve(req, [veteran, rookie],
                  rank_bonus=lambda c: history_rank(hist if c.binding["id"] == "veteran" else []))
    assert res.selected["id"] == "rookie"  # the licensed rookie wins; history never waived the hard gate
