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
