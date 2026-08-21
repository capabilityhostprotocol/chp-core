"""Contract validation + functional fit (proposal 0051).

Proves the runtime enforcement the crosswalk partials were missing: input/output/effect contracts
are checked (CHP-CAP-004/005/006) and the resolver computes functional fit with unknown preserved
(CHP-RES-003/011). The invariant under test throughout: only 'satisfied' satisfies — a missing
schema or undetermined fit is 'unknown', never a silent pass.
"""

import pytest

from chp_core import (
    CapabilityDefinition,
    CapabilityRequirement,
    ResolvedCandidate,
    check_contract,
    check_effect,
    functional_fit,
    resolve,
    validate_input,
    validate_output,
)
from chp_core.contract import SATISFIED, UNKNOWN, UNSATISFIED

NS = {"authority": {"id": "urn:chp:ns:test"}}


def _defn(**kw):
    base = dict(id="doc.summarize", version="1", namespace=NS, description="d")
    base.update(kw)
    return CapabilityDefinition(**base)


# ---- CHP-CAP-004 / 005: input + output contracts ----

_SCHEMA = {"type": "object", "required": ["text"], "properties": {"text": {"type": "string"}}}


def test_valid_input_satisfies():
    d = _defn(input_schema=_SCHEMA)
    assert validate_input(d, {"text": "hi"}) == SATISFIED


def test_invalid_input_unsatisfied():
    d = _defn(input_schema=_SCHEMA)
    assert validate_input(d, {"text": 5}) == UNSATISFIED  # wrong type
    assert validate_input(d, {}) == UNSATISFIED  # missing required


def test_no_schema_is_unknown_never_silent_pass():
    # CHP-CAP-004/005: an undeclared contract cannot be judged — unknown, not satisfied.
    d = _defn()  # no input_schema / output_schema
    assert validate_input(d, {"anything": 1}) == UNKNOWN
    assert validate_output(d, {"anything": 1}) == UNKNOWN


def test_output_contract():
    d = _defn(output_schema=_SCHEMA)
    assert validate_output(d, {"text": "done"}) == SATISFIED
    assert validate_output(d, {"n": 1}) == UNSATISFIED


# ---- CHP-CAP-006: effect semantics ----

def test_effect_must_match_declared():
    d = _defn(effect={"class": "transformative"})
    assert check_effect(d, "transformative") == SATISFIED
    assert check_effect(d, "physical") == UNSATISFIED  # cannot claim an undeclared effect


def test_effect_undeclared_or_unclaimed_is_unknown():
    assert check_effect(_defn(), "transformative") == UNKNOWN  # nothing declared
    assert check_effect(_defn(effect={"class": "advisory"}), None) == UNKNOWN  # nothing claimed


def test_check_contract_aggregates_and_only_satisfied_satisfies():
    d = _defn(input_schema=_SCHEMA, effect={"class": "transformative"})
    ok = check_contract(d, input={"text": "hi"}, effect_class="transformative")
    assert ok.result == SATISFIED and ok.is_satisfied()
    assert ok.definition_id == "doc.summarize@1"
    # one unsatisfied aspect drags the whole result off satisfied
    bad = check_contract(d, input={"text": "hi"}, effect_class="physical")
    assert bad.checks["input"] == SATISFIED and bad.checks["effect"] == UNSATISFIED
    assert bad.result == UNSATISFIED


def test_contract_check_rejects_bad_state():
    from chp_core.contract import ContractCheck
    with pytest.raises(ValueError):
        ContractCheck(definition_id="x", checks={"input": "maybe"}, result="satisfied")


# ---- CHP-RES-003 / 011: functional fit + unknown preservation ----

def test_functional_fit_same_capability_and_effect():
    req = _defn(effect={"class": "transformative"})
    cand = _defn(effect={"class": "transformative"})
    assert functional_fit(req, cand) == SATISFIED


def test_functional_fit_unrelated_capability_does_not_fit():
    req = _defn(id="doc.summarize", effect={"class": "transformative"})
    cand = _defn(id="image.resize", effect={"class": "transformative"})
    assert functional_fit(req, cand) == UNSATISFIED


def test_functional_fit_effect_mismatch_does_not_fit():
    req = _defn(effect={"class": "observational"})
    cand = _defn(effect={"class": "transformative"})
    assert functional_fit(req, cand) == UNSATISFIED


def test_functional_fit_undetermined_is_unknown():
    # No declared effect on either side → cannot judge → unknown (preserved, CHP-RES-011).
    assert functional_fit(_defn(), _defn()) == UNKNOWN


def test_resolve_excludes_unknown_fit_candidate():
    # CHP-RES-011: an unknown-fit candidate must NOT be silently selected.
    req_defn = _defn(effect={"class": "transformative"})
    requirement = CapabilityRequirement(capability={"id": "doc.summarize"})
    unknown_cand = ResolvedCandidate(binding={"id": "b-unknown"}, definition=_defn())  # no effect → unknown
    res = resolve(requirement, [unknown_cand], require_fit=req_defn)
    assert res.result == "unresolved"
    assert res.candidates == []  # excluded, not ranked


def test_resolve_selects_satisfied_fit_and_records_it():
    # CHP-RES-003: computed fit gates eligibility; the satisfied candidate is selected.
    req_defn = _defn(effect={"class": "transformative"})
    requirement = CapabilityRequirement(capability={"id": "doc.summarize"})
    good = ResolvedCandidate(binding={"id": "b-good"}, definition=_defn(effect={"class": "transformative"}), score=5)
    bad = ResolvedCandidate(binding={"id": "b-bad"}, definition=_defn(id="other", effect={"class": "transformative"}))
    res = resolve(requirement, [good, bad], require_fit=req_defn)
    assert res.result == "resolved"
    assert res.selected == {"id": "b-good"}
    assert len(res.candidates) == 1 and res.candidates[0]["functional_fit"] == SATISFIED


def test_resolve_without_require_fit_is_unchanged():
    # Backward compatibility: no require_fit → today's asserted-satisfied_hard behavior, no fit field.
    requirement = CapabilityRequirement(capability={"id": "x"}, hard=["h1"])
    c = ResolvedCandidate(binding={"id": "b"}, satisfied_hard=["h1"], score=1)
    res = resolve(requirement, [c])
    assert res.selected == {"id": "b"}
    assert "functional_fit" not in res.candidates[0]
