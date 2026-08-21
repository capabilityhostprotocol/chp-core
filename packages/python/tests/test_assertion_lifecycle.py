"""Assertion lifecycle — supersession/revocation + value validation (Tier B partials).

CHP-SEM-008: superseded/revoked assertions are excluded from the active set but PRESERVED in
history (immutability — supersede/revoke create new records). CHP-SEM-010: an assertion's value
is validated against its ClaimType.value_schema, four-state, never silently satisfied.
"""

import pytest

from chp_core import Assertion, ClaimType, active_assertions, validate_assertion_value


def _a(value, **kw):
    base = dict(claim_type="chp.identity.licence", issuer={"id": "iss"},
                subject={"kind": "person", "id": "jane"}, value=value)
    base.update(kw)
    return Assertion(**base)


def test_supersession_and_revocation_exclude_but_preserve():
    v1 = _a({"no": "P-1"})
    v2 = _a({"no": "P-2"}, supersedes=v1.id)   # a newer licence supersedes v1
    v3 = _a({"no": "P-9"})
    revoke = _a({"no": "P-9"}, revokes=v3.id)  # v3 is revoked
    all_ = [v1, v2, v3, revoke]

    active = active_assertions(all_)
    active_ids = {a.id for a in active}
    assert v1.id not in active_ids            # superseded
    assert v3.id not in active_ids            # revoked
    assert v2.id in active_ids                # the current licence
    assert all_ == [v1, v2, v3, revoke]       # history preserved — input unchanged, nothing removed


def test_value_validation_four_state():
    ct = ClaimType(id="chp.identity.licence", version="1.0.0",
                   value_schema={"type": "object", "required": ["no"]},
                   description="A licence claim.")
    assert validate_assertion_value(_a({"no": "P-1"}), ct) == "satisfied"
    assert validate_assertion_value(_a({"wrong": "x"}), ct) == "unsatisfied"  # missing required 'no'
    # an invalid value_schema is an error, not a pass
    bad_ct = ClaimType(id="chp.identity.licence", version="1", value_schema={"type": "not-a-type"},
                       description="x")
    assert validate_assertion_value(_a({"no": "P-1"}), bad_ct) == "error"


def test_value_validation_rejects_claim_type_mismatch():
    ct = ClaimType(id="chp.other", version="1", value_schema={"type": "object"}, description="x")
    with pytest.raises(ValueError):
        validate_assertion_value(_a({"no": "P-1"}), ct)  # assertion.claim_type != ct.id
