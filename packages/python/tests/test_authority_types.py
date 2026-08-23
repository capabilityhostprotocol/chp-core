"""Distinct authority types (CHP-AUTH-012/013) — requesting a capability is not disclosing data,
and selecting a provider is not committing funds. Each is a separate scope namespace."""

from chp_core.signing import commit_allows, disclose_allows, scope_allows


def test_disclosure_authority_is_separate_from_request():
    # A mandate scoped to REQUEST a capability grants NO authority to disclose data (CHP-AUTH-012).
    request_only = ["legal.review", "chp.adapters.audit.*"]
    assert scope_allows(request_only, "legal.review")           # may request
    assert not disclose_allows(request_only, "pii")             # may NOT disclose
    # disclosure requires its own explicit grant
    assert disclose_allows(["disclose:pii", "legal.review"], "pii")


def test_commit_authority_is_separate_from_selection():
    # Authority to SELECT/REQUEST a provider is not authority to COMMIT funds (CHP-AUTH-013).
    select_only = ["legal.review"]
    assert not commit_allows(select_only, "funds")              # selecting != committing
    assert commit_allows(["commit:funds", "legal.review"], "funds")  # explicit commit grant
    # the two authority types don't leak into each other
    assert not disclose_allows(["commit:funds"], "pii")
    assert not commit_allows(["disclose:pii"], "funds")
