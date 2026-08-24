"""CHP-CORE-018 — a CHP-enforced claim requires demonstrable non-bypassable execution control."""
from chp_core import EnforcementControl, assess_enforcement
from chp_core.enforcement import DISCOVERABLE, ENFORCED, OBSERVED


def test_enforced_requires_boundary_verifier_and_no_bypass():
    c = EnforcementControl(boundary="governed-grant", verifier={"id": "grant-signature"})
    assert c.is_non_bypassable() and assess_enforcement(c) == ENFORCED


def test_a_bypass_path_forbids_enforced():
    # CORE-018 MUST NOT: an ungoverned bypass path caps the claim at observed, never enforced
    c = EnforcementControl(boundary="governed-grant", verifier={"id": "x"}, bypass_paths=["out-of-band manual action"])
    assert not c.is_non_bypassable() and assess_enforcement(c) == OBSERVED


def test_unverified_boundary_is_observed_not_enforced():
    assert assess_enforcement(EnforcementControl(boundary="governed-grant")) == OBSERVED


def test_no_boundary_is_discoverable():
    assert assess_enforcement(None) == DISCOVERABLE
    assert assess_enforcement({}) == DISCOVERABLE


def test_accepts_dict_form():
    d = {"boundary": "governed-grant", "verifier": {"id": "v"}, "bypass_paths": []}
    assert assess_enforcement(d) == ENFORCED
