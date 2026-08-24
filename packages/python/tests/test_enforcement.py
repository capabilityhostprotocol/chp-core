"""CHP-CORE-018 — a CHP-enforced claim requires demonstrable non-bypassable execution control."""
from chp_core import (
    CapabilityDescriptor,
    EnforcementControl,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    assess_enforcement,
    host_enforcement,
)
from chp_core.enforcement import DISCOVERABLE, ENFORCED, OBSERVED
from chp_core.policy import PolicyConfig


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


# ---- CORE-018: the level is DERIVED from the running host, not self-declared ----

def _host(**policy_kw):
    h = LocalCapabilityHost("h", store=SQLiteEvidenceStore(":memory:"), policy=PolicyConfig(**policy_kw))
    h.register(CapabilityDescriptor(id="svc.x", version="1.0.0", description="x"), lambda _c, _p: {"ok": True})
    return h


def test_governed_host_is_enforced():
    # a host with a real (non-audit) policy is the non-bypassable boundary — every invoke is evidence-wrapped
    # and policy-checked, no public path reaches a handler past a denial (test_core_hardening). So ENFORCED is
    # a fact derived from the host, not a badge it can hand itself.
    assert host_enforcement(_host(block_capability_ids=["svc.blocked"])) == ENFORCED


def test_audit_only_host_is_observed_not_enforced():
    # audit-only records decisions but does NOT block — a denied effect still runs, an ungoverned bypass.
    assert host_enforcement(_host(audit_only=True)) == OBSERVED


def test_host_without_governed_boundary_is_discoverable():
    class _Bare:  # no policy/store wired → nothing governs execution
        policy = None
        store = None
    assert host_enforcement(_Bare()) == DISCOVERABLE
