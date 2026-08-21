"""Derived graph edges + inference labeling (proposal 0053; CHP-SEM-006/009, + 007/004).

Assertions project into graph edges that are always LABELED derived and traceable to their source
(never mistaken for ground truth), an inferred value is LABELED as an inference (not asserted fact),
contradictory assertions both survive the projection (conflict preserved, never merged), and an
unknown claim type round-trips unchanged (preserved, not dropped).
"""

from chp_core import Assertion, derive_edges

ISS = {"id": "urn:chp:issuer:acme"}
SUBJ = {"kind": "person", "id": "urn:chp:entity:jane"}


def _a(value, **kw):
    return Assertion(claim_type="chp.identity.role", issuer=ISS, subject=SUBJ, value=value, **kw)


# ---- CHP-SEM-009: inference labeling ----

def test_inferred_assertion_is_labeled_and_distinct_from_fact():
    fact = _a("attorney")
    inferred = _a("attorney", inference={"basis": ["asrt_x"], "method": "role-graph"})
    assert not fact.is_inferred() and "inference" not in fact.to_dict()
    assert inferred.is_inferred()
    assert inferred.to_dict()["inference"] == {"basis": ["asrt_x"], "method": "role-graph"}


# ---- CHP-SEM-006: derived graph edges (traceable, labeled derived) ----

def test_derive_edges_labels_derived_and_traces_to_source():
    a = _a("attorney")
    edges = derive_edges([a])
    assert len(edges) == 1
    e = edges[0]
    assert e["kind"] == "derived"                 # never ground truth
    assert e["derived_from"] == a.id              # traceable to the source assertion
    assert e["subject"] == SUBJ and e["predicate"] == "chp.identity.role" and e["object"] == "attorney"
    assert e["inferred"] is False


def test_edge_inherits_inference_flag():
    inferred = _a("partner", inference={"basis": ["asrt_x"], "method": "m"})
    assert derive_edges([inferred])[0]["inferred"] is True


# ---- CHP-SEM-007: conflicting assertions both survive the projection ----

def test_conflicting_assertions_both_projected_not_merged():
    a1 = _a("attorney")
    a2 = _a("paralegal")   # contradicts a1 on the same subject+claim_type, neither supersedes
    edges = derive_edges([a1, a2])
    objects = sorted(e["object"] for e in edges)
    assert objects == ["attorney", "paralegal"]   # both preserved, not reconciled


def test_superseded_assertion_does_not_project():
    a1 = _a("attorney")
    a2 = _a("partner", supersedes=a1.id)
    edges = derive_edges([a1, a2])
    assert [e["object"] for e in edges] == ["partner"]  # only the active one projects (SEM-008)


# ---- CHP-SEM-004: an unknown claim type is preserved, not dropped ----

def test_unknown_claim_type_preserved():
    a = Assertion(claim_type="x.vendor.custom_unknown", issuer=ISS, subject=SUBJ, value={"k": 1})
    assert a.to_dict()["claim_type"] == "x.vendor.custom_unknown"
    assert derive_edges([a])[0]["predicate"] == "x.vendor.custom_unknown"
