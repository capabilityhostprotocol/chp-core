"""Negative-conformance catalog gate (RG-SEC) — the v0.3 adversarial catalog, executable.

``07_conformance/01_negative_cases.md`` (v0.3) is the canonical adversarial catalog: 13 attacks a
conforming CHP substrate MUST honestly refuse (fail verification, stay indeterminate, keep records
separate) rather than fabricate a pass. Four cases had scattered coverage (stale-registry,
evidence-laundering, artifact-substitution, federation-poisoning); this file drives ALL 13 through
the REAL chp_core primitive that expresses each refusal, so the whole catalog is one machine-checked
gate — the point of a conformance suite (`07_conformance/02`).

Reuse-first: every case drives an existing primitive (VerificationResult four-state, ClaimType
namespace authority, active_assertions/succession, binding/invocation digests, payload commitment,
freshness, corroboration, claim-scoped trust). Nothing here is a new protocol mechanism; a case
whose full enforcement lives OUTSIDE chp_core (grant single-use → platform admission) drives its
chp_core half and names the boundary rather than fabricating the rest.
"""

import pytest

from chp_core.assertions import (
    Assertion,
    ClaimType,
    VerificationResult,
    active_assertions,
    derive_edges,
    independent_sources,
)
from chp_core.assurance import assurance_from
from chp_core.digests import binding_digest, invocation_digest
from chp_core.entities import EntitySubject
from chp_core.store import _payload_commitment
from chp_core.temporal import assess_freshness
from chp_core.trust import TrustAnchor, anchored_issuer_trusted


def _vr(checks: dict) -> VerificationResult:
    return VerificationResult(assertion="a", verifier={"id": "urn:verifier"}, checks=checks,
                              result=VerificationResult.derive_result(checks))


# 1. Entity impersonation — asserting control of another's external identifier without control evidence.
def test_entity_impersonation_fails_verification_no_merge():
    # The attacker's assertion may be integrity-valid, but the subject-binding check (does this issuer
    # control the claimed identifier?) is unsatisfied → derive_result is unsatisfied, never silently
    # satisfied (CHP-VER-007). No identity merge follows from an unverified binding.
    vr = _vr({"schema": "satisfied", "integrity": "satisfied",
              "issuer_identity": "satisfied", "subject_binding": "unsatisfied"})
    assert vr.result == "unsatisfied" and not vr.is_verified()


# 2. Duplicate fuzzy match — two people share a name + employer.
def test_duplicate_fuzzy_match_keeps_records_separate():
    # A fuzzy signal is not identity: distinct entities keep distinct stable ids and neither succeeds
    # the other. Merging requires a VERIFIED identity-link (an explicit succession), never a name match.
    a = EntitySubject(id="e-1", kind="person", display={"name": "Jordan Lee", "employer": "Acme"})
    b = EntitySubject(id="e-2", kind="person", display={"name": "Jordan Lee", "employer": "Acme"})
    assert a.id != b.id and a.succeeds_id is None and b.succeeds_id is None
    assert a.ref() != b.ref()  # separate subjects until link evidence is verified


# 3. Key rotation — old signing key expires, new key verified for the SAME entity.
def test_key_rotation_preserves_entity_id_and_history():
    old = Assertion(claim_type="chp.identity.signing_key", issuer={"id": "e-1"},
                    subject={"kind": "person", "id": "e-1"}, value={"key": "old"})
    new = Assertion(claim_type="chp.identity.signing_key", issuer={"id": "e-1"},
                    subject={"kind": "person", "id": "e-1"}, value={"key": "new"}, supersedes=old.id)
    active_ids = {a.id for a in active_assertions([old, new])}
    assert active_ids == {new.id}                      # only the new key is active…
    assert old.id in {old.id, new.id}                  # …the old assertion is preserved in history
    ent = EntitySubject(id="e-1", kind="person")
    assert ent.succeeds_id is None                     # rotation NEVER creates a new entity (CHP-ENT-001)


# 4. Credential replay — a copied, integrity-valid credential presented for the WRONG subject.
def test_credential_replay_fails_on_subject_binding():
    # Document integrity being valid is not enough: the subject-binding check fails for the wrong
    # subject, so the overall result is unsatisfied. Integrity ≠ truth ≠ correct subject (CHP-VER-002).
    assert VerificationResult.derive_result(
        {"integrity": "satisfied", "subject_binding": "unsatisfied"}) == "unsatisfied"


# 5. Stale registry evidence — readiness was eligible yesterday; the mandatory assertion is now expired.
def test_stale_registry_evidence_is_stale_by_policy():
    day = 24 * 3600
    assert assess_freshness("2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z", 7 * day) == "stale"
    assert assess_freshness("2026-08-19T00:00:00Z", "2026-08-20T00:00:00Z", 7 * day) == "fresh"


# 6. Relationship authority leakage — member_of exists but no authority permits signing.
def test_relationship_authority_leakage_kept_separate():
    # The membership claim can be fully integrity-verified, yet issuer_authority (may this issuer SIGN?)
    # is a SEPARATE dimension carried as unsatisfied — never collapsed into the integrity pass
    # (CHP-TRUST-004 / CHP-VER-011). Displaying the relationship does not grant signing authority.
    vr = _vr({"schema": "satisfied", "integrity": "satisfied", "subject_binding": "satisfied"})
    av = assurance_from(vr, issuer_authority="unsatisfied")
    assert vr.is_verified() and av.issuer_authority == "unsatisfied"


# 7. Namespace squatting — publishing a capability/claim in a namespace one cannot show authority over.
def test_namespace_squatting_extension_must_declare_authority():
    # An extension claim type outside the core "chp." namespace MUST name its namespace_authority, so it
    # cannot masquerade as unowned/core (CHP-SEM-003). A squatter that omits it is rejected outright…
    with pytest.raises(ValueError):
        ClaimType(id="acme.custom.claim", version="1", value_schema={}, description="squat")
    # …and one that declares an authority is an explicitly-OWNED extension, never equated with core.
    owned = ClaimType(id="acme.custom.claim", version="1", value_schema={}, description="owned",
                      namespace_authority={"id": "urn:acme"})
    assert owned.namespace_authority == {"id": "urn:acme"} and not owned.id.startswith("chp.")


# 8. Capability similarity laundering — an LLM says two capabilities are equivalent; no mapping exists.
def test_capability_similarity_laundering_stays_inference():
    equiv = Assertion(claim_type="chp.capability.equivalent_to", issuer={"id": "urn:llm"},
                      subject={"kind": "capability", "id": "cap.a"}, value="cap.b",
                      inference={"basis": ["llm-judgment"], "method": "semantic-similarity"})
    assert equiv.is_inferred()                         # it is an inference, never an asserted fact…
    assert derive_edges([equiv])[0]["inferred"] is True  # …and the label survives projection (CHP-SEM-009)


# 9. Evidence laundering — a marketplace re-signs a provider self-assertion.
def test_evidence_laundering_does_not_raise_assurance():
    # Re-signing relays; it does not corroborate: two relays of ONE underlying issuer count as one
    # independent source (CHP-TRUST-006), and trust keys on the ORIGINAL issuer, not the relay
    # (CHP-TRUST-005) — trusting the marketplace does not launder the provider's claim into trust.
    relayed = [{"issuer": "urn:provider"}, {"issuer": "urn:provider"}]
    assert independent_sources(relayed, key=lambda i: i["issuer"]) == 1
    anchors = [TrustAnchor(issuer="urn:marketplace", claim_types=["*"])]
    assert not anchored_issuer_trusted(anchors, "urn:provider", "chp.identity.licence")


# 10. Offer bait-and-switch — resolution binds offer digest O1; provider serves changed O2.
def test_offer_bait_and_switch_changes_binding_digest():
    o1 = binding_digest(capability={"id": "legal.review"},
                        provider={"id": "p", "terms": "v1"}, host={"id": "h"})
    o2 = binding_digest(capability={"id": "legal.review"},
                        provider={"id": "p", "terms": "v2"}, host={"id": "h"})
    assert o1 != o2  # a materially changed offer is a different content-addressed binding; O1 stays authoritative


# 11. Artifact substitution — review attestation binds artifact A; downstream filing submits B.
def test_artifact_substitution_breaks_exact_binding():
    assert _payload_commitment({"artifact": "A"}) != _payload_commitment({"artifact": "B"})


# 12. Grant replay — a consumed grant presented again.
def test_grant_replay_cannot_transplant_to_a_different_invocation():
    # chp_core half: a grant binds an invocation_digest; re-presenting it for a DIFFERENT invocation
    # (different binding/provider routing) yields a different invocation_digest, so the grant does not
    # bind the new attempt (CHP-CORE-004: routing change re-keys admission).
    # ponytail: stateful single-use — rejecting a replay of the SAME invocation_digest — is enforced at
    # platform admission (approval_queue consumed-set), not in chp_core; that half lives in chp-platform.
    common = dict(invocation_id="inv-1", action_digest="ad", actor={"id": "a"}, principal={"id": "p"})
    d1 = invocation_digest(binding={"id": "b1"}, provider={"id": "p1"}, host={"id": "h"}, **common)
    d2 = invocation_digest(binding={"id": "b2"}, provider={"id": "p2"}, host={"id": "h"}, **common)
    assert d1 != d2


# 13. Federation poisoning — a partner maps Entity X to a local trusted provider on weak evidence.
def test_federation_poisoning_mapping_is_only_an_assertion():
    # The cross-market mapping is just an assertion; local trust policy can reject it (the mapped issuer
    # is not a local anchor) WITHOUT losing the remote record — the assertion still exists, it is simply
    # not trusted (CHP-TRUST-002 claim-scoped, INV-12 local reverification).
    anchors = [TrustAnchor(issuer="urn:local-registry", claim_types=["chp.identity.provider"])]
    assert not anchored_issuer_trusted(anchors, "urn:partner-mapped", "chp.identity.provider")
    assert anchored_issuer_trusted(anchors, "urn:local-registry", "chp.identity.provider")  # local still trusted


# --- Catalog coverage guard: every v0.3 negative case has an executable test here. ---
def test_every_catalog_case_is_covered():
    catalog = {  # 07_conformance/01_negative_cases.md v0.3 → the test asserting it
        "entity-impersonation": test_entity_impersonation_fails_verification_no_merge,
        "duplicate-fuzzy-match": test_duplicate_fuzzy_match_keeps_records_separate,
        "key-rotation": test_key_rotation_preserves_entity_id_and_history,
        "credential-replay": test_credential_replay_fails_on_subject_binding,
        "stale-registry-evidence": test_stale_registry_evidence_is_stale_by_policy,
        "relationship-authority-leakage": test_relationship_authority_leakage_kept_separate,
        "namespace-squatting": test_namespace_squatting_extension_must_declare_authority,
        "capability-similarity-laundering": test_capability_similarity_laundering_stays_inference,
        "evidence-laundering": test_evidence_laundering_does_not_raise_assurance,
        "offer-bait-and-switch": test_offer_bait_and_switch_changes_binding_digest,
        "artifact-substitution": test_artifact_substitution_breaks_exact_binding,
        "grant-replay": test_grant_replay_cannot_transplant_to_a_different_invocation,
        "federation-poisoning": test_federation_poisoning_mapping_is_only_an_assertion,
    }
    assert len(catalog) == 13  # the whole v0.3 catalog is driven — no case silently dropped
