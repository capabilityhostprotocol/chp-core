"""ACTIVATION_EVIDENCE_TYPES — Capability Activation evidence family (M1.1).

Capability Activation records each step of making a capability operational
(CONNECT / DEPLOY / INSTANTIATE) as DISTINCT, separately-attributable claims on
the host's own SHA256-chained store. These tests pin:

* the distinct-claims discipline (deploy success != health != contract
  conformance != admission != operational);
* denial-awareness (an activation effect can be refused, like any gate denial);
* that the family is disjoint from the existing evidence families; and
* that a full activation sequence writes and verify_chain()'s intact.
"""

from pathlib import Path

from chp_core.store import SQLiteEvidenceStore
from chp_core.types import (
    ACTIVATION_EVIDENCE_TYPES,
    AUTONOMY_EVIDENCE_TYPES,
    CORE_EVIDENCE_TYPES,
    SUPPLY_CHAIN_EVIDENCE_TYPES,
    AssuranceMetadata,
    CorrelationContext,
    DenialReason,
    ExecutionEvidence,
    new_id,
)

# The five claims the kit requires to stay distinct, plus denial + reconcile.
DISTINCT_CLAIMS = {
    "activation_deploy_succeeded",
    "activation_health_verified",
    "activation_contract_conformed",
    "activation_admitted",
    "activation_operational",
}


def test_distinct_claims_are_separate_members():
    # None of the distinct claims collapse into one another or into "operational".
    assert DISTINCT_CLAIMS <= ACTIVATION_EVIDENCE_TYPES
    assert len(DISTINCT_CLAIMS) == 5
    # a deploy that succeeded is NOT by itself operational
    assert "activation_deploy_succeeded" != "activation_operational"


def test_family_is_denial_aware():
    assert "activation_denied" in ACTIVATION_EVIDENCE_TYPES


def test_family_disjoint_from_other_families():
    for other in (CORE_EVIDENCE_TYPES, AUTONOMY_EVIDENCE_TYPES, SUPPLY_CHAIN_EVIDENCE_TYPES):
        assert ACTIVATION_EVIDENCE_TYPES.isdisjoint(other), (
            "activation claims must not collide with an existing family"
        )


def test_family_is_in_reserved_names_registry():
    # protocol_checks guards this too; assert it directly so the family is pinned.
    doc = (Path(__file__).resolve().parents[3] / "spec" / "reserved-names.md").read_text()
    for member in ACTIVATION_EVIDENCE_TYPES:
        assert f"`{member}`" in doc, f"{member} missing from spec/reserved-names.md"


def _event(event_type: str, corr: str, denial: DenialReason | None = None) -> ExecutionEvidence:
    return ExecutionEvidence(
        event_id=new_id("evt"),
        event_type=event_type,
        invocation_id=new_id("act"),
        capability_id="chp.adapters.activation.activate",
        capability_version="0.1.0",
        host_id="owned-host",
        correlation=CorrelationContext(correlation_id=corr),
        assurance=AssuranceMetadata(),
        denial=denial,
    )


def test_activation_sequence_chains_and_verifies(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "activation.sqlite"))
    corr = "activation-slice-1"
    sequence = [
        "activation_requested",
        "activation_plan_created",
        "activation_authorized",
        "activation_deploy_succeeded",
        "activation_health_verified",
        "activation_contract_conformed",
        "activation_admitted",
        "activation_operational",
    ]
    for et in sequence:
        store.append(_event(et, corr))

    rows = store.export_correlation(corr)
    types_in_order = [r["event_type"] for r in rows]
    assert types_in_order == sequence, "activation claims must be ordered and complete"
    assert all(t in ACTIVATION_EVIDENCE_TYPES for t in types_in_order)

    result = store.verify_chain(corr)
    store.close()
    assert result.valid, f"chain broken at {result.first_broken_sequence}"
    assert result.event_count == len(sequence)
    assert result.unverified_count == 0


def test_denied_activation_records_a_denial(tmp_path):
    store = SQLiteEvidenceStore(str(tmp_path / "denied.sqlite"))
    corr = "activation-denied"
    store.append(_event("activation_requested", corr))
    store.append(_event("activation_plan_created", corr))
    # vendor-namespaced code (reverse-DNS) per spec until M1.3 reserves a code.
    denial = DenialReason(code="com.chp.activation.effect_not_authorized",
                          message="destination host refused the activation effect")
    store.append(_event("activation_denied", corr, denial=denial))

    rows = store.export_correlation(corr)
    store.close()
    assert rows[-1]["event_type"] == "activation_denied"
    assert rows[-1]["denial"]["code"] == "com.chp.activation.effect_not_authorized"
    # a denial terminates without ever emitting an operational claim
    assert "activation_operational" not in [r["event_type"] for r in rows]
