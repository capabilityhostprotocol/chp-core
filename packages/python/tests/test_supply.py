"""Supply types — ProviderProfile / CapabilityOffer / EvidenceContract (proposal 0048, Tier C).

Proves the supply-side invariants: EvidenceContract is a PROMISE not evidence (no 'evidence
exists' assertion, CHP-CAP-014); ProviderProfile rejects permanent conclusions (CHP-SUP-002);
a CapabilityOffer is not a Core execution record and publishing it is not admission (CHP-SUP-008);
all three serialize under schema.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from chp_core import CapabilityOffer, EvidenceContract, ProviderProfile

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _schema(name: str) -> dict:
    return json.loads((_SCHEMAS / name).read_text())


def test_evidence_contract_is_a_promise_not_evidence():
    ec = EvidenceContract(id="ec_review_v1",
                          execution_produces=["executor_identity", "completion_attestation"],
                          effect_observation={"available": False})
    out = ec.to_dict()
    jsonschema.validate(out, _schema("evidence-contract.schema.json"))
    # CHP-CAP-014: it declares EXPECTED evidence — it does not assert evidence exists.
    assert out["execution_produces"] == ["executor_identity", "completion_attestation"]
    assert not ({"evidence", "verified", "satisfied"} & set(out))


def test_provider_profile_is_descriptive_and_rejects_conclusions():
    p = ProviderProfile(entity={"id": "urn:chp:entity:jane"},
                        capability_declarations=[{"capability": {"id": "legal.review"}}],
                        service_metadata={"turnaround": "48h"})
    jsonschema.validate(p.to_dict(), _schema("provider-profile.schema.json"))
    # CHP-SUP-002: a permanent conclusion may not be encoded on the profile.
    for bad in ("qualified", "authorized", "approved", "trusted"):
        with pytest.raises(ValueError):
            ProviderProfile(entity={"id": "e"}, service_metadata={bad: True})


def test_capability_offer_is_not_admission():
    ec = EvidenceContract(id="ec1", execution_produces=["attestation"])
    offer = CapabilityOffer(binding={"id": "binding_1"}, provider={"id": "urn:chp:entity:jane"},
                            evidence_contract=ec.to_dict(), jurisdiction="CA-ON",
                            commercial_terms={"rate": "500/hr"})
    out = offer.to_dict()
    jsonschema.validate(out, _schema("capability-offer.schema.json"))
    # CHP-SUP-008: publishing an offer is not admission — no admitted/grant field.
    assert not ({"admitted", "grant", "admission", "success"} & set(out))
    assert out["evidence_contract"]["execution_produces"] == ["attestation"]
    assert out["version"] == "1"  # governance-relevant change bumps this (CHP-SUP-006)
