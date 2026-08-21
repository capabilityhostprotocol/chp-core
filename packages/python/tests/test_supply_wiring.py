"""Supply wiring — offer_to_candidate + capabilities.txt projection (proposal 0049, Tier C).

Proves the supply→resolve seam (a published offer becomes a resolver candidate; the hard-filter
still governs) and that the capabilities.txt projection is DISCOVERY ONLY — id/version/description
+ href pointers, and never advertises admission/authorization/qualification (CHP-SUP-009).
"""

import json
from pathlib import Path

import jsonschema

from chp_core import (
    CapabilityDefinition,
    CapabilityOffer,
    CapabilityRequirement,
    EvidenceContract,
    offer_to_candidate,
    project_capabilities_txt,
    resolve,
)

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def test_offer_to_candidate_feeds_the_resolver():
    ec = EvidenceContract(id="ec1", execution_produces=["attestation"])
    good = CapabilityOffer(binding={"id": "b_licensed"}, provider={"id": "jane"},
                           evidence_contract=ec.to_dict())
    weak = CapabilityOffer(binding={"id": "b_unlicensed"}, provider={"id": "para"},
                           evidence_contract=ec.to_dict())
    req = CapabilityRequirement(capability={"id": "legal.review"}, hard=["bar_licence"])
    # the caller evaluates which hard constraints each offer supports (against its evidence).
    candidates = [offer_to_candidate(weak, satisfied_hard=[], score=900),
                  offer_to_candidate(good, satisfied_hard=["bar_licence"], score=1)]
    res = resolve(req, candidates, provenance={"policy": "p"})
    assert res.selected == {"id": "b_licensed"}   # hard filter beats the high-score unlicensed offer


def test_capabilities_txt_is_discovery_only():
    defs = [CapabilityDefinition(id="engineering.design_review", version="1.2",
                                 namespace={"authority": {"id": "a"}}, description="Review an artifact."),
            CapabilityDefinition(id="legal.document.review", version="1.0.0",
                                 namespace={"authority": {"id": "b"}}, description="Review a document.")]
    doc = project_capabilities_txt(host={"id": "host:legal-network", "name": "Legal Network"},
                                   capabilities=defs)
    jsonschema.validate(doc, json.loads((_SCHEMAS / "capabilities-txt.schema.json").read_text()))
    assert doc["chp"] == "0.1"
    ids = [c["id"] for c in doc["capabilities"]]
    assert ids == ["engineering.design_review", "legal.document.review"]  # canonical ids (CHP-SUP-011)
    cap = doc["capabilities"][0]
    assert cap["bindings"]["href"].endswith("/engineering.design_review/bindings")  # href pointer
    # CHP-SUP-009: no admission/authorization/qualification advertised anywhere.
    flat = json.dumps(doc)
    for forbidden in ("admitted", "authorized", "qualified", "grant"):
        assert f'"{forbidden}"' not in flat


def test_projection_is_stable():
    # CHP-SUP-010: the same supply yields the same document.
    d = [CapabilityDefinition(id="c", version="1", namespace={"authority": {"id": "a"}}, description="x")]
    host = {"id": "h", "name": "H"}
    assert project_capabilities_txt(host=host, capabilities=d) == project_capabilities_txt(host=host, capabilities=d)
