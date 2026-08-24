"""Core machine contracts + CORE-032 conformance vectors.

Proves the generalized machine contracts this arc adds: EvidenceSubject spans the eight subject
kinds and grants nothing (CORE-019); the invocation schema carries action_digest + invocation_digest
as DISTINCT sha256 fields (CORE-026); the evidence-record schema admits non-invocation subjects with
explicit issuer/claim provenance (CORE-027); and every core candidate schema has BOTH a positive and
a negative conformance vector that a validator accepts / rejects (CORE-032), plus the computational
negatives — a tampered digest and a wall-clock-vs-causal ordering conflict.
"""

import json
from pathlib import Path

import jsonschema
import pytest
from chp_core import EvidenceSubject
from chp_core.digests import invocation_digest, invocation_document
from chp_core.ordering import order_events
from referencing import Registry, Resource

_ROOT = Path(__file__).resolve().parents[3]
_SCHEMAS = _ROOT / "schemas"
_VECTORS = json.loads((_ROOT / "spec/test-vectors/core-schema-vectors.json").read_text())

# a $ref registry over every local schema (keyed by $id) so cross-schema refs (correlation-context, …) resolve
_REGISTRY = Registry().with_resources([
    (d["$id"], Resource.from_contents(d))
    for f in _SCHEMAS.glob("*.schema.json")
    for d in [json.loads(f.read_text())] if "$id" in d
])

# the CORE-CANDIDATE machine-contract schemas that CORE-032 requires pos+neg vectors for before promotion
_CORE_CANDIDATE_SCHEMAS = {
    "evidence-subject.schema.json", "evidence-record.schema.json", "effect-evidence.schema.json",
    "invocation-envelope.schema.json", "chp-approval-grant.schema.json", "evidence-event.schema.json",
}


def _schema(name: str) -> dict:
    return json.loads((_SCHEMAS / name).read_text())


def _validate(instance: object, schema_name: str) -> None:
    jsonschema.Draft202012Validator(_schema(schema_name), registry=_REGISTRY).validate(instance)


def test_evidence_subject_kinds_and_grants_nothing():
    # CORE-019: the eight subject kinds; a non-invocation subject needs no invocation.
    for kind in ("entity", "capability", "binding", "invocation", "execution", "artifact", "effect", "external"):
        s = EvidenceSubject(kind=kind, id="x")
        assert s.to_dict()["kind"] == kind
        jsonschema.validate(s.to_dict(), _schema("evidence-subject.schema.json"))
    with pytest.raises(ValueError):
        EvidenceSubject(kind="nonsense", id="x")
    # kind carries no authority/trust field — it is informational only (mirrors CHP-ENT-003)
    assert set(EvidenceSubject(kind="binding", id="b1").to_dict()) <= {"kind", "id", "ref"}


def test_invocation_schema_carries_both_digests_as_distinct_fields():
    # CORE-026: action_digest and invocation_digest are declared, distinct, sha256-patterned fields.
    schema = _schema("invocation-envelope.schema.json")
    props = schema["properties"]
    assert "action_digest" in props and "invocation_digest" in props
    fld = _VECTORS["invocation_digest_field"]
    for name in ("action_digest", "invocation_digest"):
        jsonschema.validate(fld["valid"], props[name])              # a real sha256 digest validates
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(fld["invalid"], props[name])        # a non-digest is rejected


def test_core032_positive_vectors_accepted():
    for v in _VECTORS["positive"]:
        _validate(v["instance"], v["schema"])    # MUST accept


def test_core032_negative_vectors_rejected():
    for v in _VECTORS["negative"]:
        with pytest.raises(jsonschema.ValidationError):
            _validate(v["instance"], v["schema"])  # MUST reject (CORE-032)


def test_core032_covers_every_core_candidate_schema():
    # CORE-032: EVERY core candidate schema MUST have BOTH a positive and a negative vector before promotion.
    pos = {v["schema"] for v in _VECTORS["positive"]}
    neg = {v["schema"] for v in _VECTORS["negative"]}
    missing_pos = _CORE_CANDIDATE_SCHEMAS - pos
    missing_neg = _CORE_CANDIDATE_SCHEMAS - neg
    assert not missing_pos, f"core candidate schemas without a positive vector: {sorted(missing_pos)}"
    assert not missing_neg, f"core candidate schemas without a negative vector: {sorted(missing_neg)}"


def test_core032_tampered_digest_is_detectable():
    # CORE-032/CHP-CORE-006: a digest is recomputable from its document, so a tampered digest is caught.
    doc = invocation_document(invocation_id="i", action_digest="sha256:" + "a" * 64,
                              actor={"id": "a"}, principal={"id": "p"}, binding={"id": "b1"},
                              provider={"id": "prov"}, host={"id": "h"})
    honest = invocation_digest(**{k: doc[k] for k in
                                  ("invocation_id", "action_digest", "actor", "principal", "binding", "provider", "host")})
    tampered = dict(doc, binding={"id": "b2"})  # someone swapped the binding but kept the old digest
    recomputed = invocation_digest(**{k: tampered[k] for k in
                                      ("invocation_id", "action_digest", "actor", "principal", "binding", "provider", "host")})
    assert recomputed != honest  # the claimed (honest) digest no longer matches the tampered document


def test_core032_causal_order_beats_wall_clock():
    # CORE-032: an adversarial input where wall-clock disagrees with causation — causal order wins.
    events = [
        {"event_id": "e2", "host_id": "h", "sequence": 2, "timestamp": "2026-01-01T00:00:00Z",
         "correlation": {"correlation_id": "c", "causation_id": "e1"}, "invocation_id": "e2"},
        {"event_id": "e1", "host_id": "h", "sequence": 1, "timestamp": "2026-01-01T00:00:05Z",
         "correlation": {"correlation_id": "c"}, "invocation_id": "e1"},
    ]
    ordered = [e["event_id"] for e in order_events(events)]
    assert ordered == ["e1", "e2"]  # cause before effect, despite e1's LATER wall-clock timestamp


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
