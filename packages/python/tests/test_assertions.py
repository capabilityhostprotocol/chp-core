"""Evidence-semantics kernel — ClaimType, Assertion, VerificationResult (proposal 0044, Tier B).

Proves the types serialize under their schemas, the four-state verification result never reads
'satisfied' unless every check is satisfied (CHP-VER-007), a bad status is rejected, and
integrity verification stays separate from trust acceptance (CHP-VER-002/011 — there is no
'trusted'/'accepted' field; is_verified() is integrity only).
"""

import json
from pathlib import Path

import jsonschema
import pytest

from chp_core import Assertion, ClaimType, VerificationResult

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _schema(name: str) -> dict:
    return json.loads((_SCHEMAS / name).read_text())


def test_claim_type_serializes_under_schema():
    ct = ClaimType(
        id="org.chp.professional.licence",
        version="1.0.0",
        value_schema={"type": "object", "required": ["licence_no"]},
        description="A professional licence claim.",
        subject_kinds=["person"],
        namespace_authority={"id": "urn:chp:authority:law-society"},
    )
    jsonschema.validate(ct.to_dict(), _schema("claim-type.schema.json"))


def test_assertion_serializes_and_is_evidence_backed():
    a = Assertion(
        claim_type="org.chp.professional.licence",
        issuer={"id": "urn:chp:entity:law-society"},
        subject={"kind": "person", "id": "urn:chp:entity:jane"},
        value={"licence_no": "P-12345"},
        evidence=["evt_abc"],
    )
    out = a.to_dict()
    jsonschema.validate(out, _schema("assertion.schema.json"))
    assert out["issuer"]["id"] and out["subject"]["kind"] == "person"
    # a fresh assertion carries no supersede/revoke (immutability: those create new records)
    assert "supersedes" not in out and "revokes" not in out


def test_verification_result_never_silently_satisfied():
    # CHP-VER-007: any non-satisfied check → result is not satisfied.
    base = {"schema": "satisfied", "integrity": "satisfied", "issuer_identity": "satisfied",
            "subject_binding": "satisfied", "value_binding": "satisfied", "freshness": "satisfied",
            "revocation": "satisfied"}
    assert VerificationResult.derive_result(base) == "satisfied"
    assert VerificationResult.derive_result({**base, "revocation": "unsatisfied"}) == "unsatisfied"
    assert VerificationResult.derive_result({**base, "freshness": "unknown"}) == "unknown"
    assert VerificationResult.derive_result({**base, "integrity": "error"}) == "error"
    assert VerificationResult.derive_result({}) == "unknown"  # no checks → not satisfied


def test_verification_result_serializes_and_integrity_is_not_trust():
    checks = {"integrity": "satisfied", "issuer_identity": "satisfied", "revocation": "satisfied"}
    vr = VerificationResult(
        assertion="asrt_1",
        verifier={"id": "urn:chp:verifier:market"},
        checks=checks,
        result=VerificationResult.derive_result(checks),
    )
    out = vr.to_dict()
    jsonschema.validate(out, _schema("verification-result.schema.json"))
    assert vr.is_verified() is True
    # CHP-VER-002/011: is_verified() is integrity, NOT trust — the type carries no
    # 'trusted'/'accepted' field; a relying policy decides acceptance separately.
    assert "trusted" not in out and "accepted" not in out


def test_verification_result_rejects_bad_status():
    with pytest.raises(ValueError):
        VerificationResult(assertion="a", verifier={"id": "v"}, checks={}, result="maybe")
    with pytest.raises(ValueError):
        VerificationResult(assertion="a", verifier={"id": "v"},
                           checks={"integrity": "definitely"}, result="satisfied")
