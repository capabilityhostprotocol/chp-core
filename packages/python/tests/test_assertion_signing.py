"""Signing-based assertion integrity (proposal 0050, CHP-VER-002).

Proves an assertion can be signed by its issuer's key and verified offline: a valid signature
verifies and binds the signer; tampering the value breaks it; a wrong pinned issuer key fails;
and a non-dict fails closed. A valid signature proves attribution/integrity, not truth.
"""

import tempfile

from chp_core import Assertion
from chp_core.signing import generate_keypair, sign_assertion, verify_assertion_signature


def _assertion() -> dict:
    return Assertion(claim_type="chp.identity.licence", issuer={"id": "urn:chp:issuer:bar"},
                     subject={"kind": "person", "id": "jane"}, value={"no": "P-1"}).to_dict()


def test_sign_and_verify():
    k = generate_keypair(tempfile.mkdtemp())
    signed = sign_assertion(k, _assertion())
    v = verify_assertion_signature(signed)
    assert v.valid
    assert v.checks["signature"] and v.checks["binds_signer"]
    assert signed["signer_identity"]["host_id"] == k.key_id


def test_tampering_the_value_breaks_the_signature():
    k = generate_keypair(tempfile.mkdtemp())
    signed = sign_assertion(k, _assertion())
    tampered = dict(signed)
    tampered["value"] = {"no": "P-EVIL"}
    assert not verify_assertion_signature(tampered).valid   # integrity fails


def test_pinned_issuer_key():
    k = generate_keypair(tempfile.mkdtemp())
    signed = sign_assertion(k, _assertion())
    assert verify_assertion_signature(signed, expected_issuer_key=k.key_id).valid
    assert not verify_assertion_signature(signed, expected_issuer_key="urn:other").valid


def test_fail_closed_on_non_dict():
    assert verify_assertion_signature("not-a-dict").valid is False
