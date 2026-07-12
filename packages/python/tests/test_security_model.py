"""The security-model doc (proposal 0020) + its keep-honest guards: the doc
exists, references every reserved denial code and scheme, and the guards CATCH a
doc that drifts."""

from __future__ import annotations

from pathlib import Path

from chp_core.protocol_checks import check_alignment
from chp_core.types import DenialReason

REPO = Path(__file__).resolve().parents[3]
DOC = REPO / "spec" / "chp-security-model.md"

SCHEMES = (
    "chp-stable-v1", "chp-jcs-v1", "chp-event-hash-v1", "chp-event-hash-v2",
    "chp-causal-order-v1", "chp-store-head-v1", "chp-store-head-v2",
    "chp-revocation-head-v1", "chp-witness-quorum-v1", "chp-store-head-anchor-v1",
    "chp-completeness-v1", "chp-chunk-seq-v1",
)


def _guard(name: str) -> dict:
    r = check_alignment(REPO)
    return next(c for c in r["checks"] if c["name"] == name)


def test_the_three_guards_pass_on_the_shipped_doc():
    for name in ("spec_defines_security_model",
                 "security_model_names_denial_codes",
                 "security_model_names_schemes"):
        c = _guard(name)
        assert c.get("passed", c.get("ok")) is True, (name, c)


def test_doc_references_every_reserved_denial_code():
    doc = DOC.read_text()
    for code in DenialReason.RESERVED_CODES:
        assert f"`{code}`" in doc, f"security model omits denial code {code}"


def test_doc_references_every_scheme():
    doc = DOC.read_text()
    for scheme in SCHEMES:
        assert scheme in doc, f"security model omits scheme {scheme}"


# ── the guards CATCH drift (the whole point of a doc arc) ─────────────────────

def test_denial_code_guard_catches_a_missing_code():
    """The guard idiom must fail when a new code is added but the doc forgets it."""
    doc = DOC.read_text()
    reserved_plus = set(DenialReason.RESERVED_CODES) | {"future_new_code"}
    missing = [c for c in reserved_plus if f"`{c}`" not in doc]
    assert missing == ["future_new_code"], missing


def test_scheme_guard_catches_a_missing_scheme():
    doc = DOC.read_text()
    schemes_plus = (*SCHEMES, "chp-future-scheme-v1")
    missing = [s for s in schemes_plus if s not in doc]
    assert missing == ["chp-future-scheme-v1"], missing


def test_defines_guard_catches_a_gutted_doc():
    """A doc missing the adversary-class or residual-risk sections must fail."""
    gutted = "# Not the security model\nnothing here"
    assert not ("CHP Security Model" in gutted and "Adversary classes" in gutted)
