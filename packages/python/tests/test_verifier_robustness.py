"""Crypto/evidence verifier robustness (proposal 0042). CHP's security foundation is
signed evidence: a hostile bundle/attestation/mandate/token/anchor/receipt with missing,
wrong-type, truncated, or nonsense fields must ALWAYS yield a clean *invalid* verdict —
never raise (a DoS) and never falsely verify (a security break). This fuzzes every public
verifier with a matrix of garbage and asserts both properties."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import signing, rekor

# Valid-JSON garbage: not-a-dict, empty, wrong-typed fields, truncated crypto, nesting.
GARBAGE = [
    None, {}, [], "a string", 42, True, 3.14,
    {"kind": "wrong"},
    {"signature": "not-a-dict"},
    {"signature": {}},
    {"signature": {"algorithm": "ed25519", "key_id": "x", "signature": "!!notb64!!"}},
    {"events": "not-a-list"},
    {"events": [123, "x"]},
    {"events": [{"event_id": None}]},
    {"subject": "not-a-dict", "capability_id": 123},
    {"anchor": 123},
    {"anchor": {"type": "rekor"}},
    {"anchor": {"type": "did", "did": 123, "countersignature": []}},
    {"recipient": 5, "who": [], "signature": None},
    {"caller": None, "sub": {}, "aud": [], "iat": 1, "exp": None},
    {"principal": "x", "scope": 123, "signature": 7},
    {"payload": {"a": {"b": {"c": {"d": {}}}}}},  # nested
    {"root_hash": None, "store_head": [], "sequence": "x"},
]

# (name, callable) — each verifier called with ONLY the untrusted input + defaulted kwargs.
VERIFIERS = [
    ("verify_bundle", lambda g: signing.verify_bundle(g)),
    ("verify_attestation", lambda g: signing.verify_attestation(g)),
    ("verify_mandate", lambda g: signing.verify_mandate(g)),
    ("verify_auth_token", lambda g: signing.verify_auth_token(g, aud="h", at_time="2026-01-01T00:00:00Z")),
    ("verify_store_head_anchor", lambda g: signing.verify_store_head_anchor(g)),
    ("verify_disclosure_receipt", lambda g: signing.verify_disclosure_receipt(g)),
    ("verify_continuity", lambda g: signing.verify_continuity(g)),
    ("verify_revocation", lambda g: signing.verify_revocation(g)),
    ("verify_chain_witness", lambda g: signing.verify_chain_witness(g)),
    ("verify_provenance_statement", lambda g: signing.verify_provenance_statement(g)),
    ("verify_store_head_monitor_report", lambda g: signing.verify_store_head_monitor_report(g)),
    ("verify_rekor_anchor", lambda g: rekor.verify_rekor_anchor(g, log_public_key_pem="not-a-key")),
]


def _is_invalid(result) -> bool:
    """A verdict is 'invalid' whether it's a BundleVerification (.valid False), a bool
    (False), or None (falsy)."""
    valid = getattr(result, "valid", None)
    if valid is not None:
        return valid is False
    return not bool(result)


def test_every_verifier_rejects_garbage_without_crashing() -> None:
    failures: list[str] = []
    for name, fn in VERIFIERS:
        for g in GARBAGE:
            try:
                result = fn(g)
            except Exception as exc:  # noqa: BLE001 — a raise IS the defect we hunt
                failures.append(f"{name} RAISED {type(exc).__name__} on {g!r}: {exc}")
                continue
            if not _is_invalid(result):
                failures.append(f"{name} FALSELY VERIFIED garbage {g!r} → {result}")
    assert not failures, "verifier robustness defects:\n" + "\n".join(failures)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--no-header", "-p", "no:cacheprovider", "--no-cov"]))
