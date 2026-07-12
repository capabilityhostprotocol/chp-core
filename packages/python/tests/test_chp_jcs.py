"""chp-jcs-v1 — the second canonicalization (chp-v0.2.md §2, proposal 0015):
the `canonicalization` field as a real dispatch seam."""

from __future__ import annotations

import asyncio

import pytest

from chp_core import signing
from chp_core.host import LocalCapabilityHost
from chp_core.signing import _canon, _canon_for, _canon_jcs
from chp_core.store import SQLiteEvidenceStore
from chp_core.types import CapabilityDescriptor

CORR = "corr-jcs-1"


def _host():
    host = LocalCapabilityHost("jcs-host", store=SQLiteEvidenceStore(":memory:"))

    async def handler(_ctx, payload):
        return {"echo": payload}

    host.register(CapabilityDescriptor(id="j.cap", version="1.0.0", description=""), handler)
    asyncio.run(host.ainvoke("j.cap", {"note": "café 🔒"}, correlation={"correlation_id": CORR}))
    return host


# ── the serializer ───────────────────────────────────────────────────────────

def test_jcs_is_compact_raw_utf8_sorted():
    obj = {"z": "café", "a": 1, "m": {"b": True, "a": None}}
    b = _canon_jcs(obj)
    # compact separators (no spaces), raw UTF-8 (café literal), sorted keys
    assert b == '{"a":1,"m":{"a":null,"b":true},"z":"café"}'.encode("utf-8")
    # emoji stays raw (not 🔒)
    assert _canon_jcs({"k": "🔒"}) == '{"k":"🔒"}'.encode("utf-8")


def test_jcs_differs_from_stable_v1():
    obj = {"note": "café", "n": 2}
    assert _canon_jcs(obj) != _canon(obj)                # different bytes
    assert _canon(obj) == b'{"n": 2, "note": "caf\\u00e9"}'   # stable-v1: spaced + escaped
    assert _canon_jcs(obj) == '{"n":2,"note":"café"}'.encode("utf-8")  # jcs: compact + raw


def test_jcs_rejects_floats():
    with pytest.raises(ValueError, match="rule 6"):
        _canon_jcs({"score": 0.5})
    with pytest.raises(ValueError, match="rule 6"):
        _canon_jcs([1, 2, 3.14])
    # bool is an int subclass — allowed
    assert _canon_jcs({"ok": True}) == b'{"ok":true}'


def test_canon_for_dispatch():
    assert _canon_for("chp-jcs-v1") is _canon_jcs
    assert _canon_for("chp-stable-v1") is _canon
    assert _canon_for(None) is _canon        # absent → default
    assert _canon_for("") is _canon
    with pytest.raises(ValueError, match="unknown canonicalization"):
        _canon_for("chp-nope-v9")


# ── the seam: bundles under each scheme ──────────────────────────────────────

def _signed(canon: str, tmp_path, key=None):
    host = _host()
    key = key or signing.generate_keypair(tmp_path / "k")
    events = host.store.export_correlation(CORR)
    return key, signing.sign_bundle(
        signing.build_bundle("jcs-host", events, created_at="2026-07-11T00:00:00Z",
                             canonicalization=canon), key)


def test_stable_v1_bundle_byte_identical(tmp_path):
    """The default is unchanged — a chp-stable-v1 bundle verifies exactly as before."""
    _, b = _signed("chp-stable-v1", tmp_path)
    assert b["canonicalization"] == "chp-stable-v1"
    assert signing.verify_bundle(b).valid


def test_jcs_bundle_signs_and_verifies(tmp_path):
    _, b = _signed("chp-jcs-v1", tmp_path)
    assert b["canonicalization"] == "chp-jcs-v1"
    v = signing.verify_bundle(b)
    assert v.valid, v.reason
    assert v.checks["signature"] and v.checks["host_identity"]


def test_jcs_and_stable_signatures_differ(tmp_path):
    """Same events + same key, different canon → different header-signature bytes (the seam)."""
    host = _host()
    key = signing.generate_keypair(tmp_path / "k")
    events = host.store.export_correlation(CORR)
    common = dict(created_at="2026-07-11T00:00:00Z")
    s = signing.sign_bundle(signing.build_bundle("jcs-host", events, canonicalization="chp-stable-v1", **common), key)
    j = signing.sign_bundle(signing.build_bundle("jcs-host", events, canonicalization="chp-jcs-v1", **common), key)
    # same root (events unchanged — hash_scheme axis), different header signature
    assert s["root_hash"] == j["root_hash"]
    assert s["signature"]["signature"] != j["signature"]["signature"]
    assert signing.verify_bundle(s).valid and signing.verify_bundle(j).valid


def test_wrong_scheme_at_verify_fails_not_crash(tmp_path):
    _, b = _signed("chp-jcs-v1", tmp_path)
    b["canonicalization"] = "chp-bogus-v1"  # tamper the declared scheme
    v = signing.verify_bundle(b)
    assert not v.valid and v.checks.get("signature") is False


def test_jcs_bundle_verified_under_wrong_serializer_fails(tmp_path):
    """A jcs bundle relabelled chp-stable-v1 fails (the header bytes no longer match)."""
    _, b = _signed("chp-jcs-v1", tmp_path)
    b["canonicalization"] = "chp-stable-v1"
    assert signing.verify_bundle(b).checks.get("signature") is False
