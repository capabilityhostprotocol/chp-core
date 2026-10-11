"""Tests for chp.adapters.safety.tpm_witness_attest — the node-side TPM witness collector.

No TPM is present in CI, so these exercise the fail-closed (W3-base) path, the NV-chain splitter, and
end-to-end interop with the verifier (collector output → verify_tpm_witness) — all offline.
"""

from __future__ import annotations

import base64
import json
from zipfile import ZipFile
from io import BytesIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_safety import SafetyAdapter
from chp_adapter_safety._tpm_collector import _sha256, _split_der_certs, build_attestation, reverify_bundle
from chp_adapter_safety._tpm_witness import WitnessIndependence, verify_tpm_witness


def _make_bundle(extra: dict | None = None) -> bytes:
    """Build a minimal valid chp-safety-case/v0.1 bundle (case.json + signed manifest)."""
    case_bytes = json.dumps({"case_id": "t", "kind": "SafetyCase"}, sort_keys=True).encode()
    files = {"case.json": case_bytes}
    for k, v in (extra or {}).items():
        files[k] = v
    manifest = {"format": "chp-safety-case/v0.1",
                "files": {n: _sha256(d) for n, d in sorted(files.items())}}
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    key = Ed25519PrivateKey.generate()
    sigdoc = {
        "public_key_b64": base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
        "signature_b64": base64.b64encode(key.sign(manifest_bytes)).decode(),
    }
    buf = BytesIO()
    with ZipFile(buf, "w") as zf:
        for n, d in files.items():
            zf.writestr(n, d)
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("signature.json", json.dumps(sigdoc).encode())
    return buf.getvalue()


def test_split_der_certs_roundtrip():
    # two toy DER-SEQUENCE blobs (0x30 0x82 <len16> <len bytes>)
    def der(n):
        body = bytes([n]) * n
        return bytes([0x30, 0x82, (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + body
    blob = der(10) + der(20)
    parts = _split_der_certs(blob)
    assert len(parts) == 2
    assert base64.b64decode(parts[0]) == der(10) and base64.b64decode(parts[1]) == der(20)


def test_reverify_good_and_tampered():
    b = _make_bundle()
    ok, errs = reverify_bundle(b)
    assert ok, errs
    # flip a byte in the zip → parse/digest/signature fails
    bad = bytearray(b); bad[-10] ^= 0xFF
    ok2, _ = reverify_bundle(bytes(bad))
    assert ok2 is False


def test_attest_no_tpm_returns_signed_w3_base():
    att = build_attestation(_make_bundle(), execution_id="e1")
    assert att["integrity_reverified"] is True
    assert att["tpm"]["available"] is False               # no tpm2-tools in CI
    assert att["declared_independence"] == "W3_INDEPENDENT_HOST"
    assert att["bundle_sha256"].startswith("sha256:")
    assert "signature" in att and att["witness_pubkey_hex"]


def test_collector_output_verifies_as_w3():
    """The collector's attestation is consumable by verify_tpm_witness; no TPM ⇒ honest W3 base."""
    bundle = _make_bundle()
    att = build_attestation(bundle, execution_id="e2")
    v = verify_tpm_witness(att, expected_bundle_sha256=att["bundle_sha256"],
                           producer_host="some-other-producer",
                           trusted_witness_keys={att["witness_key_id"]: att["witness_pubkey_hex"]},
                           allow_network=False)
    assert v.derivation.independence == WitnessIndependence.W3_INDEPENDENT_HOST
    assert v.quote_present is False


def _host():
    h = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(h, SafetyAdapter())
    return h


def test_capability_via_host():
    att_b64 = base64.b64encode(_make_bundle()).decode()
    r = _host().invoke("chp.adapters.safety.tpm_witness_attest", {"bundle_b64": att_b64})
    assert r.outcome == "success"
    assert r.data["tpm_available"] is False
    assert r.data["integrity_reverified"] is True
    assert r.data["attestation"]["declared_independence"] == "W3_INDEPENDENT_HOST"


def test_capability_rejects_bad_base64():
    r = _host().invoke("chp.adapters.safety.tpm_witness_attest", {"bundle_b64": "!!!not-base64!!!"})
    assert r.outcome != "success"
