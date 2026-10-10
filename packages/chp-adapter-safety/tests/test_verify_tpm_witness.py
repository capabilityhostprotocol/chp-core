"""Tests for chp.adapters.safety.verify_tpm_witness — the W4 hardware-attested witness verifier.

Synthetic-but-structurally-real TPM quote (TPMS_ATTEST + TPMT_SIGNATURE + TPM2B_PUBLIC) + a 2-cert EK
chain to a locally-pinned test root exercise the parsing, AK-signature check, EK chain validation, and
the derive_w4 honesty gate offline — no hardware.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import struct
from pathlib import Path

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_safety import SafetyAdapter
from chp_adapter_safety._tpm_witness import (
    WitnessIndependence,
    _ak_public_key,
    _parse_attest_extradata,
    _verify_quote_signature,
    verify_ek_chain,
    verify_tpm_witness,
)

_BUNDLE = "sha256:" + "ab" * 32
_QUALIFYING = bytes.fromhex("ab" * 32)


def _tpm2b(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def _attest(extra: bytes) -> bytes:
    out = struct.pack(">I", 0xFF544347) + struct.pack(">H", 0x8018)
    out += _tpm2b(b"") + _tpm2b(extra) + b"\x00" * 25
    return out


def _tpm2b_public_rsa(pub: rsa.RSAPublicKey) -> bytes:
    n = pub.public_numbers().n.to_bytes(256, "big")
    tpmt = struct.pack(">H", 0x0001) + struct.pack(">H", 0x000B) + struct.pack(">I", 0)
    tpmt += _tpm2b(b"") + struct.pack(">H", 0x0010) + struct.pack(">H", 0x0010)
    tpmt += struct.pack(">H", 2048) + struct.pack(">I", 0) + _tpm2b(n)
    return _tpm2b(tpmt)


def _sig_rsassa(sig: bytes) -> bytes:
    return struct.pack(">H", 0x0014) + struct.pack(">H", 0x000B) + _tpm2b(sig)


# -- quote primitives -------------------------------------------------------

def test_extradata_parse():
    ok, extra = _parse_attest_extradata(_attest(_QUALIFYING))
    assert ok and extra == _QUALIFYING


def test_rejects_non_quote_magic():
    bad = b"\x00\x00\x00\x00" + _attest(_QUALIFYING)[4:]
    assert _parse_attest_extradata(bad)[0] is False


def test_ak_pub_roundtrip_and_sig_verify():
    ak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    msg = _attest(_QUALIFYING)
    sig = ak.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    pub = _ak_public_key(_tpm2b_public_rsa(ak.public_key()))
    assert isinstance(pub, rsa.RSAPublicKey)
    assert pub.public_numbers().n == ak.public_key().public_numbers().n
    assert _verify_quote_signature(pub, msg, _sig_rsassa(sig)) is True
    assert _verify_quote_signature(pub, msg + b"x", _sig_rsassa(sig)) is False


# -- EK chain to a pinned root ---------------------------------------------

def _make_ca(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _issue(cn: str, issuer_key, issuer_cert):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(issuer_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .sign(issuer_key, hashes.SHA256()))
    return key, cert


def test_ek_chain_to_pinned_root(tmp_path: Path):
    rk, root = _make_ca("Test Manufacturer Root")
    _k, ek = _issue("Test EK", rk, root)
    anchors = tmp_path / "a"; anchors.mkdir()
    (anchors / "root.der").write_bytes(root.public_bytes(serialization.Encoding.DER))
    ok, notes = verify_ek_chain(ek.public_bytes(serialization.Encoding.DER),
                                anchor_dir=anchors, allow_network=False)
    assert ok, notes


def test_ek_chain_untrusted_root_fails(tmp_path: Path):
    rk, root = _make_ca("Rogue Root")
    _k, ek = _issue("Forged EK", rk, root)
    anchors = tmp_path / "a"; anchors.mkdir()
    _ok, other = _make_ca("Unrelated Root")
    (anchors / "o.der").write_bytes(other.public_bytes(serialization.Encoding.DER))
    ok, _notes = verify_ek_chain(ek.public_bytes(serialization.Encoding.DER),
                                 anchor_dir=anchors, allow_network=False)
    assert ok is False


def test_bundled_intel_root_present():
    anchor = Path(__file__).resolve().parents[1] / "chp_adapter_safety" / "trust_anchors" / "intel_ondie_root.der"
    assert anchor.exists()
    assert "Intel" in x509.load_der_x509_certificate(anchor.read_bytes()).subject.rfc4514_string()


# -- end-to-end honesty gate -----------------------------------------------

def _attestation(*, with_tpm, ak=None, ek_der=None, witness_host="witness-host"):
    wkey = Ed25519PrivateKey.generate()
    pub_hex = wkey.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    key_id = "test-witness-key-1"
    p = {"execution_id": "e", "bundle_sha256": _BUNDLE, "witness_host": witness_host,
         "witness_key_id": key_id, "witness_pubkey_hex": pub_hex,
         "declared_independence": "W3_INDEPENDENT_HOST", "method": "test",
         "integrity_reverified": True, "integrity_errors": [], "ts": 1.0}
    if with_tpm:
        msg = _attest(_QUALIFYING)
        sig = ak.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        p["tpm"] = {"available": True, "ek_certificate_der_b64":
                    base64.b64encode(ek_der).decode() if ek_der else None,
                    "ak_public_b64": base64.b64encode(_tpm2b_public_rsa(ak.public_key())).decode(),
                    "quote_message_b64": base64.b64encode(msg).decode(),
                    "quote_signature_b64": base64.b64encode(_sig_rsassa(sig)).decode()}
    else:
        p["tpm"] = {"available": False}
    p["signature"] = wkey.sign(json.dumps(p, sort_keys=True, separators=(",", ":")).encode()).hex()
    return p, {key_id: pub_hex}


def test_no_tpm_stays_w3():
    att, keys = _attestation(with_tpm=False)
    v = verify_tpm_witness(att, expected_bundle_sha256=_BUNDLE, producer_host="producer-host",
                           trusted_witness_keys=keys, allow_network=False)
    assert v.derivation.independence == WitnessIndependence.W3_INDEPENDENT_HOST


def test_valid_quote_untrusted_ek_stays_w3(tmp_path: Path):
    ak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rk, root = _make_ca("Rogue"); _k, ek = _issue("EK", rk, root)
    att, keys = _attestation(with_tpm=True, ak=ak, ek_der=ek.public_bytes(serialization.Encoding.DER))
    anchors = tmp_path / "a"; anchors.mkdir()
    _o, other = _make_ca("Unrelated"); (anchors / "o.der").write_bytes(other.public_bytes(serialization.Encoding.DER))
    v = verify_tpm_witness(att, expected_bundle_sha256=_BUNDLE, producer_host="producer-host",
                           trusted_witness_keys=keys, anchor_dir=anchors, allow_network=False)
    assert v.quote_signature_valid and v.qualifying_data == _BUNDLE and v.ek_chain_verified is False
    assert v.derivation.independence == WitnessIndependence.W3_INDEPENDENT_HOST


def test_full_w4_when_everything_holds(tmp_path: Path):
    ak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rk, root = _make_ca("Pinned Root"); _k, ek = _issue("Genuine EK", rk, root)
    anchors = tmp_path / "a"; anchors.mkdir()
    (anchors / "root.der").write_bytes(root.public_bytes(serialization.Encoding.DER))
    att, keys = _attestation(with_tpm=True, ak=ak, ek_der=ek.public_bytes(serialization.Encoding.DER))
    v = verify_tpm_witness(att, expected_bundle_sha256=_BUNDLE, producer_host="producer-host",
                           trusted_witness_keys=keys, anchor_dir=anchors, allow_network=False)
    assert v.derivation.independence == WitnessIndependence.W4_HARDWARE_ATTESTED


# -- governed capability ----------------------------------------------------

def _make_host():
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, SafetyAdapter())
    return host


def test_capability_full_w4_via_host(tmp_path: Path):
    ak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rk, root = _make_ca("Pinned Root"); _k, ek = _issue("Genuine EK", rk, root)
    # the capability loads anchors from the bundled dir; stage our test root there via a temp copy
    anchors = Path(__file__).resolve().parents[1] / "chp_adapter_safety" / "trust_anchors"
    tmp_root = anchors / "_test_root.der"
    tmp_root.write_bytes(root.public_bytes(serialization.Encoding.DER))
    try:
        att, keys = _attestation(with_tpm=True, ak=ak, ek_der=ek.public_bytes(serialization.Encoding.DER))
        host = _make_host()
        r = host.invoke("chp.adapters.safety.verify_tpm_witness", {
            "attestation": att, "expected_bundle_sha256": _BUNDLE,
            "producer_host": "producer-host", "trusted_witness_keys": keys, "allow_network": False})
        assert r.outcome == "success"
        assert r.data["witness_class"] == "W4_HARDWARE_ATTESTED"
        assert r.data["hardware_attested"] is True and r.data["ek_chain_verified"] is True
    finally:
        tmp_root.unlink(missing_ok=True)


def test_capability_rejects_non_object_attestation():
    host = _make_host()
    r = host.invoke("chp.adapters.safety.verify_tpm_witness", {
        "attestation": "not-an-object", "expected_bundle_sha256": _BUNDLE, "producer_host": "p"})
    assert r.outcome != "success"
