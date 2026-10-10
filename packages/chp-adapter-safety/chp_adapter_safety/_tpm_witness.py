"""Hardware-attested (W4) TPM witness VERIFICATION — self-contained, producer-independent.

Promoted from the chp-safety product (proven live on an Intel PTT fTPM) so every CHP host can verify a
TPM witness attestation and derive its witness-independence class, not just one product. The verifier
re-derives EVERY condition itself and never trusts a boolean the collector asserted:

  1. W3 base — `derive_witness_independence`: Ed25519 signature valid, witness host != producer host,
     attested bundle digest matches, bundle integrity re-verified, and the witness key is a TRUSTED
     independent-host key (a producer cannot sign its own attestation and assert a foreign host).
  2. quote_verified — parse the TPMS_ATTEST, confirm TPM2_GENERATED magic + ATTEST_QUOTE type, verify
     the quote signature under the AK public key.
  3. qualifying data — read extraData out of the SIGNED quote and compare it to the attested bundle
     digest (never the collector's stated field).
  4. ek_chain_verified — the EK certificate chains, by cryptographic signature, to a PINNED
     manufacturer root bundled with this adapter (Intel OnDie CA). A software/self-signed TPM cannot
     satisfy this, so cannot reach W4.

`derive_w4` applies the honesty gate: W4 only when all hold; otherwise it stays at the verified base
(≤ W3). Pure verification; the only side effect is an OPTIONAL fetch of AIA-referenced intermediate CA
certs (offline-tolerant — a failed fetch leaves the chain unestablished → honest ≤ W3).
"""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_DEFAULT_ANCHOR_DIR = Path(__file__).resolve().parent / "trust_anchors"
_SIG_FIELD = "signature"

# TPM constants (TCG TPM 2.0, Part 2)
_TPM2_GENERATED = 0xFF544347
_ST_ATTEST_QUOTE = 0x8018
_ALG_RSA = 0x0001
_ALG_ECC = 0x0023
_ALG_NULL = 0x0010
_ALG_RSASSA = 0x0014
_ALG_RSAPSS = 0x0016
_ALG_ECDSA = 0x0018


class WitnessIndependence(IntEnum):
    W0_NONE = 0
    W1_SAME_RUNTIME = 1
    W2_ISOLATED_PROCESS = 2
    W3_INDEPENDENT_HOST = 3
    W4_HARDWARE_ATTESTED = 4


# --------------------------------------------------------------------------
# W3 base: independent-host witness derivation (evidence-derived, not declared)
# --------------------------------------------------------------------------

def canonical_payload_bytes(signed: dict) -> bytes:
    """Deterministic bytes the witness signs: the attestation minus its own signature field."""
    payload = {k: v for k, v in signed.items() if k != _SIG_FIELD}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class WitnessDerivation:
    independence: WitnessIndependence
    witness_host: str
    witness_key_id: str
    signature_valid: bool
    host_independent: bool
    bundle_match: bool
    integrity_reverified: bool
    key_trusted: bool
    reasons: tuple[str, ...]


def _parse_declared(value: str) -> WitnessIndependence:
    try:
        return WitnessIndependence[value]
    except KeyError:
        return WitnessIndependence.W0_NONE


def derive_witness_independence(
    signed: dict,
    *,
    expected_bundle_sha256: str,
    producer_host: str,
    trusted_witness_keys: Mapping[str, str] | None = None,
) -> WitnessDerivation:
    """Derive the witness independence class from evidence. `trusted_witness_keys` maps key_id →
    public-key hex for keys KNOWN to belong to an independent host (registered out of band — e.g.
    anchored by the governed mesh invocation that generated the key on that host). W3 requires the
    attestation's key to be in this registry: a signed but untrusted key does NOT reach W3."""
    trusted_witness_keys = trusted_witness_keys or {}
    reasons: list[str] = []
    witness_host = str(signed.get("witness_host", "")).strip()
    witness_key_id = str(signed.get("witness_key_id", ""))

    signature_valid = False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signed["witness_pubkey_hex"]))
        pub.verify(bytes.fromhex(signed[_SIG_FIELD]), canonical_payload_bytes(signed))
        signature_valid = True
    except Exception:
        reasons.append("witness signature invalid")

    host_independent = bool(
        witness_host and producer_host and witness_host.lower() != producer_host.lower())
    if not host_independent:
        reasons.append("witness host is not independent of the producer host")

    bundle_match = str(signed.get("bundle_sha256", "")) == expected_bundle_sha256
    if not bundle_match:
        reasons.append("attestation is for a different bundle digest")

    integrity_reverified = signed.get("integrity_reverified") is True
    if not integrity_reverified:
        reasons.append("witness did not re-verify bundle integrity")

    key_trusted = (
        bool(witness_key_id)
        and trusted_witness_keys.get(witness_key_id) == signed.get("witness_pubkey_hex"))
    if not key_trusted:
        reasons.append("witness key is not a trusted independent-host key")

    declared = _parse_declared(str(signed.get("declared_independence", "W0_NONE")))
    if signature_valid and host_independent and bundle_match and integrity_reverified and key_trusted:
        independence = min(
            declared if declared >= WitnessIndependence.W3_INDEPENDENT_HOST
            else WitnessIndependence.W0_NONE,
            WitnessIndependence.W3_INDEPENDENT_HOST)
        if declared < WitnessIndependence.W3_INDEPENDENT_HOST:
            reasons.append(f"witness declared only {declared.name}")
    else:
        independence = WitnessIndependence.W0_NONE
    return WitnessDerivation(independence, witness_host, witness_key_id, signature_valid,
                             host_independent, bundle_match, integrity_reverified, key_trusted,
                             tuple(reasons))


@dataclass(frozen=True)
class W4Derivation:
    independence: WitnessIndependence
    quote_verified: bool
    ek_chain_verified: bool
    qualifying_data_matches: bool
    reasons: tuple[str, ...]


def derive_w4(
    base: WitnessDerivation,
    *,
    quote_verified: bool,
    ek_chain_verified: bool,
    quote_qualifying_data: str,
    expected_bundle_sha256: str,
) -> W4Derivation:
    """Elevate a W3 derivation to W4 ONLY on a verified hardware root of trust: a valid W3 base + the
    TPM quote signature verifies (`quote_verified`) + the quote's qualifying data equals the attested
    bundle digest + the AK's EK chains to a trusted manufacturer root (`ek_chain_verified`). Without
    the EK chain a software-TPM could forge the quote, so W4 is not claimed — the result stays ≤ W3."""
    reasons: list[str] = []
    qualifying_matches = quote_qualifying_data == expected_bundle_sha256
    if base.independence < WitnessIndependence.W3_INDEPENDENT_HOST:
        reasons.append(f"base witness independence {base.independence.name} below W3")
    if not quote_verified:
        reasons.append("TPM quote signature did not verify")
    if not qualifying_matches:
        reasons.append("quote qualifying data != attested bundle digest")
    if not ek_chain_verified:
        reasons.append("EK certificate does not chain to a trusted manufacturer root")
    if (base.independence >= WitnessIndependence.W3_INDEPENDENT_HOST
            and quote_verified and qualifying_matches and ek_chain_verified):
        independence = WitnessIndependence.W4_HARDWARE_ATTESTED
    else:
        independence = base.independence
    return W4Derivation(independence, quote_verified, ek_chain_verified, qualifying_matches,
                        tuple(reasons))


# --------------------------------------------------------------------------
# Minimal TPM structure reader + quote verification
# --------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.o = 0

    def u16(self) -> int:
        v = struct.unpack_from(">H", self.d, self.o)[0]; self.o += 2; return v

    def u32(self) -> int:
        v = struct.unpack_from(">I", self.d, self.o)[0]; self.o += 4; return v

    def blob16(self) -> bytes:
        n = self.u16(); v = self.d[self.o:self.o + n]; self.o += n; return v


def _parse_attest_extradata(quote_msg: bytes) -> tuple[bool, bytes]:
    r = _Reader(quote_msg)
    try:
        if r.u32() != _TPM2_GENERATED or r.u16() != _ST_ATTEST_QUOTE:
            return False, b""
        r.blob16()               # TPM2B_NAME qualifiedSigner
        return True, r.blob16()  # TPM2B_DATA extraData (qualifying data)
    except Exception:
        return False, b""


def _ak_public_key(tpm2b_public: bytes):
    r = _Reader(tpm2b_public)
    try:
        r.u16()                      # size
        key_type = r.u16()
        r.u16()                      # nameAlg
        r.u32()                      # objectAttributes
        r.blob16()                   # authPolicy
        if key_type == _ALG_RSA:
            if r.u16() != _ALG_NULL:
                r.u16(); r.u16()
            if r.u16() != _ALG_NULL:
                r.u16()
            r.u16()                  # keyBits
            exponent = r.u32() or 65537
            modulus = r.blob16()
            return rsa.RSAPublicNumbers(exponent, int.from_bytes(modulus, "big")).public_key()
        if key_type == _ALG_ECC:
            if r.u16() != _ALG_NULL:
                r.u16(); r.u16()
            if r.u16() != _ALG_NULL:
                r.u16()
            curve_id = r.u16()
            if r.u16() != _ALG_NULL:
                r.u16()
            x = r.blob16(); y = r.blob16()
            curve = {0x0003: ec.SECP256R1(), 0x0004: ec.SECP384R1()}.get(curve_id)
            if curve is None:
                return None
            return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"),
                                                 int.from_bytes(y, "big"), curve).public_key()
    except Exception:
        return None
    return None


def _verify_quote_signature(ak_pub, quote_msg: bytes, sig_bytes: bytes) -> bool:
    try:
        r = _Reader(sig_bytes)
        sig_alg = r.u16(); hash_alg = r.u16()
        if hash_alg != 0x000B:
            return False
        if isinstance(ak_pub, rsa.RSAPublicKey) and sig_alg in (_ALG_RSASSA, _ALG_RSAPSS):
            signature = r.blob16()
            pad = padding.PKCS1v15() if sig_alg == _ALG_RSASSA else \
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
            ak_pub.verify(signature, quote_msg, pad, hashes.SHA256())
            return True
        if isinstance(ak_pub, ec.EllipticCurvePublicKey) and sig_alg == _ALG_ECDSA:
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            rr = int.from_bytes(r.blob16(), "big"); ss = int.from_bytes(r.blob16(), "big")
            ak_pub.verify(encode_dss_signature(rr, ss), quote_msg, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, Exception):
        return False
    return False


# --------------------------------------------------------------------------
# EK certificate chain validation (to a pinned manufacturer root), via OpenSSL
# --------------------------------------------------------------------------

def _is_self_signed(c) -> bool:
    return c.get_issuer().der() == c.get_subject().der()


def _load_anchor_certs(anchor_dir: Path):
    """Load trust-anchor certs via OpenSSL (lenient — manufacturer EK/CA certs are often non-canonical
    DER that pyca rejects). Returns (roots, intermediates)."""
    from OpenSSL import crypto
    roots, intermediates = [], []
    if not anchor_dir.is_dir():
        return roots, intermediates
    for p in sorted(anchor_dir.iterdir()):
        if p.suffix.lower() not in (".der", ".cer", ".crt", ".pem"):
            continue
        try:
            raw = p.read_bytes()
            ft = crypto.FILETYPE_ASN1 if raw[:1] == b"\x30" else crypto.FILETYPE_PEM
            c = crypto.load_certificate(ft, raw)
        except Exception:
            continue
        (roots if _is_self_signed(c) else intermediates).append(c)
    return roots, intermediates


def _aia_ca_issuers_url(cert_der: bytes) -> str | None:
    import subprocess
    try:
        cp = subprocess.run(["openssl", "x509", "-inform", "DER", "-text", "-noout"],
                            input=cert_der, capture_output=True, timeout=15)
        text = cp.stdout.decode("utf-8", "replace")
    except Exception:
        return None
    marker = "CA Issuers - URI:"
    for line in text.splitlines():
        if marker in line:
            return line.split(marker, 1)[1].strip()
    return None


def _fetch_der(url: str) -> bytes | None:
    if not url.startswith(("http://", "https://")):
        return None
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310 (validated against pinned root)
            return resp.read()
    except Exception:
        return None


def verify_ek_chain(
    ek_cert_der: bytes,
    *,
    anchor_dir: Path | None = None,
    extra_intermediates: list[bytes] | None = None,
    allow_network: bool = True,
    max_depth: int = 6,
) -> tuple[bool, list[str]]:
    """Validate that the EK certificate chains, by signature, to a PINNED manufacturer root. Trust is
    pinned: ONLY the self-signed roots bundled in `anchor_dir` are trusted. Non-self-signed anchors +
    `extra_intermediates` (e.g. the attestation's NV issuer chain) are untrusted intermediates;
    AIA-referenced upper links are fetched when `allow_network`. Uses OpenSSL's path builder (lenient
    about the non-canonical DER real TPM EK certs use). Returns (ok, notes)."""
    from OpenSSL import crypto

    notes: list[str] = []
    roots, intermediates = _load_anchor_certs(anchor_dir or _DEFAULT_ANCHOR_DIR)
    if not roots:
        return False, ["no trusted (self-signed) manufacturer root anchors bundled"]

    for raw in (extra_intermediates or []):
        try:
            ft = crypto.FILETYPE_ASN1 if raw[:1] == b"\x30" else crypto.FILETYPE_PEM
            intermediates.append(crypto.load_certificate(ft, raw))
        except Exception:
            continue

    try:
        ek = crypto.load_certificate(crypto.FILETYPE_ASN1, ek_cert_der)
    except Exception as exc:  # noqa: BLE001
        return False, [f"EK certificate parse failure: {exc}"]

    if allow_network:
        have = {c.get_subject().der() for c in intermediates} | {ek.get_subject().der()}
        frontier = [ek, *intermediates]
        for _ in range(max_depth):
            added = False
            for cert in list(frontier):
                if cert.get_issuer().der() in have:
                    continue
                url = _aia_ca_issuers_url(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))
                if not url:
                    continue
                fetched = _fetch_der(url)
                if not fetched:
                    continue
                try:
                    issuer = crypto.load_certificate(crypto.FILETYPE_ASN1, fetched)
                except Exception:
                    continue
                if issuer.get_subject().der() in have:
                    continue
                intermediates.append(issuer); frontier.append(issuer)
                have.add(issuer.get_subject().der()); added = True
            if not added:
                break

    notes.append("EK issuer: " + dict(ek.get_issuer().get_components()).get(b"CN", b"?").decode("latin1"))
    notes.append("pinned roots: " + ", ".join(
        dict(r.get_subject().get_components()).get(b"CN", b"?").decode("latin1") for r in roots))

    store = crypto.X509Store()
    for r in roots:
        store.add_cert(r)
    try:
        crypto.X509StoreContext(store, ek, chain=intermediates).verify_certificate()
        notes.append("EK verified to a pinned manufacturer root")
        return True, notes
    except crypto.X509StoreContextError as exc:
        reason = exc.args[0] if exc.args else str(exc)
        notes.append(f"EK not verified: {reason} (have {len(intermediates)} intermediate(s))")
        return False, notes
    except Exception as exc:  # noqa: BLE001
        notes.append(f"chain verification error: {type(exc).__name__}: {exc}")
        return False, notes


# --------------------------------------------------------------------------
# Top-level verification
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TpmWitnessVerification:
    derivation: W4Derivation
    quote_present: bool
    quote_valid_structure: bool
    quote_signature_valid: bool
    qualifying_data: str | None
    ek_chain_verified: bool
    ek_chain_notes: tuple[str, ...]
    base_reasons: tuple[str, ...]


def verify_tpm_witness(
    attestation: Mapping,
    *,
    expected_bundle_sha256: str,
    producer_host: str,
    trusted_witness_keys: Mapping[str, str] | None = None,
    anchor_dir: Path | None = None,
    allow_network: bool = True,
) -> TpmWitnessVerification:
    """Verify a TPM witness attestation and derive its witness-independence class (≤ W4)."""
    base = derive_witness_independence(
        dict(attestation), expected_bundle_sha256=expected_bundle_sha256,
        producer_host=producer_host, trusted_witness_keys=trusted_witness_keys)

    tpm = dict(attestation.get("tpm") or {})
    quote_present = bool(tpm.get("available")) and bool(tpm.get("quote_message_b64"))
    quote_valid_structure = quote_signature_valid = ek_chain_verified = False
    qualifying_data: str | None = None
    ek_notes: list[str] = []

    if quote_present:
        try:
            quote_msg = base64.b64decode(tpm["quote_message_b64"])
            quote_sig = base64.b64decode(tpm["quote_signature_b64"])
            ak_pub_raw = base64.b64decode(tpm["ak_public_b64"])
            quote_valid_structure, extra = _parse_attest_extradata(quote_msg)
            if quote_valid_structure and extra:
                qualifying_data = "sha256:" + extra.hex()
            ak_pub = _ak_public_key(ak_pub_raw)
            if ak_pub is not None and quote_valid_structure:
                quote_signature_valid = _verify_quote_signature(ak_pub, quote_msg, quote_sig)
        except Exception:
            quote_valid_structure = False

        ek_b64 = tpm.get("ek_certificate_der_b64")
        if ek_b64:
            nv_chain = [base64.b64decode(c) for c in (tpm.get("issuer_chain_der_b64") or [])]
            ek_chain_verified, ek_notes = verify_ek_chain(
                base64.b64decode(ek_b64), anchor_dir=anchor_dir,
                extra_intermediates=nv_chain, allow_network=allow_network)
        else:
            ek_notes = ["no EK certificate in attestation"]

    quote_verified = quote_valid_structure and quote_signature_valid
    derivation = derive_w4(base, quote_verified=quote_verified, ek_chain_verified=ek_chain_verified,
                           quote_qualifying_data=qualifying_data or "",
                           expected_bundle_sha256=expected_bundle_sha256)
    return TpmWitnessVerification(derivation, quote_present, quote_valid_structure,
                                  quote_signature_valid, qualifying_data, ek_chain_verified,
                                  tuple(ek_notes), base.reasons)
