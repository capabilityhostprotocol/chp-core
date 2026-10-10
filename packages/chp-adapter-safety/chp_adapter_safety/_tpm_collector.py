"""Node-side TPM witness COLLECTOR — self-contained (promoted from chp-safety).

Runs ON the invoking host and emits ONE signed attestation combining two independent things:

  1. W3 BASE — re-verifies a Safety Case bundle's integrity (recomputes every member digest against the
     signed manifest, checks the manifest Ed25519 signature, rejects unsigned members) and signs a W3
     attestation with an Ed25519 key generated HERE (private key never leaves this host).
  2. TPM EVIDENCE — runs the TPM2 quote ceremony (createek / getekcertificate / createak / quote) with
     the quote's qualifying data set to the bundle digest, collects the raw artifacts (EK cert, EK/AK
     public, quote message/signature/PCRs), and reads the EK issuer chain from TPM NV.

HONESTY BOUNDARY: this is a COLLECTOR, not a verifier — it asserts NOTHING about W4
(`quote_verified`/`ek_chain_verified`). Those are derived independently by
`chp.adapters.safety.verify_tpm_witness`. Fail-closed: if the TPM is absent or the ceremony fails, the
W3-base attestation is still returned with `tpm.available = false`, and the verifier keeps it at ≤ W3.
"""

from __future__ import annotations

import base64
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from hashlib import sha256
from zipfile import ZipFile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_SIG_FIELD = "signature"


def _sha256(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def reverify_bundle(bundle: bytes) -> tuple[bool, list[str]]:
    """Standalone re-verification of chp-safety-case/v0.1 integrity + manifest signature, from bytes."""
    errors: list[str] = []
    try:
        with ZipFile(io.BytesIO(bundle), "r") as zf:
            names = set(zf.namelist())
            if not {"case.json", "manifest.json", "signature.json"}.issubset(names):
                return False, ["missing required bundle file"]
            manifest_bytes = zf.read("manifest.json")
            manifest = json.loads(manifest_bytes)
            sigdoc = json.loads(zf.read("signature.json"))
            expected = manifest.get("files", {})
            for name, digest in expected.items():
                if name not in names:
                    errors.append(f"missing: {name}")
                elif _sha256(zf.read(name)) != digest:
                    errors.append(f"digest mismatch: {name}")
            unexpected = names - (set(expected) | {"manifest.json", "signature.json"})
            if unexpected:
                errors.append("unsigned files present: " + ",".join(sorted(unexpected)))
            try:
                pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(sigdoc["public_key_b64"]))
                pub.verify(base64.b64decode(sigdoc["signature_b64"]), manifest_bytes)
            except Exception:
                errors.append("manifest signature invalid")
    except Exception as exc:  # noqa: BLE001
        return False, [f"bundle parse failure: {exc}"]
    return (not errors), errors


def _run(cmd: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=60)


def _b64_file(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            return base64.b64encode(fh.read()).decode("ascii")
    except Exception:
        return None


def _split_der_certs(blob: bytes) -> list[str]:
    """Split a concatenation of DER X.509 certs (each a SEQUENCE, 0x30 0x82 <len16>) into b64 parts."""
    out: list[str] = []
    i = 0
    while i < len(blob) - 4:
        if blob[i] == 0x30 and blob[i + 1] == 0x82:
            total = 4 + ((blob[i + 2] << 8) | blob[i + 3])
            cert = blob[i:i + total]
            if len(cert) == total:
                out.append(base64.b64encode(cert).decode("ascii"))
                i += total
                continue
        i += 1
    return out


def _read_nv_issuer_chain(workdir: str) -> list[str]:
    """Read the Intel ODCA EK issuer chain stored in TPM NV (0x1c00100 + 0x1c00101), concatenated, as
    base64 DER certs. [] if the indices are absent (non-Intel TPM)."""
    blob = b""
    for ix in ("0x01c00100", "0x01c00101"):
        cp = _run(["tpm2_nvread", "-C", "o", ix], workdir)
        if cp.returncode == 0 and cp.stdout:
            blob += cp.stdout
    return _split_der_certs(blob) if blob else []


def collect_tpm_evidence(bundle_sha256: str, *, pcrs: str, ek_alg: str) -> dict:
    """Run the TPM2 quote ceremony; return the raw artifacts (base64) or an error. Never raises."""
    tpm: dict = {"available": False, "error": None, "qualifying_data": bundle_sha256,
                 "pcr_selection": pcrs, "ek_algorithm": ek_alg}
    if shutil.which("tpm2_quote") is None or shutil.which("tpm2_createek") is None:
        tpm["error"] = "tpm2-tools not installed (tpm2_createek/tpm2_quote absent)"
        return tpm

    qualifying_hex = bundle_sha256.split(":", 1)[-1]
    workdir = tempfile.mkdtemp(prefix="chp-tpm-witness-")
    try:
        ver = _run(["tpm2_quote", "--version"], workdir)
        tpm["tpm2_tools_version"] = (ver.stdout or ver.stderr).decode("utf-8", "replace").strip()[:200]

        steps = [
            (["tpm2_createek", "-G", ek_alg, "-c", "ek.ctx", "-u", "ek.pub"], "createek"),
            (["tpm2_createak", "-C", "ek.ctx", "-G", ek_alg, "-g", "sha256", "-s", "rsassa",
              "-c", "ak.ctx", "-u", "ak.pub", "-n", "ak.name"], "createak"),
            (["tpm2_quote", "-c", "ak.ctx", "-l", pcrs, "-q", qualifying_hex,
              "-m", "quote.msg", "-s", "quote.sig", "-o", "quote.pcrs", "-g", "sha256"], "quote"),
        ]
        for cmd, label in steps:
            cp = _run(cmd, workdir)
            if cp.returncode != 0:
                if label == "createak" and ek_alg == "ecc":
                    cp = _run(["tpm2_createak", "-C", "ek.ctx", "-G", "ecc", "-g", "sha256",
                               "-s", "ecdsa", "-c", "ak.ctx", "-u", "ak.pub", "-n", "ak.name"], workdir)
                if cp.returncode != 0:
                    tpm["error"] = f"{label} failed: " + cp.stderr.decode("utf-8", "replace").strip()[:400]
                    return tpm

        ek_crt_path = os.path.join(workdir, "ek.crt")
        cp = _run(["tpm2_getekcertificate", "-o", "ek.crt"], workdir)
        if cp.returncode != 0 or not os.path.exists(ek_crt_path):
            cp = _run(["tpm2_getekcertificate"], workdir)
            if cp.returncode == 0 and cp.stdout:
                with open(ek_crt_path, "wb") as fh:
                    fh.write(cp.stdout)
        tpm["ek_certificate_der_b64"] = _b64_file(ek_crt_path)
        if not tpm["ek_certificate_der_b64"]:
            tpm["ek_certificate_error"] = cp.stderr.decode("utf-8", "replace").strip()[:300] or "no EK certificate"

        tpm["ek_public_b64"] = _b64_file(os.path.join(workdir, "ek.pub"))
        tpm["ak_public_b64"] = _b64_file(os.path.join(workdir, "ak.pub"))
        try:
            with open(os.path.join(workdir, "ak.name"), "rb") as fh:
                tpm["ak_name_hex"] = fh.read().hex()
        except Exception:
            tpm["ak_name_hex"] = None
        tpm["quote_message_b64"] = _b64_file(os.path.join(workdir, "quote.msg"))
        tpm["quote_signature_b64"] = _b64_file(os.path.join(workdir, "quote.sig"))
        tpm["quote_pcrs_b64"] = _b64_file(os.path.join(workdir, "quote.pcrs"))
        tpm["issuer_chain_der_b64"] = _read_nv_issuer_chain(workdir)

        if tpm["quote_message_b64"] and tpm["quote_signature_b64"] and tpm["ak_public_b64"]:
            tpm["available"] = True
        else:
            tpm["error"] = tpm.get("error") or "quote produced no message/signature"
    except subprocess.TimeoutExpired:
        tpm["error"] = "tpm2 ceremony timed out"
    except Exception as exc:  # noqa: BLE001
        tpm["error"] = f"tpm2 ceremony failure: {type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return tpm


def build_attestation(bundle: bytes, *, execution_id: str,
                      pcrs: str = "sha256:0,1,2,3,4,5,6,7", ek_alg: str = "rsa") -> dict:
    """Produce a signed TPM witness attestation over `bundle` (the .chpsafety bytes), on THIS host."""
    integrity_ok, errors = reverify_bundle(bundle)
    bundle_sha256 = _sha256(bundle)
    tpm = collect_tpm_evidence(bundle_sha256, pcrs=pcrs, ek_alg=ek_alg)

    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    host = socket.gethostname()
    payload = {
        "execution_id": execution_id,
        "bundle_sha256": bundle_sha256,
        "witness_host": host,
        "witness_key_id": f"chp-safety-tpm-witness-{host}-{int(time.time())}",
        "witness_pubkey_hex": pub_hex,
        "declared_independence": "W3_INDEPENDENT_HOST",
        "method": "independent-host bundle re-verification + TPM2 quote",
        "integrity_reverified": integrity_ok,
        "integrity_errors": errors,
        "tpm": tpm,
        "ts": round(time.time(), 3),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload[_SIG_FIELD] = key.sign(canonical).hex()
    return payload
