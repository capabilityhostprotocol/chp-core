"""in-toto / DSSE attestation bridge (chp-v0.2.md §15, proposal 0021).

Export a signed CHP evidence bundle as a standard **in-toto Statement** wrapped
in a **DSSE** (Dead Simple Signing Envelope), signed by the host ed25519 key over
the DSSE **PAE** — so CHP evidence is portable into the Sigstore/in-toto/SLSA
ecosystem. Any DSSE verifier checks the PAE signature; a CHP verifier
additionally re-verifies the embedded bundle. The bundle is wrapped, not
modified, so nothing CHP already signed changes.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
CHP_BUNDLE_PREDICATE_TYPE = "https://chp.dev/attestation/evidence-bundle/v1"


def _pae(payload_type: bytes, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding — the exact bytes signed:
    ``DSSEv1 SP LEN(payloadType) SP payloadType SP LEN(body) SP body`` (SP = a
    space, LEN = ASCII-decimal byte length). DSSE owns this serialization, so a
    signer does NOT route through chp-stable-v1."""
    return (b"DSSEv1 "
            + str(len(payload_type)).encode() + b" " + payload_type + b" "
            + str(len(body)).encode() + b" " + body)


def _bundle_subject_name(bundle: dict) -> str:
    """The in-toto subject name for a bundle: the correlation it attests."""
    comp = bundle.get("completeness") or {}
    if comp.get("correlation_id"):
        return str(comp["correlation_id"])
    for ev in reversed(bundle.get("events") or []):
        cid = (ev.get("correlation") or {}).get("correlation_id")
        if cid:
            return str(cid)
    return "chp-evidence-bundle"


def bundle_to_statement(bundle: dict) -> dict:
    """Wrap a signed CHP bundle as an in-toto Statement/v1. The subject digest is
    the bundle ``root_hash`` (a SHA-256 hex — the correlation's signed evidence
    root); the predicate is the full bundle (lossless round-trip)."""
    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [{"name": _bundle_subject_name(bundle),
                     "digest": {"sha256": bundle.get("root_hash", "")}}],
        "predicateType": CHP_BUNDLE_PREDICATE_TYPE,
        "predicate": bundle,
    }


def dsse_sign(statement: dict, host_key: Any) -> dict:
    """Sign a Statement into a DSSE envelope with the host ed25519 key over the
    PAE. ``host_key`` is a signing-capable ``HostKey``."""
    from .signing import SigningUnavailable, _sign  # noqa: PLC0415

    if not getattr(host_key, "can_sign", False):
        raise SigningUnavailable("host key has no private component; cannot sign a DSSE envelope")
    body = json.dumps(statement, sort_keys=True).encode("utf-8")
    sig = _sign(host_key._private, _pae(IN_TOTO_PAYLOAD_TYPE.encode(), body))
    return {
        "payload": base64.b64encode(body).decode(),
        "payloadType": IN_TOTO_PAYLOAD_TYPE,
        "signatures": [{"keyid": host_key.key_id, "sig": sig}],
    }


def bundle_to_attestation(bundle: dict, host_key: Any) -> dict:
    """A signed CHP bundle → a DSSE-wrapped in-toto attestation (the full export)."""
    return dsse_sign(bundle_to_statement(bundle), host_key)


def dsse_statement(envelope: dict) -> dict:
    """Decode the DSSE payload back to the in-toto Statement."""
    return json.loads(base64.b64decode(envelope["payload"]))


def attestation_to_bundle(envelope: dict) -> dict:
    """Extract the CHP bundle (the predicate) — the round-trip back to a bundle a
    CHP verifier checks natively."""
    return dsse_statement(envelope).get("predicate") or {}


def verify_dsse(envelope: dict, public_key_b64: str) -> bool:
    """Level 1 — any DSSE verifier: recompute the PAE from ``payloadType`` + the
    decoded ``payload`` and check ``ed25519(PAE)`` against ``public_key_b64``.
    True if any signature verifies."""
    from .signing import _verify_sig  # noqa: PLC0415

    try:
        body = base64.b64decode(envelope["payload"])
        pae = _pae(str(envelope.get("payloadType", "")).encode(), body)
    except Exception:  # noqa: BLE001 — malformed envelope
        return False
    return any(_verify_sig(public_key_b64, pae, str(s.get("sig", "")))
               for s in (envelope.get("signatures") or []))


@dataclass
class AttestationVerification:
    valid: bool
    checks: dict
    reason: str | None = None


def verify_attestation(envelope: dict, *, public_key: str | None = None) -> AttestationVerification:
    """Level 2 — the full CHP check: the DSSE PAE signature is authentic, the
    subject digest equals the embedded bundle's ``root_hash``, and the embedded
    bundle verifies (chain, root, header signature, host identity). The public
    key defaults to the embedded bundle's ``public_key`` (self-attested by its
    ``host_identity``), so the attestation is self-contained."""
    from .signing import verify_bundle  # noqa: PLC0415

    checks: dict[str, bool] = {}
    try:
        stmt = dsse_statement(envelope)
    except Exception as exc:  # noqa: BLE001
        return AttestationVerification(False, {"envelope": False}, f"malformed DSSE payload: {exc}")

    bundle = stmt.get("predicate") or {}
    pub = public_key or bundle.get("public_key")
    checks["dsse_signature"] = bool(pub) and verify_dsse(envelope, str(pub))
    checks["statement_type"] = (stmt.get("_type") == IN_TOTO_STATEMENT_TYPE
                                and stmt.get("predicateType") == CHP_BUNDLE_PREDICATE_TYPE)
    subj = (stmt.get("subject") or [{}])[0].get("digest", {}).get("sha256")
    checks["subject_digest"] = subj == bundle.get("root_hash")
    bundle_v = verify_bundle(bundle)
    checks["bundle"] = bundle_v.valid
    valid = all(checks.values())
    reason = None if valid else "attestation checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return AttestationVerification(valid, checks, reason)
