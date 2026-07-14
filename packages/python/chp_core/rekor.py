"""Rekor / Sigstore transparency-log submission (chp-v0.2.md §12, proposal 0033).

A signed CHP bundle exports as a DSSE-wrapped in-toto attestation (proposal 0021) —
which is *exactly* Rekor's ``intoto``/``dsse`` entry body. Submitting it to a Rekor
log (``POST /api/v1/log/entries``) gets a public, append-only inclusion proof: a
third party learns "this attestation, committing root ``R``, is in the log at index
``i``." Rekor returns an RFC 6962 inclusion proof + a signed entry timestamp (SET);
this module folds both into a ``store-head-anchor`` with ``anchor.type = "rekor"`` and
verifies it **offline** — the inclusion proof recomputes via ``merkle`` (Rekor is RFC
6962, same as ``chp-store-head-v2``) and the SET is an ECDSA-P256 signature over the
canonical entry metadata, checked against the log's pinned public key.

**Honest boundary.** CHP specifies the *carrier* + the *offline verification* of a
Rekor inclusion proof, NOT the operation of a log. Submission is **opt-in** and reaches
the network; a host that never submits stays fully conformant. A real submission writes
to a permanent, immutable, public log — callers do that deliberately.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Callable

from . import merkle
from .dsse import bundle_to_attestation
from .signing import BundleVerification, _canon_jcs, _fail_closed_bv

REKOR_ANCHOR_TYPE = "rekor"
_INTOTO_KIND = "intoto"
_INTOTO_API_VERSION = "0.0.2"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_envelope_bytes(envelope: dict) -> bytes:
    """Stable bytes for the DSSE envelope hash Rekor records (envelopeHash)."""
    return _canon_jcs(envelope)


def build_proposed_entry(dsse_envelope: dict) -> dict:
    """The Rekor ``POST /api/v1/log/entries`` body for a DSSE attestation
    (``intoto`` v0.0.2). Rekor hashes the envelope + its payload; we send both so
    the log records exactly the attestation we can later re-present."""
    env_bytes = _canonical_envelope_bytes(dsse_envelope)
    payload_bytes = base64.b64decode(dsse_envelope["payload"])
    return {
        "apiVersion": _INTOTO_API_VERSION,
        "kind": _INTOTO_KIND,
        "spec": {
            "content": {
                "envelope": base64.b64encode(env_bytes).decode(),
                "hash": {"algorithm": "sha256", "value": _sha256_hex(env_bytes)},
                "payloadHash": {"algorithm": "sha256", "value": _sha256_hex(payload_bytes)},
            },
        },
    }


def submit_bundle(bundle: dict, host_key: Any, *, rekor_url: str,
                  http_post: Callable[[str, dict], dict] | None = None) -> dict:
    """Submit ``bundle`` (as a DSSE attestation) to a Rekor log and return the raw
    Rekor entry response. **Opt-in + network** — a real ``rekor_url`` writes to a
    permanent public log. ``http_post(url, json_body) -> response_json`` is
    injectable (tests / a governed HTTP adapter); the default uses stdlib urllib."""
    envelope = bundle_to_attestation(bundle, host_key)
    body = build_proposed_entry(envelope)
    url = rekor_url.rstrip("/") + "/api/v1/log/entries"
    if http_post is None:
        http_post = _default_post
    return http_post(url, body)


def _default_post(url: str, json_body: dict) -> dict:
    import urllib.request

    req = urllib.request.Request(
        url, data=json.dumps(json_body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (caller opts in)
        return json.loads(resp.read().decode())


def rekor_anchor_from_response(bundle: dict, host_key: Any, response: dict, *,
                              host_id: str, sequence: int, anchored_at: str) -> dict:
    """Fold a Rekor entry response into a ``store-head-anchor`` with
    ``anchor.type = "rekor"``. ``store_head`` is the bundle ``root_hash`` (what the
    logged DSSE commits); the anchor carries the inclusion proof + SET + the DSSE so
    a stranger verifies inclusion offline and binds it back to the root."""
    envelope = bundle_to_attestation(bundle, host_key)
    entry = next(iter(response.values())) if isinstance(response, dict) else response
    ip = entry.get("verification", {}).get("inclusionProof", {})
    return {
        "kind": "store-head-anchor",
        "host_id": host_id,
        "sequence": sequence,
        "store_head": bundle.get("root_hash", ""),
        "anchored_at": anchored_at,
        "anchor": {
            "type": REKOR_ANCHOR_TYPE,
            "log_id": entry.get("logID", ""),
            "log_index": int(entry.get("logIndex", 0)),
            "integrated_time": int(entry.get("integratedTime", 0)),
            "set": entry.get("verification", {}).get("signedEntryTimestamp", ""),
            "entry_body": entry.get("body", ""),
            "tree_root": ip.get("rootHash", ""),
            "tree_size": int(ip.get("treeSize", 0)),
            "inclusion_index": int(ip.get("logIndex", 0)),
            "inclusion_hashes": list(ip.get("hashes", [])),
            "dsse_envelope": envelope,
        },
    }


def set_message(anchor: dict) -> bytes:
    """The canonical bytes a Rekor SET signs: ``{body, integratedTime, logIndex,
    logID}`` under RFC 8785 JCS (Rekor's `signedEntryTimestamp` payload)."""
    return _canon_jcs({
        "body": anchor.get("entry_body", ""),
        "integratedTime": int(anchor.get("integrated_time", 0)),
        "logID": anchor.get("log_id", ""),
        "logIndex": int(anchor.get("log_index", 0)),
    })


@_fail_closed_bv
def verify_rekor_anchor(statement: dict, *, log_public_key_pem: str | bytes) -> BundleVerification:
    """Offline-verify a ``store-head-anchor`` of ``anchor.type = "rekor"`` against a
    pinned Rekor log public key. Four independent checks:

      - **inclusion** — ``SHA256(0x00 ‖ entry_body)`` is committed at
        ``(inclusion_index, tree_size)`` under ``tree_root`` (RFC 6962, via ``merkle``).
      - **set** — the SET is a valid ECDSA-P256/SHA256 signature over the canonical
        ``{body, integratedTime, logIndex, logID}`` under the log key.
      - **entry_binds_dsse** — the logged entry records THIS DSSE envelope (its
        ``envelopeHash`` equals ``sha256(canonical envelope)``).
      - **root** — the DSSE commits ``store_head`` (in-toto subject digest == root).

    No network: everything needed is in the anchor + the pinned key.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    checks: dict[str, bool] = {}
    anchor = statement.get("anchor") or {}
    checks["structure"] = (statement.get("kind") == "store-head-anchor"
                           and anchor.get("type") == REKOR_ANCHOR_TYPE
                           and bool(statement.get("store_head")))

    # inclusion (RFC 6962 — reuse the chp-store-head-v2 verifier)
    try:
        entry_body = base64.b64decode(anchor.get("entry_body", ""))
        checks["inclusion"] = merkle.verify_inclusion(
            bytes.fromhex(anchor.get("tree_root", "")), entry_body,
            int(anchor.get("inclusion_index", 0)), int(anchor.get("tree_size", 0)),
            [bytes.fromhex(h) for h in anchor.get("inclusion_hashes", [])])
    except Exception:  # noqa: BLE001
        checks["inclusion"] = False

    # SET (ECDSA-P256 over the canonical entry metadata, pinned log key)
    try:
        pem = log_public_key_pem.encode() if isinstance(log_public_key_pem, str) else log_public_key_pem
        pub = serialization.load_pem_public_key(pem)
        assert isinstance(pub, ec.EllipticCurvePublicKey)
        pub.verify(base64.b64decode(anchor.get("set", "")), set_message(anchor),
                   ec.ECDSA(hashes.SHA256()))
        checks["set"] = True
    except Exception:  # noqa: BLE001 (InvalidSignature or a malformed key/sig)
        checks["set"] = False

    # entry_binds_dsse: the logged entry records this exact DSSE envelope
    try:
        envelope = anchor.get("dsse_envelope") or {}
        env_hash = _sha256_hex(_canonical_envelope_bytes(envelope))
        body_obj = json.loads(entry_body.decode())
        recorded = (body_obj.get("spec", {}).get("content", {})
                    .get("hash", {}).get("value", ""))
        checks["entry_binds_dsse"] = (recorded == env_hash)
    except Exception:  # noqa: BLE001
        checks["entry_binds_dsse"] = False

    # root: the DSSE commits store_head as its in-toto subject digest
    try:
        payload = json.loads(base64.b64decode(envelope["payload"]).decode())
        subj = (payload.get("subject") or [{}])[0].get("digest", {}).get("sha256", "")
        checks["root"] = (subj == statement.get("store_head"))
    except Exception:  # noqa: BLE001
        checks["root"] = False

    valid = all(checks.values())
    reason = None if valid else "rekor-anchor checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return BundleVerification(valid, "signed", checks, reason)
