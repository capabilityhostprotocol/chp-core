"""Sealed payloads — payload confidentiality over the evidence chain (chp-v0.2.md
§16, proposal 0025).

The sibling of selective disclosure (§14): because ``chp-event-hash-v2`` binds an
event's ``content_hash`` to ``payload_commitment = sha256(canon(plaintext))``, not
the inline payload, a payload can be *sealed* (replaced with an encrypted
``{chp_sealed}`` marker) exactly as it can be *withheld* — the chain, root, and
signature verify offline over the ciphertext with no key. Only the holder of the
recipient X25519 key unseals, then re-runs the §14 commitment check.

``chp-sealed-v1`` = ephemeral X25519 ECDH → HKDF-SHA256 (``info="chp-sealed-v1"``)
→ ChaCha20-Poly1305 over ``canon(plaintext)``. All primitives are in the installed
``cryptography`` library — no new dependency, no PyNaCl, no ed25519→x25519 map (the
recipient sealing key is a *separate* X25519 key, published as ``enc_public_key``
in the signed host attestation).
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any, Callable

SEALED_SCHEME = "chp-sealed-v1"
SEALED_SCHEME_V2 = "chp-sealed-v2"  # multi-recipient envelope encryption (proposal 0030)
_HKDF_INFO = b"chp-sealed-v1"
_ENC_PRIVATE_NAME = "host_x25519"
_ENC_PUBLIC_NAME = "host_x25519.pub"

# The commitment binds the inline payload only under chp-event-hash-v2 (§14).
EVENT_HASH_V2 = "chp-event-hash-v2"


def _canon_bytes(payload: Any) -> bytes:
    """chp-stable-v1 canonical bytes of a payload — identical to the form
    ``_payload_commitment`` hashes, so an unsealed payload round-trips to the same
    commitment."""
    return json.dumps(payload if payload is not None else {}, sort_keys=True).encode()


# ── Recipient X25519 key management (a sibling of the ed25519 key dir) ───────


def generate_enc_keypair(key_dir: str | Path, *, overwrite: bool = False):
    """Generate the host's X25519 sealing keypair alongside its ed25519 identity.
    Writes ``host_x25519`` (raw base64 private) + ``host_x25519.pub`` (raw base64
    public). Returns the ``X25519PrivateKey``. The public key is published as
    ``enc_public_key`` in the host attestation so senders can seal to it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    key_dir = Path(key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / _ENC_PRIVATE_NAME
    pub_path = key_dir / _ENC_PUBLIC_NAME
    if priv_path.exists() and not overwrite:
        return load_enc_private_key(key_dir)
    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    priv_path.write_bytes(base64.b64encode(raw_priv))
    pub_path.write_bytes(base64.b64encode(raw_pub))
    try:
        priv_path.chmod(0o600)
    except OSError:  # pragma: no cover - non-POSIX
        pass
    return priv


def load_enc_private_key(key_dir: str | Path):
    """Load the host's X25519 sealing private key, or None if unprovisioned."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    path = Path(key_dir) / _ENC_PRIVATE_NAME
    if not path.exists():
        return None
    return X25519PrivateKey.from_private_bytes(base64.b64decode(path.read_bytes()))


def load_enc_public_key_b64(key_dir: str | Path) -> str | None:
    """The host's X25519 sealing PUBLIC key (base64), or None if unprovisioned."""
    path = Path(key_dir) / _ENC_PUBLIC_NAME
    if not path.exists():
        return None
    return path.read_bytes().decode().strip()


# ── The chp-sealed-v1 envelope ──────────────────────────────────────────────


def _derive_key(shared: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_HKDF_INFO).derive(shared)


def _seal_bytes(recipient_pub_b64: str, plaintext: bytes,
                *, _esk_seed: bytes | None = None, _nonce: bytes | None = None) -> dict:
    """Seal ``plaintext`` to a recipient X25519 public key → a ``chp-sealed-v1``
    envelope. Fresh ephemeral key + nonce per call (non-deterministic ciphertext).
    ``_esk_seed``/``_nonce`` are test/vector hooks for a reproducible envelope — a
    real seal MUST leave them None (a reused ephemeral key/nonce is unsafe)."""
    import os

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    recipient = X25519PublicKey.from_public_bytes(base64.b64decode(recipient_pub_b64))
    esk = (X25519PrivateKey.from_private_bytes(_esk_seed) if _esk_seed
           else X25519PrivateKey.generate())
    epk = esk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    key = _derive_key(esk.exchange(recipient))
    nonce = _nonce if _nonce is not None else os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return {
        "scheme": SEALED_SCHEME,
        "epk": base64.b64encode(epk).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


def _seal_bytes_multi(recipient_pub_b64s: list[str], plaintext: bytes, *,
                      _cek: bytes | None = None, _content_nonce: bytes | None = None,
                      _esk_seeds: list[bytes] | None = None,
                      _wrap_nonces: list[bytes] | None = None) -> dict:
    """Seal ``plaintext`` to N recipient X25519 public keys → a ``chp-sealed-v2``
    envelope (envelope encryption). A single random 32-byte content key encrypts
    the payload ONCE (one ``ct``); that key is then wrapped per recipient by
    reusing ``_seal_bytes`` (a v1 seal of the 32-byte key). Any one recipient key
    recovers the content key and decrypts. Test hooks (``_cek``/``_content_nonce``/
    ``_esk_seeds``/``_wrap_nonces``) reproduce a fixed envelope for vectors — a real
    seal MUST leave them None."""
    import os

    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    cek = _cek if _cek is not None else os.urandom(32)
    content_nonce = _content_nonce if _content_nonce is not None else os.urandom(12)
    ct = ChaCha20Poly1305(cek).encrypt(content_nonce, plaintext, None)
    recipients = []
    for i, pub in enumerate(recipient_pub_b64s):
        wrap = _seal_bytes(pub, cek,
                           _esk_seed=(_esk_seeds[i] if _esk_seeds else None),
                           _nonce=(_wrap_nonces[i] if _wrap_nonces else None))
        # Drop the redundant per-recipient scheme (v2 parent implies the v1 wrap).
        recipients.append({"epk": wrap["epk"], "nonce": wrap["nonce"],
                           "wrapped_key": wrap["ct"]})
    return {
        "scheme": SEALED_SCHEME_V2,
        "nonce": base64.b64encode(content_nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "recipients": recipients,
    }


def _unseal_bytes(envelope: dict, enc_private_key) -> bytes:
    """Recover the plaintext bytes from a ``chp-sealed-v1`` (single-recipient) or
    ``chp-sealed-v2`` (multi-recipient envelope encryption) envelope with the
    recipient X25519 private key. A wrong key or tampered ciphertext raises."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    scheme = envelope.get("scheme")
    if scheme == SEALED_SCHEME:
        epk = X25519PublicKey.from_public_bytes(base64.b64decode(envelope["epk"]))
        key = _derive_key(enc_private_key.exchange(epk))
        return ChaCha20Poly1305(key).decrypt(
            base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), None)
    if scheme == SEALED_SCHEME_V2:
        cek = None
        for r in envelope.get("recipients") or []:
            try:  # trial-unwrap: reconstruct the v1 wrap of the content key
                cek = _unseal_bytes({"scheme": SEALED_SCHEME, "epk": r["epk"],
                                     "nonce": r["nonce"], "ct": r["wrapped_key"]},
                                    enc_private_key)
                break
            except Exception:
                continue  # not our wrap — try the next recipient
        if cek is None:
            raise ValueError("no recipient key unwraps this chp-sealed-v2 envelope")
        return ChaCha20Poly1305(cek).decrypt(
            base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]), None)
    raise ValueError(f"unknown sealing scheme: {scheme!r}")


# ── Bundle-level seal / unseal (mirrors signing.withhold_payloads) ───────────


def seal_payloads(bundle: dict, recipient_enc_pubkey: str | list[str],
                  predicate: Callable[[dict], bool] | None = None) -> dict:
    """Return a copy of ``bundle`` with every selected chp-event-hash-v2 event's
    ``payload`` replaced by a ``{"chp_sealed": <envelope>}`` marker (§16). The
    ``payload_commitment`` and ``content_hash`` are untouched, so the root and the
    ORIGINAL signature still verify — no re-signing, no store mutation, exactly like
    ``withhold_payloads``. An already-withheld or already-sealed payload is left
    as-is.

    ``recipient_enc_pubkey`` is a single X25519 public key (``chp-sealed-v1``,
    byte-identical to proposal 0025) OR a **list** of keys → ``chp-sealed-v2``
    envelope encryption (proposal 0030): the payload is encrypted once and readable
    by ANY of the N recipients."""
    if predicate is None:
        predicate = lambda ev: True  # noqa: E731
    out = copy.deepcopy(bundle)
    for ev in out.get("events") or []:
        if ev.get("hash_scheme") != EVENT_HASH_V2 or not ev.get("payload_commitment"):
            continue
        payload = ev.get("payload")
        if isinstance(payload, dict) and ("chp_withheld" in payload or "chp_sealed" in payload):
            continue  # already withheld/sealed
        if predicate(ev):
            pt = _canon_bytes(payload)
            env = (_seal_bytes_multi(recipient_enc_pubkey, pt)
                   if isinstance(recipient_enc_pubkey, list)
                   else _seal_bytes(recipient_enc_pubkey, pt))
            ev["payload"] = {"chp_sealed": env}
    return out


def unseal_payload(marker: dict, enc_private_key) -> Any:
    """Recover the plaintext payload from a ``{"chp_sealed": <envelope>}`` marker
    with the recipient X25519 private key. Returns the payload object; a caller
    then re-runs the §14 commitment check to confirm integrity."""
    envelope = marker.get("chp_sealed") if isinstance(marker, dict) else None
    if not isinstance(envelope, dict):
        raise ValueError("not a sealed payload marker")
    return json.loads(_unseal_bytes(envelope, enc_private_key))


def unseal_bundle(bundle: dict, enc_private_key) -> dict:
    """Return a copy of ``bundle`` with every ``{chp_sealed}`` payload decrypted
    back to plaintext (the inverse of ``seal_payloads``). Only the recipient can."""
    out = copy.deepcopy(bundle)
    for ev in out.get("events") or []:
        payload = ev.get("payload")
        if isinstance(payload, dict) and "chp_sealed" in payload:
            ev["payload"] = unseal_payload(payload, enc_private_key)
    return out
