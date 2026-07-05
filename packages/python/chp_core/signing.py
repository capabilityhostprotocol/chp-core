"""Evidence integrity v0.2 — ed25519 keypairs and signed evidence bundles.

CHP v0.1 evidence is hash-chained (mutation/reorder detection) but unsigned: a
local actor with store access can recompute the whole chain. v0.2 adds an
*optional* signing layer that binds an exported bundle to a host keypair, so a
verifier can detect tampering by any party without the private key.

Assurance tiers (declared by the host, per the v0.2 design doc):
- ``none``       — local append-only evidence (v0.1 baseline)
- ``hash-chain`` — per-event content_hash + prev_hash (mutation/reorder)
- ``signed``     — hash-chain bundle + ed25519 signature over the root hash

Design decisions (see docs/design/evidence-integrity-v0.2.md):
- Sign the bundle ROOT hash, not every event — cheap, and event-level
  hash-chaining still gives per-event integrity.
- Canonicalization is named ``chp-stable-v1`` (the shipped stable-field
  ``json.dumps(sort_keys=True)`` hashing), NOT RFC 8785 JCS. Switching schemes
  would invalidate every existing chain mesh-wide, and JCS's value (cross-
  language verification) is moot until a non-Python verifier exists. The
  ``canonicalization`` field makes adopting ``chp-jcs-v1`` a non-breaking
  addition later.

``cryptography`` is an OPTIONAL extra (``chp-core[signing]``). Without it, hosts
stay at the ``hash-chain`` tier: unsigned bundles still build and verify; only
signing/signature-verification raise a clear error.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .store import _compute_event_hash

CANONICALIZATION = "chp-stable-v1"
SIGNATURE_ALGORITHM = "ed25519"
DEFAULT_KEY_DIR = Path.home() / ".chp" / "keys"
_PRIVATE_NAME = "host_ed25519"
_PUBLIC_NAME = "host_ed25519.pub"


class SigningUnavailable(RuntimeError):
    """Raised when a signing/verification op needs `cryptography` but it's absent."""


def _load_backend() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: PLC0415
        return ed25519
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise SigningUnavailable(
            "ed25519 signing requires the optional dependency: pip install 'chp-core[signing]'"
        ) from exc


def signing_available() -> bool:
    try:
        _load_backend()
        return True
    except SigningUnavailable:
        return False


def key_id_for(public_key_bytes: bytes) -> str:
    """Stable short identifier for a public key (first 16 hex of its SHA256)."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


# --------------------------------------------------------------------------
# Keypair management (file-based, like ssh keys — works on mac/worker/raspi)
# --------------------------------------------------------------------------

@dataclass
class HostKey:
    key_id: str
    public_key_b64: str
    _private: Any = field(default=None, repr=False)

    @property
    def can_sign(self) -> bool:
        return self._private is not None


def generate_keypair(key_dir: str | Path = DEFAULT_KEY_DIR, *, overwrite: bool = False) -> HostKey:
    """Create an ed25519 keypair under *key_dir* (private 0600, dir 0700)."""
    ed25519 = _load_backend()
    key_dir = Path(key_dir)
    priv_path = key_dir / _PRIVATE_NAME
    pub_path = key_dir / _PUBLIC_NAME
    if priv_path.exists() and not overwrite:
        raise FileExistsError(f"key already exists at {priv_path}; pass overwrite=True to replace")

    key_dir.mkdir(parents=True, exist_ok=True)
    try:
        key_dir.chmod(0o700)
    except OSError:
        pass

    private = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    priv_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    # Write private with 0600 from the start (no world-readable window).
    import os  # noqa: PLC0415
    fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(base64.b64encode(priv_bytes))
    pub_path.write_bytes(base64.b64encode(pub_bytes))
    return HostKey(key_id=key_id_for(pub_bytes), public_key_b64=base64.b64encode(pub_bytes).decode(), _private=private)


def load_host_key(key_dir: str | Path = DEFAULT_KEY_DIR) -> HostKey | None:
    """Load the host keypair if present. Returns None if no key exists (the host
    then operates at the hash-chain tier)."""
    key_dir = Path(key_dir)
    priv_path = key_dir / _PRIVATE_NAME
    pub_path = key_dir / _PUBLIC_NAME
    if not pub_path.exists():
        return None
    pub_bytes = base64.b64decode(pub_path.read_bytes())
    private = None
    if priv_path.exists():
        ed25519 = _load_backend()
        priv_bytes = base64.b64decode(priv_path.read_bytes())
        private = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return HostKey(
        key_id=key_id_for(pub_bytes),
        public_key_b64=base64.b64encode(pub_bytes).decode(),
        _private=private,
    )


def _canon(obj: Any) -> bytes:
    """chp-stable-v1 canonical bytes: sorted keys, spaced separators, ensure_ascii."""
    return json.dumps(obj, sort_keys=True).encode()


# Fields covered by the header signature. Everything a stranger reads to decide
# "who/when/how" must be inside the signature — not just root_hash (events are
# already bound via root_hash). See spec/chp-v0.2.md §3.
_HEADER_FIELDS = ("host_id", "protocol_version", "created_at", "canonicalization", "root_hash")


def bundle_header(bundle: dict) -> dict:
    """The signed header: the origin/time/scheme claims + root_hash."""
    return {k: bundle.get(k) for k in _HEADER_FIELDS}


def build_attestation(host_id: str, host_key: HostKey, *, valid_from: str,
                      valid_until: str | None = None) -> dict:
    """Self-signed statement binding host_id <-> public_key.

    key_id = sha256(pubkey)[:16] only binds a key to itself; host_id is a free
    string anyone can label a bundle with. This puts the identity claim inside a
    signature by the key, so a verifier checks host_id is asserted by the keyholder
    (the TOFU trust floor, now cryptographic rather than a bare string)."""
    if not host_key.can_sign:
        raise SigningUnavailable("host key has no private component; cannot attest")
    claim = {
        "host_id": host_id,
        "public_key": host_key.public_key_b64,
        "key_id": host_key.key_id,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    return {**claim, "signature": _sign(host_key._private, _canon(claim))}


def _sign(private: Any, message: bytes) -> str:
    return base64.b64encode(private.sign(message)).decode()


def _verify_sig(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    ed25519 = _load_backend()
    pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    try:
        pub.verify(base64.b64decode(signature_b64), message)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Bundle build / sign / verify
# --------------------------------------------------------------------------

def compute_root_hash(events: list[dict]) -> str:
    """Root hash = SHA256 over each event's content_hash in sequence order.

    Events already carry content_hash from the store's hash chain, so the root
    binds the whole ordered set without re-canonicalizing every event here.
    """
    h = hashlib.sha256()
    for ev in events:
        ch = ev.get("content_hash")
        # An unhashed (legacy) event can't participate in a signed bundle.
        h.update((ch or "").encode())
        h.update(b"\n")
    return h.hexdigest()


def build_bundle(
    host_id: str,
    events: list[dict],
    *,
    created_at: str,
    protocol_version: str = "0.2",
) -> dict:
    """Build an unsigned (`hash-chain` tier) evidence bundle from exported events."""
    return {
        "host_id": host_id,
        "protocol_version": protocol_version,
        "created_at": created_at,
        "canonicalization": CANONICALIZATION,
        "assurance": "hash-chain",
        "events": events,
        "root_hash": compute_root_hash(events),
    }


def sign_bundle(bundle: dict, host_key: HostKey, *, valid_until: str | None = None) -> dict:
    """Sign a bundle's canonical header, promoting it to the `signed` tier.

    Signs the header (host_id/created_at/protocol_version/canonicalization +
    root_hash), not just root_hash, so a stranger cannot relabel the origin
    without breaking the signature. Attaches a self-signed host-identity
    attestation binding host_id <-> public_key."""
    if not host_key.can_sign:
        raise SigningUnavailable("host key has no private component; cannot sign")
    signed = dict(bundle)
    signed["assurance"] = "signed"
    signed["public_key"] = host_key.public_key_b64
    signed["host_identity"] = build_attestation(
        signed["host_id"], host_key,
        valid_from=signed.get("created_at", ""), valid_until=valid_until,
    )
    signed["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": host_key.key_id,
        "signature": _sign(host_key._private, _canon(bundle_header(signed))),
    }
    return signed


@dataclass
class BundleVerification:
    valid: bool
    assurance: str
    checks: dict[str, bool]
    reason: str | None = None


def verify_bundle(bundle: dict, *, expected_key_id: str | None = None) -> BundleVerification:
    """Offline-verify an exported bundle: per-event hashes, chain continuity,
    root hash, and (for signed bundles) the ed25519 signature.

    ``expected_key_id`` pins the signer — a bundle signed by a different key is
    rejected (defends against a valid signature from an untrusted key)."""
    checks: dict[str, bool] = {}
    events = bundle.get("events") or []

    # 1. Per-event hash recompute + chain continuity.
    chain_ok = True
    expected_prev: str | None = None
    for ev in events:
        stored_hash = ev.get("content_hash")
        stored_prev = ev.get("prev_hash")
        if stored_hash is None:
            chain_ok = False  # unhashed event can't be in an integrity bundle
            break
        recomputed = _compute_event_hash(ev, stored_prev)
        if recomputed != stored_hash or stored_prev != expected_prev:
            chain_ok = False
            break
        expected_prev = stored_hash
    checks["event_hashes"] = chain_ok

    # 2. Root hash binds the ordered set.
    checks["root_hash"] = bundle.get("root_hash") == compute_root_hash(events)

    assurance = bundle.get("assurance", "none")
    sig = bundle.get("signature")

    # 3. Signature (only for signed bundles).
    if assurance == "signed":
        if not sig or "signature" not in sig:
            return BundleVerification(False, assurance, checks, "signed bundle missing signature")
        pub = bundle.get("public_key")
        if not pub:
            return BundleVerification(False, assurance, checks, "signed bundle missing public_key")
        if expected_key_id is not None and sig.get("key_id") != expected_key_id:
            return BundleVerification(
                False, assurance, checks,
                f"signed by unexpected key {sig.get('key_id')!r} (expected {expected_key_id!r})",
            )
        checks["signature"] = _verify_sig(pub, _canon(bundle_header(bundle)), sig["signature"])

        # Host-identity attestation: the public_key must self-assert this host_id,
        # so a relabelled host_id (with a matching re-signed header) is still caught
        # unless the attesting key also vouches for the new host_id.
        att = bundle.get("host_identity")
        if att:
            claim = {k: att.get(k) for k in
                     ("host_id", "public_key", "key_id", "valid_from", "valid_until")}
            # Temporal validity: the key must have been valid WHEN it signed this
            # bundle (created_at within [valid_from, valid_until]). ISO-8601 UTC
            # strings compare lexicographically; None means unbounded. A rotated-out
            # key (valid_until in the past of created_at) is rejected — offline, no
            # wall clock needed.
            created = bundle.get("created_at")
            vf, vu = att.get("valid_from"), att.get("valid_until")
            temporal_ok = (
                (vf is None or created is None or vf <= created)
                and (vu is None or created is None or created <= vu)
            )
            checks["host_identity"] = (
                att.get("host_id") == bundle.get("host_id")
                and att.get("public_key") == pub
                and temporal_ok
                and _verify_sig(pub, _canon(claim), att.get("signature", ""))
            )

    valid = all(checks.values())
    reason = None if valid else "one or more integrity checks failed: " + ", ".join(
        k for k, v in checks.items() if not v
    )
    return BundleVerification(valid=valid, assurance=assurance, checks=checks, reason=reason)
