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


def _archive_keypair(key_dir: Path) -> str | None:
    """Move the current keypair to ``<key_dir>/archive/<key_id>/``. Returns the
    archived key_id, or None if there was no key. Overwrite/rotation MUST never
    destroy a key — old signatures stay attributable to their key lineage."""
    pub_path = key_dir / _PUBLIC_NAME
    priv_path = key_dir / _PRIVATE_NAME
    if not pub_path.exists():
        return None
    old_key_id = key_id_for(base64.b64decode(pub_path.read_bytes()))
    dest = key_dir / "archive" / old_key_id
    dest.mkdir(parents=True, exist_ok=True)
    pub_path.rename(dest / _PUBLIC_NAME)
    if priv_path.exists():
        priv_path.rename(dest / _PRIVATE_NAME)
    return old_key_id


def generate_keypair(key_dir: str | Path = DEFAULT_KEY_DIR, *, overwrite: bool = False) -> HostKey:
    """Create an ed25519 keypair under *key_dir* (private 0600, dir 0700).

    ``overwrite=True`` ARCHIVES the existing pair to ``archive/<key_id>/``
    (never destroys it). For rotation with continuity use ``rotate_keypair``."""
    ed25519 = _load_backend()
    key_dir = Path(key_dir)
    priv_path = key_dir / _PRIVATE_NAME
    pub_path = key_dir / _PUBLIC_NAME
    if priv_path.exists() and not overwrite:
        raise FileExistsError(f"key already exists at {priv_path}; pass overwrite=True to replace")
    if overwrite:
        _archive_keypair(key_dir)

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
                      valid_until: str | None = None,
                      anchors: list[dict] | None = None) -> dict:
    """Self-signed statement binding host_id <-> public_key.

    key_id = sha256(pubkey)[:16] only binds a key to itself; host_id is a free
    string anyone can label a bundle with. This puts the identity claim inside a
    signature by the key, so a verifier checks host_id is asserted by the keyholder
    (the TOFU trust floor, now cryptographic rather than a bare string).

    ``anchors`` upgrades the floor: a list of external trust roots that vouch for
    this key (spec/chp-v0.2.md §3 Anchors), e.g. ``{"type": "domain", "domain":
    "acme.com"}``. Anchors live INSIDE the signed claim so they can be neither
    stripped (downgrade) nor stapled on (forgery) without breaking the signature.
    CRITICAL: the key is omitted entirely when empty — emitting ``"anchors": []``
    would change the canonical bytes and break every published test vector."""
    if not host_key.can_sign:
        raise SigningUnavailable("host key has no private component; cannot attest")
    claim: dict[str, Any] = {
        "host_id": host_id,
        "public_key": host_key.public_key_b64,
        "key_id": host_key.key_id,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    if anchors:
        claim["anchors"] = anchors
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


def sign_bundle(bundle: dict, host_key: HostKey, *, valid_until: str | None = None,
                anchors: list[dict] | None = None) -> dict:
    """Sign a bundle's canonical header, promoting it to the `signed` tier.

    Signs the header (host_id/created_at/protocol_version/canonicalization +
    root_hash), not just root_hash, so a stranger cannot relabel the origin
    without breaking the signature. Attaches a self-signed host-identity
    attestation binding host_id <-> public_key (with ``anchors`` when the key
    is anchored to an external trust root — spec §3 Anchors)."""
    if not host_key.can_sign:
        raise SigningUnavailable("host key has no private component; cannot sign")
    signed = dict(bundle)
    signed["assurance"] = "signed"
    signed["public_key"] = host_key.public_key_b64
    signed["host_identity"] = build_attestation(
        signed["host_id"], host_key,
        valid_from=signed.get("created_at", ""), valid_until=valid_until,
        anchors=anchors,
    )
    signed["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": host_key.key_id,
        "signature": _sign(host_key._private, _canon(bundle_header(signed))),
    }
    return signed


def verify_attestation(
    attestation: dict,
    *,
    public_key: str | None = None,
    expected_host_id: str | None = None,
    at_time: str | None = None,
) -> bool:
    """Verify a host-identity attestation (chp-v0.2.md §3): the key self-signs a
    {host_id, public_key, key_id, valid_from, valid_until} claim.

    Checks the self-signature and, when given, that ``public_key`` matches the
    attested key, ``expected_host_id`` matches, and ``at_time`` falls within the
    validity window. Used by both the bundle path and the mesh key-pinning path,
    so a mesh peer verifies the attestation before trusting a key rather than
    pinning whatever ``/host`` self-reports."""
    att_pub = attestation.get("public_key")
    if not att_pub:
        return False
    if public_key is not None and att_pub != public_key:
        return False
    if expected_host_id is not None and attestation.get("host_id") != expected_host_id:
        return False
    vf, vu = attestation.get("valid_from"), attestation.get("valid_until")
    if at_time is not None:
        if vf is not None and at_time < vf:
            return False
        if vu is not None and at_time > vu:
            return False
    # Reconstruct the claim with the SAME conditional-anchors rule as
    # build_attestation: "anchors" participates in the signed bytes only when
    # present. This is what makes anchors strip/staple-proof, and what keeps a
    # no-anchor attestation byte-identical to the pre-anchor format.
    keys = ("host_id", "public_key", "key_id", "valid_from", "valid_until") + (
        ("anchors",) if "anchors" in attestation else ()
    )
    claim = {k: attestation.get(k) for k in keys}
    return _verify_sig(att_pub, _canon(claim), attestation.get("signature", ""))


def _domain_anchor(attestation: dict) -> str | None:
    """The first ``{"type": "domain"}`` anchor's domain, or None. Pure/offline."""
    for anchor in attestation.get("anchors") or []:
        if isinstance(anchor, dict) and anchor.get("type") == "domain" and anchor.get("domain"):
            return str(anchor["domain"])
    return None


def _did_anchor(attestation: dict) -> dict | None:
    """The first ``{"type": "did"}`` anchor, or None. Pure/offline."""
    for anchor in attestation.get("anchors") or []:
        if isinstance(anchor, dict) and anchor.get("type") == "did" and anchor.get("did"):
            return anchor
    return None


def did_anchor_message(chp_public_key_b64: str, host_id: str) -> bytes:
    """The exact bytes a DID key countersigns to anchor a CHP key (§3.1):
    chp-stable-v1 of {chp_public_key, host_id}, SSHSIG namespace
    ``chp-host-anchor``. Shared by the producer and both verifiers."""
    return _canon({"chp_public_key": chp_public_key_b64, "host_id": host_id})


def verify_did_anchor(anchor: dict, chp_public_key_b64: str, host_id: str) -> bool:
    """Offline-verify a ``did`` anchor: the DID's ed25519 key (decoded from
    did:key) must have countersigned THIS CHP key + host_id via SSHSIG."""
    from . import sshsig  # noqa: PLC0415
    try:
        raw_pub = sshsig.did_key_to_raw(str(anchor.get("did", "")))
    except sshsig.SshsigError:
        return False
    return sshsig.verify_sshsig(
        str(anchor.get("countersignature", "")),
        did_anchor_message(chp_public_key_b64, host_id),
        expected_raw_pubkey=raw_pub,
    )


# --------------------------------------------------------------------------
# Key lifecycle: rotation with continuity, history, revocation (spec §3.2)
# --------------------------------------------------------------------------

def rotate_keypair(key_dir: str | Path = DEFAULT_KEY_DIR) -> tuple[HostKey, dict]:
    """Rotate the host keypair WITH CONTINUITY: the OLD key signs a statement
    vouching for the new one, so a verifier that pinned the old key can follow
    the lineage instead of treating rotation as impersonation.

    Returns (new_key, continuity_statement). The statement is self-contained
    (carries old_public_key) and appended to ``<key_dir>/key_history.json``;
    the old pair is archived; the persisted attestation is invalidated so the
    next serve rebuilds under the new key."""
    key_dir = Path(key_dir)
    old = load_host_key(key_dir)
    if old is None or not old.can_sign:
        raise SigningUnavailable("no signing-capable key to rotate; run keygen first")
    from .types import utc_now  # noqa: PLC0415

    new = generate_keypair(key_dir, overwrite=True)  # archives the old pair
    claim = {
        "old_key_id": old.key_id,
        "old_public_key": old.public_key_b64,
        "new_key_id": new.key_id,
        "new_public_key": new.public_key_b64,
        "rotated_at": utc_now(),
    }
    statement = {**claim, "signature": _sign(old._private, _canon(claim))}
    history = load_key_history(key_dir)
    history.append(statement)
    (key_dir / "key_history.json").write_text(json.dumps(history, indent=2, sort_keys=True) + "\n")
    att = key_dir / "attestation.json"
    if att.exists():
        att.unlink()
    return new, statement


def verify_continuity(statement: dict) -> bool:
    """Verify a rotation continuity statement: signed by the OLD key it names.
    Self-contained — but a verifier holding an independently-pinned old key
    SHOULD check ``old_public_key`` against its pin before trusting it."""
    claim = {k: statement.get(k) for k in
             ("old_key_id", "old_public_key", "new_key_id", "new_public_key", "rotated_at")}
    old_pub = statement.get("old_public_key")
    if not old_pub:
        return False
    return _verify_sig(old_pub, _canon(claim), statement.get("signature", ""))


def load_key_history(key_dir: str | Path = DEFAULT_KEY_DIR) -> list[dict]:
    path = Path(key_dir) / "key_history.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def revoke_key(key_dir: str | Path = DEFAULT_KEY_DIR, *, reason: str = "") -> dict:
    """Revoke the CURRENT key: a self-signed revocation statement persisted to
    ``<key_dir>/revocations.json`` and served in the identity document.
    Resolution-time verifiers see it; offline verifiers cannot (documented
    limit — no global revocation infrastructure at this tier)."""
    key = load_host_key(key_dir)
    if key is None or not key.can_sign:
        raise SigningUnavailable("no signing-capable key to revoke")
    from .types import utc_now  # noqa: PLC0415

    claim = {"revoked_key_id": key.key_id, "revoked_public_key": key.public_key_b64,
             "revoked_at": utc_now(), "reason": reason}
    statement = {**claim, "signature": _sign(key._private, _canon(claim))}
    path = Path(key_dir) / "revocations.json"
    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except Exception:
            existing = []
    existing.append(statement)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")
    return statement


def verify_revocation(statement: dict) -> bool:
    """A revocation statement is self-signed by the key it revokes (a signed
    'do not trust me' — unforgeable by a third party, and an attacker gains
    nothing by forging one against their own stolen key's interests)."""
    claim = {k: statement.get(k) for k in
             ("revoked_key_id", "revoked_public_key", "revoked_at", "reason")}
    pub = statement.get("revoked_public_key")
    if not pub:
        return False
    return _verify_sig(pub, _canon(claim), statement.get("signature", ""))


def load_revocations(key_dir: str | Path = DEFAULT_KEY_DIR) -> list[dict]:
    path = Path(key_dir) / "revocations.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def load_configured_anchors(key_dir: str | Path = DEFAULT_KEY_DIR) -> list[dict]:
    """Anchors configured on this host (``<key_dir>/anchors.json``) — e.g. a
    did anchor produced by ``chp anchor-did``. Merged with any CHP_HOST_DOMAIN
    domain anchor by the serving layer."""
    path = Path(key_dir) / "anchors.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_configured_anchors(anchors: list[dict],
                            key_dir: str | Path = DEFAULT_KEY_DIR) -> None:
    path = Path(key_dir) / "anchors.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(anchors, indent=2, sort_keys=True) + "\n")


def load_or_build_attestation(host_id: str, host_key: HostKey,
                              anchors: list[dict] | None = None,
                              key_dir: str | Path = DEFAULT_KEY_DIR) -> dict:
    """The host's persistent attestation: load from disk if it still matches
    (same host_id, same key, same anchors, signature verifies), else build,
    persist, and return a fresh one.

    Persistence matters: rebuilding per request (the old /host behavior) makes
    valid_from drift to "now" on every fetch, so validity windows and anchors
    were never stable — which breaks anchored resolution and (later) rotation."""
    from .types import utc_now  # noqa: PLC0415

    path = Path(key_dir) / "attestation.json"
    if path.exists():
        try:
            att = json.loads(path.read_text())
            if (
                att.get("host_id") == host_id
                and att.get("public_key") == host_key.public_key_b64
                and (att.get("anchors") if "anchors" in att else None) == (anchors or None)
                and verify_attestation(att, public_key=host_key.public_key_b64)
            ):
                return att
        except Exception:
            pass  # unreadable/stale → rebuild below
    att = build_attestation(host_id, host_key, valid_from=utc_now(), anchors=anchors)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(att, indent=2, sort_keys=True) + "\n")
    return att


class AnchorResolutionError(RuntimeError):
    """Raised when a host identity document cannot be resolved (DNS, TLS,
    non-2xx, oversized, or non-JSON). Distinct from a verification failure —
    resolution errors mean "could not check", never "checked and matched"."""


_IDENTITY_DOC_MAX_BYTES = 64 * 1024
WELL_KNOWN_IDENTITY_PATH = "/.well-known/chp-identity"


def resolve_host_identity(domain_or_url: str, *, timeout: float = 5.0,
                          _urlopen: Any = None) -> dict:
    """Fetch a host's identity document from its well-known endpoint.

    Trust model (spec/chp-v0.2.md §3 Anchors): the document's authority comes
    from being served over TLS by the anchor domain — the Web-PKI chain (CA +
    DNS + domain control) vouches "this domain asserts key P is its CHP signing
    key". Therefore https is REQUIRED and redirects are refused (a redirect to
    http would silently break the chain). ``_urlopen`` is test injection only.
    """
    import urllib.request  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415

    url = domain_or_url if "://" in domain_or_url else f"https://{domain_or_url}"
    if not url.startswith("https://"):
        raise AnchorResolutionError(f"identity resolution requires https, got: {url}")
    if WELL_KNOWN_IDENTITY_PATH not in url:
        url = url.rstrip("/") + WELL_KNOWN_IDENTITY_PATH

    opener = _urlopen
    if opener is None:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a: Any, **k: Any) -> None:  # noqa: ARG002
                return None  # refuse ALL redirects — the origin must serve it

        opener = urllib.request.build_opener(_NoRedirect()).open
    try:
        with opener(url, timeout=timeout) as resp:  # type: ignore[operator]
            raw = resp.read(_IDENTITY_DOC_MAX_BYTES + 1)
    except Exception as exc:
        raise AnchorResolutionError(f"could not resolve {url}: {exc}") from exc
    if len(raw) > _IDENTITY_DOC_MAX_BYTES:
        raise AnchorResolutionError(f"identity document too large (> {_IDENTITY_DOC_MAX_BYTES} bytes)")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise AnchorResolutionError(f"identity document is not JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise AnchorResolutionError("identity document is not a JSON object")
    return doc


@dataclass
class BundleVerification:
    valid: bool
    assurance: str
    checks: dict[str, bool]
    reason: str | None = None
    # Which external trust root vouched for the signing key. The ROOT is the
    # answer to "whose?" — host_id is a local label and must never be treated
    # as the trust root (spec §3.1 Anchors). anchored_domain requires
    # resolve=True (network); anchored_did verifies offline.
    anchored_domain: str | None = None
    anchored_did: str | None = None


def verify_bundle(bundle: dict, *, expected_key_id: str | None = None,
                  resolve: bool = False) -> BundleVerification:
    """Offline-verify an exported bundle: per-event hashes, chain continuity,
    root hash, and (for signed bundles) the ed25519 signature.

    ``expected_key_id`` pins the signer — a bundle signed by a different key is
    rejected (defends against a valid signature from an untrusted key).

    ``resolve=True`` additionally resolves the attestation's domain anchor (if
    any) over https and checks the bundle's key against the domain's published
    identity document — provenance from a host you've never met, rooted in the
    anchor domain. Default False keeps verification fully offline (unchanged
    behavior for existing callers); a no-anchor bundle under resolve=True simply
    has no ``anchor`` check — visibly TOFU-floor, never silently 'verified'."""
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
    anchored_domain: str | None = None
    anchored_did: str | None = None

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
            # The key must have been valid WHEN it signed this bundle: created_at
            # within [valid_from, valid_until]. A rotated-out key is rejected —
            # offline, no wall clock needed.
            checks["host_identity"] = verify_attestation(
                att, public_key=pub, expected_host_id=bundle.get("host_id"),
                at_time=bundle.get("created_at"),
            )

        # DID anchor (offline — no network, no CA/DNS): the Radicle identity key
        # countersigned this CHP key. Verified whenever present; a bad
        # countersignature means a forged provenance claim.
        if att:
            did_anchor = _did_anchor(att)
            if did_anchor is not None:
                checks["did_anchor"] = verify_did_anchor(
                    did_anchor, pub, str(bundle.get("host_id", "")))
                if checks["did_anchor"]:
                    anchored_did = str(did_anchor["did"])

        # Domain-anchor resolution (opt-in): the signed attestation names an
        # external trust root; confirm the root actually vouches for THIS key.
        # Resolution proves CURRENT control of the anchor; the attestation window
        # (above) proves validity at signing time — both recorded, distinct.
        if resolve and att:
            domain = _domain_anchor(att)
            if domain is not None:
                try:
                    doc = resolve_host_identity(domain)
                    doc_keys = {doc.get("public_key"),
                                (doc.get("host_identity") or {}).get("public_key")}
                    checks["anchor"] = pub in doc_keys
                    if checks["anchor"]:
                        anchored_domain = domain
                    # Revocation (§3.2): a resolving verifier sees revocations the
                    # host publishes; a bundle signed by a revoked key is rejected.
                    # Offline verifiers cannot see this — a documented tier limit.
                    revoked = {r.get("revoked_public_key")
                               for r in doc.get("revoked_keys") or []
                               if verify_revocation(r)}
                    if pub in revoked:
                        checks["not_revoked"] = False
                except AnchorResolutionError as exc:
                    checks["anchor"] = False
                    return BundleVerification(False, assurance, checks,
                                              f"anchor resolution failed: {exc}")

    valid = all(checks.values())
    reason = None if valid else "one or more integrity checks failed: " + ", ".join(
        k for k, v in checks.items() if not v
    )
    return BundleVerification(valid=valid, assurance=assurance, checks=checks,
                              reason=reason, anchored_domain=anchored_domain,
                              anchored_did=anchored_did)
