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
import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .store import EVENT_HASH_V2, _compute_event_hash, _payload_commitment

CANONICALIZATION = "chp-stable-v1"
SIGNATURE_ALGORITHM = "ed25519"
DEFAULT_KEY_DIR = Path.home() / ".chp" / "keys"
_PRIVATE_NAME = "host_ed25519"
_PUBLIC_NAME = "host_ed25519.pub"
_SAFE_HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def resolve_key_dir(host_id: str | None = None) -> Path:
    """The signing-key directory for a host.

    Precedence: ``$CHP_KEY_DIR`` → per-host ``~/.chp/keys/<host_id>/`` when it
    holds a key → legacy shared ``~/.chp/keys``. Per-host custody is opt-in by
    provisioning the per-host dir (``chp host keygen --key-dir``); existing
    single-key machines keep working untouched. A deployment SHOULD provision a
    distinct key per host_id (chp-v0.2.md §3) — the shared default makes
    "which host signed this" collapse to "which machine".

    host_ids that are not safe path components never map to a per-host dir.
    """
    env = os.environ.get("CHP_KEY_DIR")
    if env:
        return Path(env)
    if host_id and _SAFE_HOST_ID.match(host_id):
        per_host = DEFAULT_KEY_DIR / host_id
        if (per_host / _PUBLIC_NAME).exists():
            return per_host
    return DEFAULT_KEY_DIR


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


def _resolve_key_passphrase(
    passphrase: str | None, *, prompt: bool = False, confirm: bool = False
) -> bytes | None:
    """At-rest key passphrase (proposal 0017): explicit arg → ``$CHP_KEY_PASSPHRASE``
    → (when ``prompt``) a ``getpass`` prompt. Returns UTF-8 bytes, or None for an
    unencrypted key. An operator MAY source it from an OS keychain and export it
    into the env — no platform-locked dependency lives in core. An empty value is
    treated as no passphrase."""
    import os  # noqa: PLC0415

    pw = passphrase if passphrase is not None else os.environ.get("CHP_KEY_PASSPHRASE")
    if not pw and prompt:
        import getpass  # noqa: PLC0415

        pw = getpass.getpass("CHP key passphrase: ")
        if confirm and pw != getpass.getpass("Confirm passphrase: "):
            raise ValueError("passphrases do not match")
    return pw.encode("utf-8") if pw else None


def _serialize_private(private: Any, passphrase: bytes | None) -> bytes:
    """Bytes to write for the private key. With a passphrase: PKCS#8 PEM under
    ``BestAvailableEncryption`` (self-describing, encrypted at rest). Without:
    the legacy Raw-seed base64 — byte-identical to every existing key."""
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    if passphrase:
        return private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw)


def _load_private(data: bytes, passphrase: bytes | None) -> Any:
    """Load a private key, dispatching on the on-disk format: an encrypted PKCS#8
    PEM (``-----BEGIN`` header) is decrypted with the passphrase; anything else is
    the legacy Raw-seed base64."""
    ed25519 = _load_backend()
    if data.lstrip().startswith(b"-----BEGIN"):
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

        key = serialization.load_pem_private_key(data, password=passphrase)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError("key file is not an ed25519 private key")
        return key
    return ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(data))


def _private_is_encrypted(key_dir: Path) -> bool:
    """True when the on-disk private key is an encrypted PEM (proposal 0017)."""
    priv_path = key_dir / _PRIVATE_NAME
    if not priv_path.exists():
        return False
    return priv_path.read_bytes().lstrip().startswith(b"-----BEGIN")


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


def generate_keypair(
    key_dir: str | Path = DEFAULT_KEY_DIR, *, overwrite: bool = False,
    passphrase: str | None = None,
) -> HostKey:
    """Create an ed25519 keypair under *key_dir* (private 0600, dir 0700).

    ``overwrite=True`` ARCHIVES the existing pair to ``archive/<key_id>/``
    (never destroys it). For rotation with continuity use ``rotate_keypair``.
    A non-empty ``passphrase`` encrypts the private key at rest (PKCS#8,
    proposal 0017); None writes the default Raw+base64 format, byte-identical to
    every existing key. The public key is always written unencrypted."""
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
    priv_bytes = _serialize_private(private, passphrase.encode("utf-8") if passphrase else None)
    pub_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    # Write private with 0600 from the start (no world-readable window).
    import os  # noqa: PLC0415
    fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv_bytes)
    pub_path.write_bytes(base64.b64encode(pub_bytes))
    return HostKey(key_id=key_id_for(pub_bytes), public_key_b64=base64.b64encode(pub_bytes).decode(), _private=private)


def load_host_key(
    key_dir: str | Path = DEFAULT_KEY_DIR, *, passphrase: str | None = None, prompt: bool = False,
) -> HostKey | None:
    """Load the host keypair if present. Returns None if no key exists (the host
    then operates at the hash-chain tier).

    An encrypted-at-rest private key (proposal 0017) is unlocked with the
    passphrase resolved from ``passphrase`` → ``$CHP_KEY_PASSPHRASE`` → (when
    ``prompt``) a prompt. A server loads with ``prompt=False`` (env only) so it
    never blocks on stdin; the CLI passes ``prompt=True``."""
    key_dir = Path(key_dir)
    priv_path = key_dir / _PRIVATE_NAME
    pub_path = key_dir / _PUBLIC_NAME
    if not pub_path.exists():
        return None
    pub_bytes = base64.b64decode(pub_path.read_bytes())
    private = None
    if priv_path.exists():
        data = priv_path.read_bytes()
        # Resolve a passphrase only when the file is actually encrypted, so an
        # unencrypted key never prompts.
        pw = None
        if data.lstrip().startswith(b"-----BEGIN"):
            pw = _resolve_key_passphrase(passphrase, prompt=prompt)
            if pw is None:
                raise ValueError(
                    f"encrypted key at {priv_path} requires a passphrase "
                    "(set $CHP_KEY_PASSPHRASE)"
                )
        private = _load_private(data, pw)
    return HostKey(
        key_id=key_id_for(pub_bytes),
        public_key_b64=base64.b64encode(pub_bytes).decode(),
        _private=private,
    )


def _canon(obj: Any) -> bytes:
    """chp-stable-v1 canonical bytes: sorted keys, spaced separators, ensure_ascii."""
    return json.dumps(obj, sort_keys=True).encode()


def _reject_floats(obj: Any) -> None:
    """§2 rule 6: no non-integer numbers in canonicalized content. Retained across
    ALL schemes (bool is an int subclass and is fine; a float is not)."""
    if isinstance(obj, float):
        raise ValueError("chp-jcs-v1 forbids non-integer numbers (chp-v0.2.md §2 rule 6)")
    if isinstance(obj, dict):
        for v in obj.values():
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_floats(v)


def _jcs_sort(obj: Any) -> Any:
    """Recursively order object keys by UTF-16 code unit (RFC 8785 §3.2.3).
    `str.encode('utf-16-be')` compared as bytes == code-unit order, and matches
    JS `.sort()` — so Python and TS agree byte-for-byte even on astral-plane
    keys (Python's own `sort_keys` sorts by code point and would diverge there)."""
    if isinstance(obj, dict):
        return {k: _jcs_sort(obj[k]) for k in sorted(obj, key=lambda s: s.encode("utf-16-be"))}
    if isinstance(obj, (list, tuple)):
        return [_jcs_sort(v) for v in obj]
    return obj


def _canon_jcs(obj: Any) -> bytes:
    """chp-jcs-v1 canonical bytes (RFC 8785 JCS, proposal 0015): compact
    separators, raw UTF-8 (no \\uXXXX escaping), keys sorted by UTF-16 code
    unit. Over CHP's float-free content this is `json.dumps` with
    `ensure_ascii=False` + compact separators; rule 6 is retained (non-integer
    numbers rejected) so RFC 8785's number-formatting algorithm is never
    exercised."""
    _reject_floats(obj)
    return json.dumps(_jcs_sort(obj), ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


CANONICALIZATION_JCS = "chp-jcs-v1"


def _canon_for(scheme: str | None):
    """Dispatch the header-signature serializer by the `canonicalization` field
    (chp-v0.2.md §2 — the evolution seam, proposal 0015). Absent/legacy →
    chp-stable-v1; raises on an unknown scheme (a verifier turns that into a
    failed signature check, never a crash)."""
    if scheme == CANONICALIZATION_JCS:
        return _canon_jcs
    if scheme in (None, "", CANONICALIZATION):
        return _canon
    raise ValueError(f"unknown canonicalization scheme: {scheme!r}")


# Fields covered by the header signature. Everything a stranger reads to decide
# "who/when/how" must be inside the signature — not just root_hash (events are
# already bound via root_hash). See spec/chp-v0.2.md §3.
_HEADER_FIELDS = ("host_id", "protocol_version", "created_at", "canonicalization", "root_hash")


COMPLETENESS_SCHEME = "chp-completeness-v1"


def bundle_header(bundle: dict) -> dict:
    """The signed header: the origin/time/scheme claims + root_hash, plus the
    non-omission `completeness` claim when present. `completeness` participates in
    the signed bytes ONLY when set (omit-when-absent, §12 / proposal 0018) — a
    bundle without it is byte-identical and a pre-0018 signature still verifies,
    exactly like `revocation_head` in the chain-witness header."""
    header = {k: bundle.get(k) for k in _HEADER_FIELDS}
    if bundle.get("completeness"):
        header["completeness"] = bundle["completeness"]
    return header


def build_completeness(correlation_id: str, events: list[dict], as_of_sequence: int) -> dict:
    """A `chp-completeness-v1` non-omission claim (§12, proposal 0018): the bundle
    asserts it is the COMPLETE correlation — genesis to the tail event's
    `content_hash` — as of global store `sequence` (no events for this correlation
    exist through `as_of_sequence`). Audited against a witnessed store head whose
    `leaves[correlation_id]` already commits the true tail."""
    if not events:
        raise ValueError("completeness requires at least one event")
    tail = events[-1].get("content_hash")
    if not tail:
        raise ValueError("tail event is unhashed; cannot claim completeness")
    return {
        "scheme": COMPLETENESS_SCHEME,
        "correlation_id": correlation_id,
        "as_of_sequence": as_of_sequence,
        "head_hash": tail,
    }


def build_attestation(host_id: str, host_key: HostKey, *, valid_from: str,
                      valid_until: str | None = None,
                      anchors: list[dict] | None = None,
                      enc_public_key: str | None = None) -> dict:
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
    if enc_public_key:
        # The recipient's X25519 sealing key (§16, proposal 0025), bound to
        # host_id by living inside the signed claim. Omit-when-empty like anchors —
        # emitting it when unset would change canonical bytes.
        claim["enc_public_key"] = enc_public_key
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
    canonicalization: str = CANONICALIZATION,
    completeness: dict | None = None,
) -> dict:
    """Build an unsigned (`hash-chain` tier) evidence bundle from exported events.

    ``canonicalization`` selects the header-signature serializer (§2, proposal
    0015): ``chp-stable-v1`` (default) or ``chp-jcs-v1`` (RFC 8785). Event
    content-hashes are the orthogonal ``hash_scheme`` axis and are unaffected.
    ``completeness`` (proposal 0018) attaches a non-omission claim — omit-when-
    absent, so a bundle without it is byte-identical."""
    _canon_for(canonicalization)  # validate the scheme name up front
    bundle: dict[str, Any] = {
        "host_id": host_id,
        "protocol_version": protocol_version,
        "created_at": created_at,
        "canonicalization": canonicalization,
        "assurance": "hash-chain",
        "events": events,
        "root_hash": compute_root_hash(events),
    }
    if completeness:
        bundle["completeness"] = completeness
    return bundle


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
        # Dispatch the header canon on the bundle's `canonicalization` (§2, 0015).
        "signature": _sign(host_key._private,
                           _canon_for(signed.get("canonicalization"))(bundle_header(signed))),
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
    ) + (("enc_public_key",) if "enc_public_key" in attestation else ())
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


def store_head_anchor_message(host_id: str, sequence: int, store_head: str,
                              anchored_at: str) -> bytes:
    """The exact bytes an external DID key countersigns to anchor a store head
    (chp-v0.2.md §12 External anchoring, proposal 0013): chp-stable-v1 of
    {kind, host_id, sequence, store_head, anchored_at}, SSHSIG namespace
    ``chp-store-head-anchor``. Shared by the producer and the verifier."""
    return _canon({"kind": "store-head-anchor", "host_id": host_id,
                   "sequence": sequence, "store_head": store_head,
                   "anchored_at": anchored_at})


def build_store_head_anchor(host_id: str, sequence: int, store_head: str, *,
                            anchored_at: str, did: str, countersignature: str,
                            store_head_scheme: str | None = None) -> dict:
    """Assemble a ``store-head-anchor`` statement (§12, proposal 0013) from an
    external DID key's SSHSIG ``countersignature`` over
    ``store_head_anchor_message(...)``. The countersignature is produced OUTSIDE
    the mesh (a notary / transparency-log checkpoint key); this only assembles +
    the verifier checks it offline.

    ``store_head_scheme`` (proposal 0019) is included **omit-when-absent** — it is
    advisory (the countersigned bytes do not include it; it is self-validated
    because recomputing the root under it must equal the countersigned
    ``store_head``), so a v1 anchor stays byte-identical. A v2 anchor names
    ``chp-store-head-v2`` so a stranger can recompute + verify an inclusion proof."""
    stmt = {"kind": "store-head-anchor", "host_id": host_id, "sequence": sequence,
            "store_head": store_head, "anchored_at": anchored_at,
            "anchor": {"type": "did", "did": did, "countersignature": countersignature}}
    if store_head_scheme:
        stmt["store_head_scheme"] = store_head_scheme
    return stmt


def verify_store_head_anchor(statement: dict) -> BundleVerification:
    """Offline-verify a store-head anchor: the external did:key's ed25519 key
    must have SSHSIG-countersigned THIS (host_id, sequence, store_head,
    anchored_at) under namespace ``chp-store-head-anchor``. Independent of the
    witnessing peer set — an anchored head survives even if every witness
    colludes."""
    from . import sshsig  # noqa: PLC0415

    checks: dict[str, bool] = {}
    checks["structure"] = (statement.get("kind") == "store-head-anchor"
                           and bool(statement.get("host_id"))
                           and isinstance(statement.get("sequence"), int)
                           and bool(statement.get("store_head")))
    anchor = statement.get("anchor") or {}
    anchored_did: str | None = None
    try:
        raw_pub = sshsig.did_key_to_raw(str(anchor.get("did", "")))
        checks["anchor"] = sshsig.verify_sshsig(
            str(anchor.get("countersignature", "")),
            store_head_anchor_message(str(statement.get("host_id")),
                                      int(statement.get("sequence", 0)),
                                      str(statement.get("store_head")),
                                      str(statement.get("anchored_at", ""))),
            namespace=sshsig.STORE_HEAD_ANCHOR_NAMESPACE,
            expected_raw_pubkey=raw_pub)
        if checks["anchor"]:
            anchored_did = str(anchor.get("did"))
    except sshsig.SshsigError:
        checks["anchor"] = False

    valid = all(checks.values())
    reason = None if valid else "store-head-anchor checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return BundleVerification(valid, "signed", checks, reason, anchored_did=anchored_did)


# --------------------------------------------------------------------------
# Key lifecycle: rotation with continuity, history, revocation (spec §3.2)
# --------------------------------------------------------------------------

def rotate_keypair(
    key_dir: str | Path = DEFAULT_KEY_DIR, *, passphrase: str | None = None, prompt: bool = False,
) -> tuple[HostKey, dict]:
    """Rotate the host keypair WITH CONTINUITY: the OLD key signs a statement
    vouching for the new one, so a verifier that pinned the old key can follow
    the lineage instead of treating rotation as impersonation.

    Returns (new_key, continuity_statement). The statement is self-contained
    (carries old_public_key) and appended to ``<key_dir>/key_history.json``;
    the old pair is archived; the persisted attestation is invalidated so the
    next serve rebuilds under the new key. The new key preserves the old one's
    encryption disposition (proposal 0017) — an encrypted key rotates to an
    encrypted key under the same passphrase."""
    key_dir = Path(key_dir)
    was_encrypted = _private_is_encrypted(key_dir)
    old = load_host_key(key_dir, passphrase=passphrase, prompt=prompt)
    if old is None or not old.can_sign:
        raise SigningUnavailable("no signing-capable key to rotate; run keygen first")
    from .types import utc_now  # noqa: PLC0415

    # Keep the new key encrypted iff the old one was (reuse the same passphrase).
    new_pass = _resolve_key_passphrase(passphrase, prompt=False) if was_encrypted else None
    new = generate_keypair(
        key_dir, overwrite=True,  # archives the old pair
        passphrase=new_pass.decode("utf-8") if new_pass else None,
    )
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

    # 1b. Selective disclosure (§14): a DISCLOSED chp-event-hash-v2 payload must
    # match the commitment its content_hash bound. A WITHHELD payload
    # ({"chp_withheld": true}) is skipped — the commitment alone secures the
    # chain. v1 events carry no commitment and are not checked here.
    commit_ok = True
    for ev in events:
        if ev.get("hash_scheme") != EVENT_HASH_V2:
            continue
        payload = ev.get("payload")
        if isinstance(payload, dict) and payload.get("chp_withheld") is True:
            continue  # withheld, not disclosed
        if isinstance(payload, dict) and "chp_sealed" in payload:
            continue  # sealed (§16, proposal 0025) — encrypted-but-present; the
            # commitment alone secures the chain, exactly like a withheld payload.
        if _payload_commitment(payload) != ev.get("payload_commitment"):
            commit_ok = False
            break
    checks["payload_commitments"] = commit_ok

    # 2. Root hash binds the ordered set.
    checks["root_hash"] = bundle.get("root_hash") == compute_root_hash(events)

    # 2b. Completeness self-check (§12, proposal 0018): when the bundle claims to
    # be the complete correlation, its head_hash MUST be the tail event's
    # content_hash, the correlation_id must match the events, and as_of_sequence
    # must be at least the tail's sequence. With genesis-contiguity (check 1: the
    # first event's prev_hash is null) this proves a full genesis→tail chain AS
    # CLAIMED — the teeth come from audit_completeness vs a witnessed head. The
    # claim is signed (bundle_header), so it cannot be altered without breaking
    # the signature.
    claim = bundle.get("completeness")
    if claim is not None:
        tail = events[-1] if events else {}
        tail_corr = (tail.get("correlation") or {}).get("correlation_id")
        tail_seq = tail.get("sequence")
        checks["completeness"] = (
            claim.get("scheme") == COMPLETENESS_SCHEME
            and bool(events)
            and claim.get("head_hash") == tail.get("content_hash")
            and (tail_corr is None or claim.get("correlation_id") == tail_corr)
            and (tail_seq is None or claim.get("as_of_sequence", -1) >= tail_seq)
        )

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
        # Dispatch the header-signature serializer on the bundle's declared
        # `canonicalization` (§2 seam, proposal 0015): chp-stable-v1 (absent/
        # legacy) or chp-jcs-v1. An unknown scheme is a failed signature, never
        # a crash.
        try:
            header_canon = _canon_for(bundle.get("canonicalization"))
        except ValueError:
            return BundleVerification(
                False, assurance, {**checks, "signature": False},
                f"unknown canonicalization scheme {bundle.get('canonicalization')!r}")
        checks["signature"] = _verify_sig(pub, header_canon(bundle_header(bundle)), sig["signature"])

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


def withhold_payloads(bundle: dict, predicate: Callable[[dict], bool] | None = None) -> dict:
    """Return a disclosure-minimized copy of a bundle (chp-v0.2.md §14): every
    ``chp-event-hash-v2`` event for which ``predicate(event)`` is true has its
    ``payload`` replaced by the marker ``{"chp_withheld": true}``, keeping its
    ``payload_commitment`` and ``content_hash``. The root hash and signature are
    UNCHANGED (both bind only ``content_hash``), so the ORIGINAL signature still
    verifies the minimized bundle — no re-signing, no store mutation. ``predicate``
    defaults to withholding every v2 event; v1 events carry no commitment and are
    left intact (they cannot be withheld without breaking their hash)."""
    if predicate is None:
        predicate = lambda ev: True  # noqa: E731
    out = copy.deepcopy(bundle)
    for ev in out.get("events") or []:
        if ev.get("hash_scheme") == EVENT_HASH_V2 and ev.get("payload_commitment") and predicate(ev):
            ev["payload"] = {"chp_withheld": True}
    return out


# --------------------------------------------------------------------------
# Task bundles — cross-host verification unit (chp-v0.2.md §8)
# --------------------------------------------------------------------------

def compute_task_root_hash(bundles: list[dict]) -> str:
    """SHA256 over member root_hashes joined by "\\n" (compute_root_hash, one
    level up) — a single tamper-evident fingerprint for the whole task: swap,
    add, or drop any member and it changes."""
    h = hashlib.sha256()
    for b in bundles:
        h.update((b.get("root_hash") or "").encode())
        h.update(b"\n")
    return h.hexdigest()


def _member_sort_key(bundle: dict) -> tuple[str, str]:
    return (str(bundle.get("host_id") or ""), str(bundle.get("root_hash") or ""))


_PROVENANCE_HEADER_FIELDS = ("kind", "package", "version", "wheel_sha256",
                             "created_at", "canonicalization")


def provenance_header(stmt: dict) -> dict:
    """The publisher-signed header of an adapter-provenance statement (§9)."""
    return {k: stmt.get(k) for k in _PROVENANCE_HEADER_FIELDS}


def build_provenance_statement(package: str, version: str, wheel_sha256: str,
                               host_key: HostKey, *, publisher_id: str,
                               created_at: str,
                               valid_until: str | None = None,
                               anchors: list[dict] | None = None,
                               key_history: list[dict] | None = None) -> dict:
    """A publisher's signed claim: "I built this exact artifact" (proposal 0001,
    chp-v0.2.md §9).

    Signs the canonical header {kind, package, version, wheel_sha256,
    created_at, canonicalization} with the publisher's CHP key and attaches the
    publisher's host-identity attestation (anchors ride inside it, same
    omit-when-empty rule as bundles). ``wheel_sha256`` is the SHA-256 of the
    artifact FILE — verifiable before anything executes. The installed-RECORD
    fingerprint stays evidence-side (pip rewrites RECORD at install; it is not
    a pre-install invariant)."""
    if not host_key.can_sign:
        raise SigningUnavailable("publisher key has no private component; cannot sign")
    stmt: dict = {
        "kind": "adapter-provenance",
        "package": package,
        "version": version,
        "wheel_sha256": wheel_sha256,
        "created_at": created_at,
        "canonicalization": CANONICALIZATION,
    }
    stmt["publisher"] = {
        "host_id": publisher_id,
        "public_key": host_key.public_key_b64,
        "host_identity": build_attestation(
            publisher_id, host_key, valid_from=created_at,
            valid_until=valid_until, anchors=anchors),
    }
    # Rotation continuity (§3.2, applied to publishers): the statement carries
    # the key's rotation lineage so a verifier pinned to an OLD key can walk to
    # this one. Omit-when-empty — pre-rotation statements are byte-identical.
    # The history cannot self-vouch: the walk verifies each hop under the key
    # the VERIFIER already trusts.
    if key_history:
        stmt["publisher"]["key_history"] = key_history
    stmt["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": host_key.key_id,
        "signature": _sign(host_key._private, _canon(provenance_header(stmt))),
    }
    return stmt


def verify_provenance_statement(stmt: dict, *,
                                expected_key_id: str | None = None,
                                wheel_sha256: str | None = None) -> BundleVerification:
    """Offline-verify an adapter-provenance statement: header signature,
    publisher attestation (binding + temporal), DID anchor when present, and —
    when ``wheel_sha256`` is supplied — that the artifact on hand IS the one
    the publisher signed."""
    checks: dict[str, bool] = {}
    checks["structure"] = (stmt.get("kind") == "adapter-provenance"
                           and bool(stmt.get("package")) and bool(stmt.get("version"))
                           and bool(stmt.get("wheel_sha256")))
    pub = stmt.get("publisher") or {}
    pub_key = str(pub.get("public_key") or "")
    sig = stmt.get("signature") or {}
    anchored_domain: str | None = None
    anchored_did: str | None = None

    if expected_key_id is not None and sig.get("key_id") != expected_key_id:
        return BundleVerification(
            False, "signed", checks,
            f"signed by unexpected key {sig.get('key_id')!r} (expected {expected_key_id!r})")

    checks["signature"] = (sig.get("algorithm") == SIGNATURE_ALGORITHM
                           and bool(pub_key)
                           and _verify_sig(pub_key, _canon(provenance_header(stmt)),
                                           str(sig.get("signature") or "")))

    att = pub.get("host_identity")
    if att:
        checks["publisher_identity"] = verify_attestation(
            att, public_key=pub_key, expected_host_id=pub.get("host_id"),
            at_time=stmt.get("created_at"))
        anchored_domain = _domain_anchor(att)
        did_anchor = _did_anchor(att)
        if did_anchor is not None:
            checks["did_anchor"] = verify_did_anchor(
                did_anchor, pub_key, str(pub.get("host_id", "")))
            if checks["did_anchor"]:
                anchored_did = str(did_anchor.get("did"))
    else:
        checks["publisher_identity"] = False  # a provenance claim must say WHO

    if wheel_sha256 is not None:
        checks["artifact_hash"] = wheel_sha256 == stmt.get("wheel_sha256")

    valid = all(checks.values())
    reason = None if valid else "provenance checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return BundleVerification(valid, "signed", checks, reason,
                              anchored_domain=anchored_domain,
                              anchored_did=anchored_did)


_CHAIN_WITNESS_HEADER_FIELDS = ("kind", "host_id", "sequence", "store_head",
                                "witnessed_at", "canonicalization")


def chain_witness_header(statement: dict) -> dict:
    """The witness-signed header of a chain-witness statement (§12). A
    revocation-freshness statement (proposal 0010) additionally covers
    ``revocation_head`` — present ONLY when set, so a pre-0010 statement's
    header is byte-identical (the §10 omit-when-empty rule)."""
    header = {k: statement.get(k) for k in _CHAIN_WITNESS_HEADER_FIELDS}
    if statement.get("revocation_head"):
        header["revocation_head"] = statement["revocation_head"]
    return header


def build_chain_witness(witnessed_host_id: str, sequence: int, store_head: str,
                        witness_key: HostKey, *, witness_id: str,
                        witnessed_at: str,
                        anchors: list[dict] | None = None,
                        revocation_head: str | None = None) -> dict:
    """A peer's signed countersignature over another host's store head
    (proposal 0005, chp-v0.2.md §12): "at global sequence N, HOST's store
    digested to ROOT." The fourth statement-family member. The witness signs
    only the ROOT(s) (no correlation or revocation ids leak); because chains
    are append-only, the witnessed host's history at sequence ≤ N is committed
    — a later rewrite recomputes to a different root. The record's value is
    that it lives with the WITNESS: the witnessed operator cannot delete it.
    When ``revocation_head`` is supplied (proposal 0010) it is countersigned
    too, making a dropped revocation detectable."""
    if not witness_key.can_sign:
        raise SigningUnavailable("witness key has no private component; cannot sign")
    statement: dict = {
        "kind": "chain-witness",
        "host_id": witnessed_host_id,
        "sequence": sequence,
        "store_head": store_head,
        "witnessed_at": witnessed_at,
        "canonicalization": CANONICALIZATION,
    }
    if revocation_head:
        statement["revocation_head"] = revocation_head
    statement["witness"] = {
        "host_id": witness_id,
        "public_key": witness_key.public_key_b64,
        "host_identity": build_attestation(
            witness_id, witness_key, valid_from=witnessed_at, anchors=anchors),
    }
    statement["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": witness_key.key_id,
        "signature": _sign(witness_key._private, _canon(chain_witness_header(statement))),
    }
    return statement


def verify_chain_witness(statement: dict, *,
                         expected_host_id: str | None = None,
                         expected_witness_key: str | None = None) -> BundleVerification:
    """Offline-verify a chain-witness statement: structure, header signature,
    witness attestation (binding + temporal), DID anchor when present, and —
    when supplied — the witnessed host binding and witness key pin. Store-head
    RECOMPUTATION is a separate act (``chp witness verify --store``): it needs
    the store, which a statement verifier does not have."""
    checks: dict[str, bool] = {}
    checks["structure"] = (statement.get("kind") == "chain-witness"
                           and bool(statement.get("host_id"))
                           and isinstance(statement.get("sequence"), int)
                           and bool(statement.get("store_head")))
    witness = statement.get("witness") or {}
    pub = str(witness.get("public_key") or "")
    sig = statement.get("signature") or {}
    anchored_domain: str | None = None
    anchored_did: str | None = None

    if expected_witness_key is not None and sig.get("key_id") != expected_witness_key:
        return BundleVerification(
            False, "signed", checks,
            f"signed by unexpected witness key {sig.get('key_id')!r} "
            f"(expected {expected_witness_key!r})")

    checks["signature"] = (sig.get("algorithm") == SIGNATURE_ALGORITHM
                           and bool(pub)
                           and _verify_sig(pub, _canon(chain_witness_header(statement)),
                                           str(sig.get("signature") or "")))

    att = witness.get("host_identity")
    if att:
        checks["witness_identity"] = verify_attestation(
            att, public_key=pub, expected_host_id=witness.get("host_id"),
            at_time=statement.get("witnessed_at"))
        anchored_domain = _domain_anchor(att)
        did_anchor = _did_anchor(att)
        if did_anchor is not None:
            checks["did_anchor"] = verify_did_anchor(
                did_anchor, pub, str(witness.get("host_id", "")))
            if checks["did_anchor"]:
                anchored_did = str(did_anchor.get("did"))
    else:
        checks["witness_identity"] = False  # a countersignature must say WHO witnessed

    if expected_host_id is not None:
        checks["witnessed_host"] = statement.get("host_id") == expected_host_id

    valid = all(checks.values())
    reason = None if valid else "chain-witness checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return BundleVerification(valid, "signed", checks, reason,
                              anchored_domain=anchored_domain,
                              anchored_did=anchored_did)


_STORE_HEAD_MONITOR_HEADER_FIELDS = ("kind", "host_id", "verified_through_sequence",
                                     "anchor_count", "verdict", "monitored_at",
                                     "canonicalization")


def store_head_monitor_report_header(report: dict) -> dict:
    """The monitor-signed header of a store-head-monitor-report (§12, proposal
    0023). The ``divergence`` block is covered ONLY when present (a ``forked``
    report), so a ``consistent`` report's header is byte-identical — the §10
    omit-when-empty rule, as for chain-witness ``revocation_head``."""
    header = {k: report.get(k) for k in _STORE_HEAD_MONITOR_HEADER_FIELDS}
    if report.get("divergence"):
        header["divergence"] = report["divergence"]
    return header


def build_store_head_monitor_report(host_id: str, *, verdict: str,
                                    verified_through_sequence: int, anchor_count: int,
                                    monitor_key: HostKey, monitor_id: str,
                                    monitored_at: str,
                                    divergence: dict | None = None,
                                    anchors: list[dict] | None = None) -> dict:
    """A monitor's signed finding over a host's anchor history (§12, proposal
    0023). ``verdict`` ``consistent`` (every anchored root still reconstructs from
    the live store, through ``verified_through_sequence``) or ``forked``
    (``divergence`` names the sequence where the live store stopped reproducing the
    anchored root — a rewrite). Signed by the MONITOR: the report lives with the
    monitor, not the monitored host, so the operator cannot retract it."""
    if not monitor_key.can_sign:
        raise SigningUnavailable("monitor key has no private component; cannot sign")
    report: dict = {
        "kind": "store-head-monitor-report",
        "host_id": host_id,
        "verified_through_sequence": verified_through_sequence,
        "anchor_count": anchor_count,
        "verdict": verdict,
        "monitored_at": monitored_at,
        "canonicalization": CANONICALIZATION,
    }
    if divergence:
        report["divergence"] = divergence
    report["monitor"] = {
        "host_id": monitor_id,
        "public_key": monitor_key.public_key_b64,
        "host_identity": build_attestation(
            monitor_id, monitor_key, valid_from=monitored_at, anchors=anchors),
    }
    report["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": monitor_key.key_id,
        "signature": _sign(monitor_key._private,
                           _canon(store_head_monitor_report_header(report))),
    }
    return report


def verify_store_head_monitor_report(
        report: dict, *, expected_host_id: str | None = None,
        expected_monitor_key: str | None = None) -> BundleVerification:
    """Offline-verify a store-head-monitor-report: structure, header signature,
    monitor attestation, DID anchor when present, and optional host/key pins. A
    ``forked`` verdict must NAME a real divergence. Store-head RECONSTRUCTION is a
    separate act the monitor already performed; a report verifier trusts the
    signed verdict (re-running the reconstruction needs the store)."""
    checks: dict[str, bool] = {}
    checks["structure"] = (report.get("kind") == "store-head-monitor-report"
                           and bool(report.get("host_id"))
                           and report.get("verdict") in ("consistent", "forked")
                           and isinstance(report.get("verified_through_sequence"), int))
    if report.get("verdict") == "forked":
        div = report.get("divergence") or {}
        checks["divergence_present"] = bool(
            div.get("anchored_root") and div.get("reconstructed_root")
            and div.get("anchored_root") != div.get("reconstructed_root"))
    monitor = report.get("monitor") or {}
    pub = str(monitor.get("public_key") or "")
    sig = report.get("signature") or {}
    anchored_domain: str | None = None
    anchored_did: str | None = None

    if expected_monitor_key is not None and sig.get("key_id") != expected_monitor_key:
        return BundleVerification(
            False, "signed", checks,
            f"signed by unexpected monitor key {sig.get('key_id')!r} "
            f"(expected {expected_monitor_key!r})")

    checks["signature"] = (sig.get("algorithm") == SIGNATURE_ALGORITHM
                           and bool(pub)
                           and _verify_sig(pub, _canon(store_head_monitor_report_header(report)),
                                           str(sig.get("signature") or "")))

    att = monitor.get("host_identity")
    if att:
        checks["monitor_identity"] = verify_attestation(
            att, public_key=pub, expected_host_id=monitor.get("host_id"),
            at_time=report.get("monitored_at"))
        anchored_domain = _domain_anchor(att)
        did_anchor = _did_anchor(att)
        if did_anchor is not None:
            checks["did_anchor"] = verify_did_anchor(
                did_anchor, pub, str(monitor.get("host_id", "")))
            if checks["did_anchor"]:
                anchored_did = str(did_anchor.get("did"))
    else:
        checks["monitor_identity"] = False  # a report must say WHO monitored

    if expected_host_id is not None:
        checks["monitored_host"] = report.get("host_id") == expected_host_id

    valid = all(checks.values())
    reason = None if valid else "monitor-report checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return BundleVerification(valid, "signed", checks, reason,
                              anchored_domain=anchored_domain, anchored_did=anchored_did)


# ── Signed bearer tokens (chp-v0.2.md §5, proposal 0027) ─────────────────────

_AUTH_TOKEN_HEADER_FIELDS = ("kind", "sub", "aud", "iat", "exp", "canonicalization")


def auth_token_header(token: dict) -> dict:
    """The caller-signed header of an auth-token (§5, proposal 0027)."""
    return {k: token.get(k) for k in _AUTH_TOKEN_HEADER_FIELDS}


def build_auth_token(caller_key: HostKey, *, sub: str, aud: str, iat: str, exp: str,
                     anchors: list[dict] | None = None) -> dict:
    """A caller's ed25519-signed, short-lived, audience-bound bearer token (§5,
    proposal 0027): "I am ``sub``, presenting to ``aud``, until ``exp``." The
    signature covers the canonical header; the ``caller`` block is the same
    self-attested identity a mandate principal carries. Presented over the wire as
    ``X-CHP-Token`` / ``Authorization: Bearer``."""
    if not caller_key.can_sign:
        raise SigningUnavailable("caller key has no private component; cannot mint a token")
    token: dict = {
        "kind": "auth-token", "sub": sub, "aud": aud, "iat": iat, "exp": exp,
        "canonicalization": CANONICALIZATION,
    }
    token["caller"] = {
        "host_id": sub,
        "public_key": caller_key.public_key_b64,
        "host_identity": build_attestation(sub, caller_key, valid_from=iat, anchors=anchors),
    }
    token["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": caller_key.key_id,
        "signature": _sign(caller_key._private, _canon(auth_token_header(token))),
    }
    return token


def verify_auth_token(token: dict, *, aud: str, at_time: str,
                      expected_caller_key: str | None = None) -> BundleVerification:
    """Verify an auth-token is internally valid (§5, proposal 0027): structure,
    header signature against the caller's self-attested key, the caller attestation
    binds ``host_id == sub`` to that key, ``aud`` matches, and ``iat ≤ at_time <
    exp``. When ``expected_caller_key`` is given (the host's pin for ``sub``), the
    caller's public key MUST equal it — the authorization step. A failure is a
    transport rejection, not a governance denial."""
    checks: dict[str, bool] = {}
    checks["structure"] = (token.get("kind") == "auth-token"
                           and bool(token.get("sub")) and bool(token.get("aud")))
    caller = token.get("caller") or {}
    pub = str(caller.get("public_key") or "")
    sig = token.get("signature") or {}
    if expected_caller_key is not None and pub != expected_caller_key:
        return BundleVerification(
            False, "signed", checks,
            f"caller key not authorized for sub {token.get('sub')!r}")
    checks["signature"] = (sig.get("algorithm") == SIGNATURE_ALGORITHM and bool(pub)
                           and _verify_sig(pub, _canon(auth_token_header(token)),
                                           str(sig.get("signature") or "")))
    att = caller.get("host_identity")
    if att:
        checks["caller_identity"] = verify_attestation(
            att, public_key=pub, expected_host_id=token.get("sub"), at_time=at_time)
    else:
        checks["caller_identity"] = False  # a token must say WHO signs it
    checks["audience"] = token.get("aud") == aud
    iat, exp = token.get("iat"), token.get("exp")
    checks["temporal"] = ((iat is None or str(iat) <= at_time)
                          and (exp is None or at_time < str(exp)))
    valid = all(checks.values())
    reason = None if valid else "auth-token checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return BundleVerification(valid, "signed", checks, reason)


_MANDATE_HEADER_FIELDS = ("kind", "mandate_id", "delegate_id", "scope",
                          "valid_from", "valid_until", "created_at",
                          "canonicalization")


# Sub-delegation chains (§10, proposal 0009) are capped so an over-deep or
# malicious embedded chain fails WITHOUT recursing to the Python recursion limit.
_MAX_MANDATE_DEPTH = 8


def mandate_header(mandate: dict) -> dict:
    """The principal-signed header of a mandate (§10). A sub-mandate (proposal
    0009) additionally covers ``depth`` and ``parent_id`` — but ONLY when
    ``parent_id`` is set, so a root/single-hop mandate's header is
    byte-identical to v0.2.3 (the omit-when-absent byte rule)."""
    header = {k: mandate.get(k) for k in _MANDATE_HEADER_FIELDS}
    if mandate.get("parent_id"):
        header["depth"] = mandate.get("depth")
        header["parent_id"] = mandate.get("parent_id")
    if mandate.get("max_invocations") is not None:
        # Use-count cap (§10, proposal 0026) is signed only when present, so an
        # uncapped mandate's header is byte-identical to pre-0026.
        header["max_invocations"] = mandate["max_invocations"]
    return header


def scope_allows(scope: list, capability_id: str) -> bool:
    """The binding-§2 scope grammar: exact capability id or trailing-`*` prefix."""
    return any(
        capability_id == s or (str(s).endswith("*") and capability_id.startswith(str(s)[:-1]))
        for s in scope
    )


def _attenuates(child: dict, parent: dict) -> dict[str, bool]:
    """Sub-delegation attenuation checks (§10, proposal 0009): a child may only
    NARROW scope and SHORTEN the window relative to its parent, and its link
    must join to the parent it names. Returns the per-check dict (all True =
    a valid attenuating link)."""
    child_scope = child.get("scope") or []
    parent_scope = parent.get("scope") or []
    parent_depth = int(parent.get("depth") or 0)
    return {
        # every child scope entry must be permitted by the parent's grammar
        "attenuation_scope": bool(child_scope)
        and all(scope_allows(parent_scope, s) for s in child_scope),
        # child window ⊆ parent window (lexical ISO compare, as temporal does)
        "attenuation_window": (
            str(parent.get("valid_from") or "") <= str(child.get("valid_from") or "")
            and str(child.get("valid_until") or "") <= str(parent.get("valid_until") or "")),
        # the parent delegated TO this sub-principal (the load-bearing binding)
        "delegate_join": parent.get("delegate_id") == (child.get("principal") or {}).get("host_id"),
        # the child commits to exactly this parent
        "parent_id_match": child.get("parent_id") == parent.get("mandate_id"),
        # depth is exact + capped (bounds recursion; blocks re-parenting-as-shallow)
        "depth": (isinstance(child.get("depth"), int)
                  and child["depth"] == parent_depth + 1
                  and child["depth"] <= _MAX_MANDATE_DEPTH),
    }


def build_mandate(principal_id: str, host_key: HostKey, *, delegate_id: str,
                  scope: list[str], valid_from: str, valid_until: str,
                  created_at: str, mandate_id: str | None = None,
                  anchors: list[dict] | None = None,
                  key_history: list[dict] | None = None,
                  max_invocations: int | None = None) -> dict:
    """A principal's signed grant of BOUNDED authority to a delegate (proposal
    0002, chp-v0.2.md §10): "delegate D may invoke capabilities in SCOPE on my
    behalf until VALID_UNTIL."

    The third member of the statement family (bundles §3, provenance §9): the
    signature covers the canonical header, the principal's attestation (with
    anchors) answers "whose authority?", and key_history rides omit-when-empty
    for rotation continuity. Replaces nothing — transport auth still gates the
    connection; a mandate narrows and attributes, it never bypasses."""
    if not host_key.can_sign:
        raise SigningUnavailable("principal key has no private component; cannot sign")
    from .types import new_id
    mandate: dict = {
        "kind": "mandate",
        "mandate_id": mandate_id or new_id("mnd"),
        "delegate_id": delegate_id,
        "scope": sorted(scope),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "created_at": created_at,
        "canonicalization": CANONICALIZATION,
    }
    if max_invocations is not None:
        # Signed-header use-count cap (§10, proposal 0026), omit-when-absent.
        mandate["max_invocations"] = max_invocations
    mandate["principal"] = {
        "host_id": principal_id,
        "public_key": host_key.public_key_b64,
        "host_identity": build_attestation(
            principal_id, host_key, valid_from=created_at, anchors=anchors),
    }
    if key_history:
        mandate["principal"]["key_history"] = key_history
    mandate["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": host_key.key_id,
        "signature": _sign(host_key._private, _canon(mandate_header(mandate))),
    }
    return mandate


def build_sub_mandate(parent: dict, host_key: HostKey, *, delegate_id: str,
                      scope: list[str], valid_from: str, valid_until: str,
                      created_at: str, mandate_id: str | None = None,
                      anchors: list[dict] | None = None) -> dict:
    """Attenuate a PARENT mandate into a sub-mandate (proposal 0009). The signer
    is the parent's delegate acting as a sub-principal — ``host_key`` MUST
    attest the parent's ``delegate_id`` (the delegate join). Refuses to sign a
    non-attenuating child (fail fast): a child may only NARROW scope and SHORTEN
    the window. The parent is embedded inline as transport (verified on its own
    signature); the child commits to it via the signed ``parent_id``."""
    if not host_key.can_sign:
        raise SigningUnavailable("sub-principal key has no private component; cannot sign")
    from .types import new_id
    principal_id = str(parent.get("delegate_id") or "")
    child: dict = {
        "kind": "mandate",
        "mandate_id": mandate_id or new_id("mnd"),
        "delegate_id": delegate_id,
        "scope": sorted(scope),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "created_at": created_at,
        "canonicalization": CANONICALIZATION,
        "depth": int(parent.get("depth") or 0) + 1,
        "parent_id": str(parent.get("mandate_id") or ""),
    }
    child["principal"] = {
        "host_id": principal_id,
        "public_key": host_key.public_key_b64,
        "host_identity": build_attestation(
            principal_id, host_key, valid_from=created_at, anchors=anchors),
    }
    att = _attenuates(child, parent)
    if not all(att.values()):
        raise ValueError("sub-mandate does not attenuate its parent: "
                         + ", ".join(k for k, v in att.items() if not v))
    child["parent"] = parent
    child["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": host_key.key_id,
        "signature": _sign(host_key._private, _canon(mandate_header(child))),
    }
    return child


def mandate_root_principal(mandate: dict) -> str | None:
    """Walk to the root of a mandate chain and return its principal host_id
    (the ultimate authority). For a single-hop mandate this is its own
    principal."""
    node = mandate
    while isinstance(node.get("parent"), dict):
        node = node["parent"]
    return (node.get("principal") or {}).get("host_id")


def verify_mandate(mandate: dict, *, at_time: str | None = None,
                   capability_id: str | None = None,
                   delegate_id: str | None = None,
                   expected_principal_key: str | None = None,
                   revocations: list[dict] | None = None) -> BundleVerification:
    """Offline-verify a mandate: structure, header signature, principal
    attestation (binding + temporal), DID anchor when present, the validity
    window at ``at_time``, delegate binding when ``delegate_id`` is supplied,
    and — when ``capability_id`` is supplied — that it is in scope. When
    ``revocations`` is supplied, the mandate additionally fails ``not_revoked``
    if any statement in the set revokes it under the issuer-only rule (§10):
    same ``mandate_id`` AND signed by the MANDATE's own principal key — a
    revocation signed by any other key revokes nothing."""
    checks: dict[str, bool] = {}
    checks["structure"] = (mandate.get("kind") == "mandate"
                           and bool(mandate.get("mandate_id"))
                           and bool(mandate.get("delegate_id"))
                           and isinstance(mandate.get("scope"), list)
                           and bool(mandate.get("valid_until")))
    principal = mandate.get("principal") or {}
    pub = str(principal.get("public_key") or "")
    sig = mandate.get("signature") or {}
    anchored_domain: str | None = None
    anchored_did: str | None = None

    if expected_principal_key is not None and sig.get("key_id") != expected_principal_key:
        return BundleVerification(
            False, "signed", checks,
            f"signed by unexpected key {sig.get('key_id')!r} "
            f"(expected {expected_principal_key!r})")

    checks["signature"] = (sig.get("algorithm") == SIGNATURE_ALGORITHM
                           and bool(pub)
                           and _verify_sig(pub, _canon(mandate_header(mandate)),
                                           str(sig.get("signature") or "")))

    att = principal.get("host_identity")
    if att:
        checks["principal_identity"] = verify_attestation(
            att, public_key=pub, expected_host_id=principal.get("host_id"),
            at_time=mandate.get("created_at"))
        anchored_domain = _domain_anchor(att)
        did_anchor = _did_anchor(att)
        if did_anchor is not None:
            checks["did_anchor"] = verify_did_anchor(
                did_anchor, pub, str(principal.get("host_id", "")))
            if checks["did_anchor"]:
                anchored_did = str(did_anchor.get("did"))
    else:
        checks["principal_identity"] = False  # authority must say WHOSE

    if at_time is not None:
        vf, vu = mandate.get("valid_from"), mandate.get("valid_until")
        checks["temporal"] = ((vf is None or vf <= at_time)
                              and (vu is None or at_time <= vu))
    if delegate_id is not None:
        checks["delegate"] = mandate.get("delegate_id") == delegate_id
    if capability_id is not None:
        checks["scope"] = scope_allows(mandate.get("scope") or [], capability_id)
    if revocations is not None:
        # Issuer-only rule: the revocation signature is verified against the
        # MANDATE's principal key, never the revocation's self-declared key —
        # otherwise anyone could revoke anyone by naming the mandate_id.
        checks["not_revoked"] = not any(
            r.get("kind") == "mandate-revocation"
            and r.get("mandate_id") == mandate.get("mandate_id")
            and str((r.get("principal") or {}).get("public_key") or "") == pub
            and _verify_sig(pub, _canon(mandate_revocation_header(r)),
                            str((r.get("signature") or {}).get("signature") or ""))
            for r in revocations)

    # Sub-delegation (§10, proposal 0009): when a parent is embedded, this link
    # must ATTENUATE it and the parent must itself verify — recursively to the
    # root. The parent recursion carries host time + the revocation set (so
    # every ancestor's temporal and not_revoked run against ITS own key), but
    # NOT the leaf's delegate/capability bindings (those are leaf-only). A
    # revoked ancestor fails its not_revoked → the whole leaf chain fails.
    parent = mandate.get("parent")
    if parent is not None:
        att_checks = _attenuates(mandate, parent)
        checks.update(att_checks)
        # Only recurse when depth is sane — an over-deep or malformed embedded
        # chain must fail WITHOUT recursing toward the interpreter's limit.
        if att_checks["depth"] and isinstance(parent, dict):
            checks["parent_valid"] = verify_mandate(
                parent, at_time=at_time, revocations=revocations).valid
        else:
            checks["parent_valid"] = False

    valid = all(checks.values())
    reason = None if valid else "mandate checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return BundleVerification(valid, "signed", checks, reason,
                              anchored_domain=anchored_domain,
                              anchored_did=anchored_did)


_MANDATE_REVOCATION_HEADER_FIELDS = ("kind", "mandate_id", "revoked_at",
                                     "reason", "canonicalization")


def mandate_revocation_header(statement: dict) -> dict:
    """The principal-signed header of a mandate revocation (§10)."""
    return {k: statement.get(k) for k in _MANDATE_REVOCATION_HEADER_FIELDS}


def build_mandate_revocation(mandate: dict, host_key: HostKey, *,
                             revoked_at: str, reason: str = "",
                             anchors: list[dict] | None = None) -> dict:
    """The principal's signed withdrawal of a mandate before its expiry
    (proposal 0007, chp-v0.2.md §10) — the fifth statement-family member.
    Only the ISSUER can revoke: enforcement binds a revocation to a mandate by
    ``mandate_id`` AND by principal-key match, so this refuses to sign with a
    key that is not the mandate's principal key (the statement would be
    inert anyway)."""
    if not host_key.can_sign:
        raise SigningUnavailable("principal key has no private component; cannot sign")
    principal = mandate.get("principal") or {}
    if principal.get("public_key") != host_key.public_key_b64:
        raise ValueError("revocation key does not match the mandate's principal key; "
                         "only the issuer can revoke")
    statement: dict = {
        "kind": "mandate-revocation",
        "mandate_id": str(mandate.get("mandate_id")),
        "revoked_at": revoked_at,
        "reason": reason,
        "canonicalization": CANONICALIZATION,
    }
    statement["principal"] = {
        "host_id": principal.get("host_id"),
        "public_key": host_key.public_key_b64,
        "host_identity": build_attestation(
            str(principal.get("host_id")), host_key, valid_from=revoked_at,
            anchors=anchors),
    }
    statement["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": host_key.key_id,
        "signature": _sign(host_key._private,
                           _canon(mandate_revocation_header(statement))),
    }
    return statement


def verify_mandate_revocation(statement: dict, *,
                              expected_principal_key: str | None = None) -> BundleVerification:
    """Offline-verify a mandate-revocation statement: structure, header
    signature, principal attestation (binding + temporal), DID anchor when
    present, and the principal key pin when supplied. This is
    SELF-consistency only — whether the statement actually revokes a given
    mandate is decided by ``verify_mandate(revocations=...)``, which verifies
    the signature against the MANDATE's principal key (issuer-only rule)."""
    checks: dict[str, bool] = {}
    checks["structure"] = (statement.get("kind") == "mandate-revocation"
                           and bool(statement.get("mandate_id"))
                           and bool(statement.get("revoked_at")))
    principal = statement.get("principal") or {}
    pub = str(principal.get("public_key") or "")
    sig = statement.get("signature") or {}
    anchored_domain: str | None = None
    anchored_did: str | None = None

    if expected_principal_key is not None and sig.get("key_id") != expected_principal_key:
        return BundleVerification(
            False, "signed", checks,
            f"signed by unexpected key {sig.get('key_id')!r} "
            f"(expected {expected_principal_key!r})")

    checks["signature"] = (sig.get("algorithm") == SIGNATURE_ALGORITHM
                           and bool(pub)
                           and _verify_sig(pub, _canon(mandate_revocation_header(statement)),
                                           str(sig.get("signature") or "")))

    att = principal.get("host_identity")
    if att:
        checks["principal_identity"] = verify_attestation(
            att, public_key=pub, expected_host_id=principal.get("host_id"),
            at_time=statement.get("revoked_at"))
        anchored_domain = _domain_anchor(att)
        did_anchor = _did_anchor(att)
        if did_anchor is not None:
            checks["did_anchor"] = verify_did_anchor(
                did_anchor, pub, str(principal.get("host_id", "")))
            if checks["did_anchor"]:
                anchored_did = str(did_anchor.get("did"))
    else:
        checks["principal_identity"] = False  # a revocation must say WHOSE authority

    valid = all(checks.values())
    reason = None if valid else "mandate-revocation checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    return BundleVerification(valid, "signed", checks, reason,
                              anchored_domain=anchored_domain,
                              anchored_did=anchored_did)


_TASK_HEADER_FIELDS = ("kind", "correlation_id", "protocol_version", "created_at",
                       "canonicalization", "task_root_hash")


def task_bundle_header(task: dict) -> dict:
    """The aggregator-signed header. `task_root_hash` commits to every member
    root, and `member_order` pins arrangement, so signing the header signs the
    assembly."""
    return {k: task.get(k) for k in _TASK_HEADER_FIELDS}


def sign_task_bundle(task: dict, host_key: HostKey, *, aggregator_host_id: str,
                     valid_until: str | None = None,
                     anchors: list[dict] | None = None) -> dict:
    """Attach the AGGREGATOR signature (chp-v0.2.md §8, `aggregated`): the
    assembling gateway signs the canonical task-bundle header with its own key
    and attaches its own attestation. Member signatures keep proving each
    part's origin; this proves WHO assembled the set and that the set hasn't
    been re-assembled since. Omit-when-empty: an unsigned task bundle stays
    byte-identical to the pre-aggregator format."""
    if not host_key.can_sign:
        raise SigningUnavailable("aggregator key has no private component; cannot sign")
    signed = dict(task)
    signed["aggregator"] = {
        "host_id": aggregator_host_id,
        "public_key": host_key.public_key_b64,
        "host_identity": build_attestation(
            aggregator_host_id, host_key,
            valid_from=str(task.get("created_at", "")), valid_until=valid_until,
            anchors=anchors,
        ),
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": host_key.key_id,
            "signature": _sign(host_key._private, _canon(task_bundle_header(task))),
        },
    }
    return signed


def build_task_bundle(correlation_id: str, bundles: list[dict], *,
                      created_at: str) -> dict:
    """Aggregate one correlation's per-host SIGNED bundles into a task bundle.

    Members are byte-untouched and sorted canonically by (host_id, root_hash)
    so assembly order is irrelevant — two gateways assembling the same members
    produce identical bytes. `assurance` = the MINIMUM member tier (degradation
    surfaced, never hidden). Aggregator signature is a separate, optional layer
    (`sign_task_bundle`) — omit-when-empty keeps unsigned bundles byte-stable."""
    members = sorted(bundles, key=_member_sort_key)
    tiers = {b.get("assurance", "none") for b in members}
    assurance = ("none" if "none" in tiers
                 else "hash-chain" if "hash-chain" in tiers
                 else "signed")
    return {
        "kind": "task-bundle",
        "correlation_id": correlation_id,
        "created_at": created_at,
        "protocol_version": "0.2",
        "canonicalization": CANONICALIZATION,
        "assurance": assurance,
        "bundles": members,
        "task_root_hash": compute_task_root_hash(members),
    }


@dataclass
class TaskBundleVerification:
    valid: bool
    assurance: str
    checks: dict[str, bool]
    correlation_id: str
    task_root_hash: str | None
    # Per member: who contributed what, under which trust root.
    hosts: list[dict] = field(default_factory=list)
    reason: str | None = None
    # Who ASSEMBLED the set (None = unsigned assembly — surfaced, not hidden).
    aggregator: dict | None = None


def verify_task_bundle(task: dict, *, resolve: bool = False) -> TaskBundleVerification:
    """Verify a task's evidence spanning N hosts as a unit (chp-v0.2.md §8).

    Proves: integrity of every included part (full per-member verify_bundle,
    incl. signatures + attestations + anchors), cryptographic identity of every
    contributor, and CAUSAL CLOSURE — no included event references work that is
    missing. It does NOT prove absence of evidence: a causal *ancestor* cannot
    be silently dropped (its children's causation_ids would dangle), but a
    *leaf* contributor can be omitted undetectably. Absence-proofs are out of
    scope at this tier."""
    from .ordering import order_events  # noqa: PLC0415

    checks: dict[str, bool] = {}
    correlation_id = str(task.get("correlation_id") or "")
    members = task.get("bundles") or []

    checks["structure"] = (task.get("kind") == "task-bundle"
                           and bool(correlation_id) and bool(members))
    checks["member_order"] = [_member_sort_key(b) for b in members] == sorted(
        _member_sort_key(b) for b in members)
    checks["task_root_hash"] = task.get("task_root_hash") == compute_task_root_hash(members)

    hosts: list[dict] = []
    members_valid = True
    all_events: list[dict] = []
    for b in members:
        v = verify_bundle(b, resolve=resolve)
        members_valid = members_valid and v.valid
        events = b.get("events") or []
        all_events.extend(events)
        hosts.append({
            "host_id": b.get("host_id"),
            "key_id": (b.get("signature") or {}).get("key_id"),
            "assurance": v.assurance,
            "anchored_domain": v.anchored_domain,
            "anchored_did": v.anchored_did,
            "valid": v.valid,
            "event_count": len(events),
        })
    checks["members_valid"] = members_valid

    checks["correlation"] = all(
        (e.get("correlation") or {}).get("correlation_id") == correlation_id
        for e in all_events)
    host_ids = [b.get("host_id") for b in members]
    checks["distinct_hosts"] = len(host_ids) == len(set(host_ids))

    # Causal closure: every referenced causation resolves inside the union.
    invocation_ids = {e.get("invocation_id") for e in all_events}
    dangling = {
        str(c) for e in all_events
        if (c := (e.get("correlation") or {}).get("causation_id"))
        and c not in invocation_ids
    }
    checks["causal_closure"] = not dangling

    # Acyclicity: chp-causal-order-v1 emits everything without the cycle
    # fallback iff the edge set is a DAG. Recompute edges cheaply by checking
    # the topological property: order the union, then assert every event
    # appears after its cause's first event.
    ordered = order_events(all_events)
    first_pos: dict[str, int] = {}
    for i, e in enumerate(ordered):
        inv = str(e.get("invocation_id") or "")
        if inv and inv not in first_pos:
            first_pos[inv] = i
    acyclic = True
    for i, e in enumerate(ordered):
        c = (e.get("correlation") or {}).get("causation_id")
        if c and str(c) in first_pos and first_pos[str(c)] > i:
            acyclic = False
            break
    checks["causal_acyclic"] = acyclic

    # Participation manifest (§8): when an orchestrator declared the member set
    # (task_participants_declared — riding ITS signed chain), every declared
    # host must have contributed a bundle. Absent manifest → no check (the
    # completeness limit stands, visibly). Declarations union across events.
    declared_participants: set[str] = set()
    for e in all_events:
        if e.get("event_type") == "task_participants_declared":
            declared_participants.update(
                str(p) for p in (e.get("payload") or {}).get("participants") or [])
    missing_participants: set[str] = set()
    if declared_participants:
        member_ids = {str(b.get("host_id") or "") for b in members}
        missing_participants = declared_participants - member_ids
        checks["participation"] = not missing_participants

    # Aggregator signature (§8 `aggregated` layer): verified whenever present;
    # absent = unsigned assembly, surfaced via aggregator=None (never a failure).
    aggregator_info: dict | None = None
    agg = task.get("aggregator")
    if agg is not None:
        sig = agg.get("signature") or {}
        pub = str(agg.get("public_key") or "")
        agg_ok = (sig.get("algorithm") == SIGNATURE_ALGORITHM
                  and bool(pub)
                  and _verify_sig(pub, _canon(task_bundle_header(task)),
                                  str(sig.get("signature") or "")))
        att = agg.get("host_identity")
        if agg_ok and att:
            agg_ok = verify_attestation(
                att, public_key=pub, expected_host_id=agg.get("host_id"),
                at_time=task.get("created_at"))
        elif not att:
            agg_ok = False  # a signed assembly must say who assembled it
        checks["aggregator"] = agg_ok
        aggregator_info = {
            "host_id": agg.get("host_id"),
            "key_id": sig.get("key_id"),
            "anchored_domain": _domain_anchor(att) if att else None,
            "anchored_did": ((_did_anchor(att) or {}).get("did") if att else None),
            "valid": agg_ok,
        }

    valid = all(checks.values())
    reason = None if valid else "task-bundle checks failed: " + ", ".join(
        k for k, v in checks.items() if not v)
    if not checks["causal_closure"] and dangling:
        reason = (reason or "") + f" (dangling causation_ids: {sorted(dangling)[:3]})"
    if missing_participants:
        reason = (reason or "") + f" (declared but missing: {sorted(missing_participants)[:3]})"
    return TaskBundleVerification(
        valid=valid, assurance=str(task.get("assurance", "none")), checks=checks,
        correlation_id=correlation_id, task_root_hash=task.get("task_root_hash"),
        hosts=hosts, reason=reason, aggregator=aggregator_info)
