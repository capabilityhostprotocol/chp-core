"""SSHSIG verification + did:key codec — the `did` anchor primitives (§3.1).

The Radicle identity key is a standard OpenSSH ed25519 key; its DID is
``did:key:z6Mk…`` — multibase(base58btc) of multicodec(0xed01) + the raw
32-byte public key, and byte-identical to ``"did:key:" + NID``. A host anchors
its CHP signing key to that identity by having the DID key **countersign** it
via ``ssh-keygen -Y sign`` (SSHSIG format). Verification is fully offline: no
CA, no DNS, no shell-out — just the SSHSIG envelope parse + ed25519.

SSHSIG wire format (OpenSSH PROTOCOL.sshsig):
  armored blob = MAGIC "SSHSIG" || uint32 version || string publickey
                 || string namespace || string reserved || string hash_alg
                 || string signature
  signed payload = MAGIC "SSHSIG" || string namespace || string reserved
                 || string hash_alg || string H(message)
where ``string`` is uint32-length-prefixed and H is the named hash (sha512 by
default for ssh-keygen). The publickey/signature strings are themselves SSH
wire structures: string "ssh-ed25519" || string raw-bytes.
"""

from __future__ import annotations

import base64
import hashlib
import struct

SSHSIG_MAGIC = b"SSHSIG"
DID_ANCHOR_NAMESPACE = "chp-host-anchor"
STORE_HEAD_ANCHOR_NAMESPACE = "chp-store-head-anchor"  # §12 External anchoring (0013)
_ED25519_MULTICODEC = b"\xed\x01"
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class SshsigError(ValueError):
    """Malformed SSHSIG blob / unsupported algorithm / bad did:key."""


# ── base58btc (the ~15 lines the did:key codec needs) ────────────────────────

def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            raise SshsigError(f"invalid base58 character {ch!r}")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip(_B58_ALPHABET[0]))
    return b"\x00" * pad + raw


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return _B58_ALPHABET[0] * pad + out


def did_key_to_raw(did: str) -> bytes:
    """``did:key:z6Mk…`` → the raw 32-byte ed25519 public key."""
    if not did.startswith("did:key:z"):
        raise SshsigError(f"not a did:key multibase(base58btc) DID: {did!r}")
    decoded = _b58decode(did[len("did:key:z"):])
    if not decoded.startswith(_ED25519_MULTICODEC) or len(decoded) != 34:
        raise SshsigError("did:key is not an ed25519 multicodec key")
    return decoded[2:]


def raw_to_did_key(raw_pubkey: bytes) -> str:
    """Raw 32-byte ed25519 public key → ``did:key:z6Mk…``."""
    if len(raw_pubkey) != 32:
        raise SshsigError("ed25519 public key must be 32 bytes")
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + raw_pubkey)


# ── SSHSIG parse + verify ────────────────────────────────────────────────────

def _read_string(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 4 > len(buf):
        raise SshsigError("truncated SSHSIG blob")
    (n,) = struct.unpack(">I", buf[off:off + 4])
    off += 4
    if off + n > len(buf):
        raise SshsigError("truncated SSHSIG string")
    return buf[off:off + n], off + n


def _unarmor(armored: str) -> bytes:
    body = armored.strip()
    if not (body.startswith("-----BEGIN SSH SIGNATURE-----")
            and body.endswith("-----END SSH SIGNATURE-----")):
        raise SshsigError("not an armored SSH signature")
    b64 = "".join(body.splitlines()[1:-1])
    return base64.b64decode(b64)


def parse_sshsig(armored: str) -> dict:
    """Parse an armored SSHSIG into {raw_pubkey, namespace, hash_alg, raw_sig}."""
    blob = _unarmor(armored)
    if not blob.startswith(SSHSIG_MAGIC):
        raise SshsigError("missing SSHSIG magic")
    off = len(SSHSIG_MAGIC)
    (version,) = struct.unpack(">I", blob[off:off + 4])
    off += 4
    if version != 1:
        raise SshsigError(f"unsupported SSHSIG version {version}")
    pub_blob, off = _read_string(blob, off)
    namespace, off = _read_string(blob, off)
    _reserved, off = _read_string(blob, off)
    hash_alg, off = _read_string(blob, off)
    sig_blob, off = _read_string(blob, off)

    ktype, koff = _read_string(pub_blob, 0)
    if ktype != b"ssh-ed25519":
        raise SshsigError(f"unsupported key type {ktype!r} (only ssh-ed25519)")
    raw_pubkey, _ = _read_string(pub_blob, koff)

    stype, soff = _read_string(sig_blob, 0)
    if stype != b"ssh-ed25519":
        raise SshsigError(f"unsupported signature type {stype!r}")
    raw_sig, _ = _read_string(sig_blob, soff)

    return {
        "raw_pubkey": raw_pubkey,
        "namespace": namespace.decode(),
        "hash_alg": hash_alg.decode(),
        "raw_sig": raw_sig,
    }


def _wire_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def verify_sshsig(armored: str, message: bytes, *,
                  namespace: str = DID_ANCHOR_NAMESPACE,
                  expected_raw_pubkey: bytes | None = None) -> bool:
    """Verify an SSHSIG over *message*: envelope parse, namespace match,
    optional signer pin, then ed25519 over the SSHSIG signed payload."""
    try:
        parsed = parse_sshsig(armored)
    except SshsigError:
        return False
    if parsed["namespace"] != namespace:
        return False
    if expected_raw_pubkey is not None and parsed["raw_pubkey"] != expected_raw_pubkey:
        return False
    if parsed["hash_alg"] == "sha512":
        digest = hashlib.sha512(message).digest()
    elif parsed["hash_alg"] == "sha256":
        digest = hashlib.sha256(message).digest()
    else:
        return False
    payload = (SSHSIG_MAGIC
               + _wire_string(parsed["namespace"].encode())
               + _wire_string(b"")
               + _wire_string(parsed["hash_alg"].encode())
               + _wire_string(digest))
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: PLC0415
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    except ImportError:
        return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(parsed["raw_pubkey"]).verify(
            parsed["raw_sig"], payload)
        return True
    except InvalidSignature:
        return False
