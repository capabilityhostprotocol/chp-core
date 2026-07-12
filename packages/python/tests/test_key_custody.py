"""Encrypted-at-rest host keys (chp-v0.2.md §3, proposal 0017): opt-in, wire-
identical, auto-detected on load."""

from __future__ import annotations

import base64

import pytest

from chp_core import signing

pytestmark = pytest.mark.skipif(
    not signing.signing_available(), reason="signing backend (cryptography) not installed"
)

PW = "correct horse battery staple"


def _echo_events():
    # A minimal two-event chain to sign a bundle over.
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
    import asyncio

    host = LocalCapabilityHost("kc-host", store=SQLiteEvidenceStore(":memory:"))

    async def echo(_c, p):
        return {"echo": p}

    host.register(CapabilityDescriptor(id="kc.echo", version="1.0.0", description=""), echo)
    asyncio.run(host.ainvoke("kc.echo", {"v": 1}, correlation={"correlation_id": "kc"}))
    return host.store.export_correlation("kc")


# ── format ───────────────────────────────────────────────────────────────────

def test_default_keygen_is_unencrypted_raw(tmp_path):
    signing.generate_keypair(tmp_path)
    raw = (tmp_path / signing._PRIVATE_NAME).read_bytes()
    # legacy format: base64 of a 32-byte seed, no PEM header — byte-identical to
    # every existing key.
    assert not raw.lstrip().startswith(b"-----BEGIN")
    assert len(base64.b64decode(raw)) == 32
    assert not signing._private_is_encrypted(tmp_path)


def test_encrypted_keygen_writes_pkcs8_pem(tmp_path):
    signing.generate_keypair(tmp_path, passphrase=PW)
    raw = (tmp_path / signing._PRIVATE_NAME).read_bytes()
    assert raw.lstrip().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert signing._private_is_encrypted(tmp_path)
    # the passphrase must not appear anywhere in the ciphertext
    assert PW.encode() not in raw


# ── load / unlock ────────────────────────────────────────────────────────────

def test_encrypted_key_loads_with_passphrase(tmp_path):
    gen = signing.generate_keypair(tmp_path, passphrase=PW)
    loaded = signing.load_host_key(tmp_path, passphrase=PW)
    assert loaded is not None and loaded.can_sign
    assert loaded.key_id == gen.key_id and loaded.public_key_b64 == gen.public_key_b64


def test_encrypted_key_loads_from_env(tmp_path, monkeypatch):
    signing.generate_keypair(tmp_path, passphrase=PW)
    monkeypatch.setenv("CHP_KEY_PASSPHRASE", PW)
    assert signing.load_host_key(tmp_path).can_sign


def test_encrypted_key_without_passphrase_raises(tmp_path, monkeypatch):
    signing.generate_keypair(tmp_path, passphrase=PW)
    monkeypatch.delenv("CHP_KEY_PASSPHRASE", raising=False)
    with pytest.raises(ValueError, match="requires a passphrase"):
        signing.load_host_key(tmp_path)


def test_wrong_passphrase_raises(tmp_path):
    signing.generate_keypair(tmp_path, passphrase=PW)
    with pytest.raises(Exception):  # cryptography raises on bad password
        signing.load_host_key(tmp_path, passphrase="wrong")


def test_unencrypted_key_never_prompts_or_needs_passphrase(tmp_path):
    signing.generate_keypair(tmp_path)                 # no passphrase
    assert signing.load_host_key(tmp_path).can_sign    # loads with no passphrase, no prompt


# ── the whole point: encryption never reaches the wire ───────────────────────

def test_encrypted_and_unencrypted_keys_sign_byte_identically(tmp_path):
    """Same seed → same signatures regardless of at-rest encryption. Generate an
    unencrypted key, then re-serialize the SAME private key encrypted, and show a
    bundle over the same events + created_at is byte-identical."""
    events = _echo_events()

    plain = signing.generate_keypair(tmp_path / "plain")
    # Encrypt the SAME key material into a second dir, then load it back.
    enc_dir = tmp_path / "enc"
    enc_dir.mkdir()
    import os
    from cryptography.hazmat.primitives import serialization
    pem = plain._private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(PW.encode()),
    )
    fd = os.open(str(enc_dir / signing._PRIVATE_NAME), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    (enc_dir / signing._PUBLIC_NAME).write_bytes(base64.b64encode(
        plain._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)))
    enc = signing.load_host_key(enc_dir, passphrase=PW)

    b_plain = signing.sign_bundle(signing.build_bundle("kc-host", events, created_at="2026-01-01T00:00:00Z"), plain)
    b_enc = signing.sign_bundle(signing.build_bundle("kc-host", events, created_at="2026-01-01T00:00:00Z"), enc)
    assert b_plain["signature"]["signature"] == b_enc["signature"]["signature"]
    assert b_plain["root_hash"] == b_enc["root_hash"]
    assert signing.verify_bundle(b_enc).valid


def test_encrypted_key_bundle_verifies(tmp_path):
    events = _echo_events()
    key = signing.generate_keypair(tmp_path, passphrase=PW)
    bundle = signing.sign_bundle(signing.build_bundle("kc-host", events, created_at="2026-01-01T00:00:00Z"), key)
    v = signing.verify_bundle(bundle)
    assert v.valid and v.checks["signature"] and v.checks["host_identity"]


def test_rotate_preserves_encryption(tmp_path, monkeypatch):
    signing.generate_keypair(tmp_path, passphrase=PW)
    monkeypatch.setenv("CHP_KEY_PASSPHRASE", PW)
    new, statement = signing.rotate_keypair(tmp_path)
    assert signing._private_is_encrypted(tmp_path)          # new key still encrypted
    assert statement["new_key_id"] == new.key_id
    assert signing.load_host_key(tmp_path, passphrase=PW).key_id == new.key_id
