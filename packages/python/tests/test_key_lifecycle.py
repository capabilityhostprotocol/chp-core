"""Tests for key lifecycle (spec §3.2): archival, chained rotation, identity
evidence (the host's own chain as its key-transparency log), verifier
continuity, and revocation."""

from __future__ import annotations

import json
from pathlib import Path

from chp_core import signing


def test_overwrite_archives_instead_of_destroying(tmp_path):
    old = signing.generate_keypair(tmp_path)
    new = signing.generate_keypair(tmp_path, overwrite=True)
    assert new.key_id != old.key_id
    archived = tmp_path / "archive" / old.key_id / "host_ed25519.pub"
    assert archived.exists(), "old public key must be archived, not destroyed"
    assert (tmp_path / "archive" / old.key_id / "host_ed25519").exists()


def test_rotate_with_continuity(tmp_path):
    old = signing.generate_keypair(tmp_path)
    new, stmt = signing.rotate_keypair(tmp_path)
    assert stmt["old_key_id"] == old.key_id and stmt["new_key_id"] == new.key_id
    assert signing.verify_continuity(stmt)
    # tampered statement fails
    assert not signing.verify_continuity({**stmt, "new_key_id": "deadbeef"})
    # history persisted; chained double rotation appends
    assert [s["new_key_id"] for s in signing.load_key_history(tmp_path)] == [new.key_id]
    newer, stmt2 = signing.rotate_keypair(tmp_path)
    history = signing.load_key_history(tmp_path)
    assert [s["new_key_id"] for s in history] == [new.key_id, newer.key_id]
    assert stmt2["old_key_id"] == new.key_id  # chain links


def test_mesh_pin_follows_continuity_chain(tmp_path, monkeypatch):
    import chp_host.mesh as mesh

    monkeypatch.setattr(mesh, "mesh_path", lambda: tmp_path / "mesh.json")
    (tmp_path / "mesh.json").write_text(json.dumps(
        {"agent_remotes": [{"url": "http://peer:1", "api_key_env": "X"}]}))

    k1 = signing.generate_keypair(tmp_path / "keys")
    assert mesh.pin_or_check_key("http://peer:1", k1.key_id, k1.public_key_b64)[0] == "pinned"

    # two rotations while we weren't looking
    k2, _ = signing.rotate_keypair(tmp_path / "keys")
    k3, _ = signing.rotate_keypair(tmp_path / "keys")
    history = signing.load_key_history(tmp_path / "keys")

    # presenting k3 with the published history → rotation accepted, re-pinned
    status, detail = mesh.pin_or_check_key("http://peer:1", k3.key_id, k3.public_key_b64,
                                           key_history=history)
    assert status == "rotated" and detail == k3.key_id
    assert mesh.pin_or_check_key("http://peer:1", k3.key_id, k3.public_key_b64)[0] == "ok"

    # a key with NO valid chain from the pin → hard mismatch
    stranger = signing.generate_keypair(tmp_path / "other")
    status, _ = mesh.pin_or_check_key("http://peer:1", stranger.key_id,
                                      stranger.public_key_b64, key_history=history)
    assert status == "mismatch"


def test_mesh_rejects_self_serving_history(tmp_path, monkeypatch):
    # An attacker publishes a "history" rooted at THEIR key, not the pinned one:
    # the chain walk requires each hop signed by the key we already trust.
    import chp_host.mesh as mesh

    monkeypatch.setattr(mesh, "mesh_path", lambda: tmp_path / "mesh.json")
    (tmp_path / "mesh.json").write_text(json.dumps(
        {"agent_remotes": [{"url": "http://peer:1", "api_key_env": "X"}]}))

    pinned = signing.generate_keypair(tmp_path / "real")
    mesh.pin_or_check_key("http://peer:1", pinned.key_id, pinned.public_key_b64)

    attacker_old = signing.generate_keypair(tmp_path / "atk")
    attacker_new, forged_stmt = signing.rotate_keypair(tmp_path / "atk")
    # forged_stmt verifies (it IS validly signed) — but by the attacker's key,
    # not the pinned one, so the walk never starts.
    assert signing.verify_continuity(forged_stmt)
    status, _ = mesh.pin_or_check_key("http://peer:1", attacker_new.key_id,
                                      attacker_new.public_key_b64,
                                      key_history=[forged_stmt])
    assert status == "mismatch"


def test_revocation_statement_and_resolve_rejection(tmp_path):
    key = signing.generate_keypair(tmp_path)
    stmt = signing.revoke_key(tmp_path, reason="compromised")
    assert signing.verify_revocation(stmt)
    assert not signing.verify_revocation({**stmt, "revoked_key_id": "deadbeef"})
    assert signing.load_revocations(tmp_path)[0]["reason"] == "compromised"

    # A bundle signed by the revoked key: resolve=True sees the revocation.
    import asyncio
    from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore

    store = SQLiteEvidenceStore(str(tmp_path / "ev.sqlite"))
    host = LocalCapabilityHost("rvk-host", store=store)

    async def _h(_c, _p):
        return {"ok": True}

    host.register(CapabilityDescriptor(id="x.cap", version="1.0.0", description=""), _h)
    asyncio.run(host.ainvoke("x.cap", {}, correlation={"correlation_id": "c"}))
    bundle = signing.sign_bundle(
        signing.build_bundle("rvk-host", store.export_correlation("c"),
                             created_at="2026-07-05T00:00:00Z"),
        key, anchors=[{"type": "domain", "domain": "rvk.example"}])

    import chp_core.signing as S
    orig = S.resolve_host_identity
    try:
        # the domain's doc now serves the (new key +) revocation of the old one
        S.resolve_host_identity = lambda d, **kw: {
            "public_key": key.public_key_b64,  # doc still lists it → anchor ok
            "revoked_keys": signing.load_revocations(tmp_path),
        }
        v = S.verify_bundle(bundle, resolve=True)
        assert v.checks["anchor"] is True
        assert v.checks["not_revoked"] is False
        assert not v.valid
    finally:
        S.resolve_host_identity = orig


def test_identity_evidence_chain_is_the_transparency_log(tmp_path):
    # key_rotated events ride the host's own hash chain — exportable + verifiable.
    from chp_core.cli._core import _record_identity_event
    from chp_core.store import SQLiteEvidenceStore
    from chp_core.types import IDENTITY_EVIDENCE_TYPES

    store_path = str(tmp_path / "ev.sqlite")
    key = signing.generate_keypair(tmp_path / "keys")
    _new, stmt = signing.rotate_keypair(tmp_path / "keys")
    evt = _record_identity_event(store_path, "log-host", "key_rotated", {
        "old_key_id": stmt["old_key_id"], "new_key_id": stmt["new_key_id"],
        "rotated_at": stmt["rotated_at"],
    })
    assert evt is not None
    store = SQLiteEvidenceStore(store_path)
    events = store.export_correlation("host-identity-log-host")
    store.close()
    assert [e["event_type"] for e in events] == ["key_rotated"]
    assert events[0]["event_type"] in IDENTITY_EVIDENCE_TYPES
    # the identity correlation exports + verifies like any bundle
    new_key = signing.load_host_key(tmp_path / "keys")
    bundle = signing.sign_bundle(
        signing.build_bundle("log-host", events, created_at="2026-07-05T00:00:00Z"), new_key)
    assert signing.verify_bundle(bundle).valid
