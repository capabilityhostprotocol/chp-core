"""Witness quorum + external anchoring (chp-v0.2.md §12, proposal 0013)."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from chp_core import signing, sshsig
from chp_core.witnessing import evaluate_witness_quorum

HOST = "witnessed-host"
SEQ = 7
HEAD = "a" * 64
TS = "2026-07-11T00:00:00Z"


def _witness_key(tmp_path, n: int) -> signing.HostKey:
    return signing.generate_keypair(tmp_path / f"w{n}")


def _witness(tmp_path, n: int, *, host_id=HOST, sequence=SEQ, store_head=HEAD):
    key = _witness_key(tmp_path, n)
    return signing.build_chain_witness(host_id, sequence, store_head, key,
                                       witness_id=f"witness-{n}", witnessed_at=TS)


# ── quorum ───────────────────────────────────────────────────────────────────

def test_k_distinct_witnesses_meets_quorum(tmp_path):
    statements = [_witness(tmp_path, n) for n in range(3)]
    q = evaluate_witness_quorum(statements, host_id=HOST, sequence=SEQ, store_head=HEAD, k=3)
    assert q["verdict"] == "quorum_met" and q["distinct"] == 3
    # k-1 available → short
    short = evaluate_witness_quorum(statements[:2], host_id=HOST, sequence=SEQ,
                                    store_head=HEAD, k=3)
    assert short["verdict"] == "quorum_short" and short["distinct"] == 2


def test_duplicate_witness_does_not_inflate(tmp_path):
    key = _witness_key(tmp_path, 0)
    # same witness key submits twice — counts once (dedupe by key_id)
    s1 = signing.build_chain_witness(HOST, SEQ, HEAD, key, witness_id="w", witnessed_at=TS)
    s2 = signing.build_chain_witness(HOST, SEQ, HEAD, key, witness_id="w", witnessed_at="2026-07-11T01:00:00Z")
    q = evaluate_witness_quorum([s1, s2], host_id=HOST, sequence=SEQ, store_head=HEAD, k=2)
    assert q["distinct"] == 1 and q["verdict"] == "quorum_short"


def test_wrong_head_statement_excluded(tmp_path):
    good = [_witness(tmp_path, n) for n in range(2)]
    other = _witness(tmp_path, 9, store_head="b" * 64)  # valid, but different head
    q = evaluate_witness_quorum(good + [other], host_id=HOST, sequence=SEQ, store_head=HEAD, k=3)
    assert q["distinct"] == 2 and q["verdict"] == "quorum_short"  # `other` not counted


def test_witness_set_restriction(tmp_path):
    statements = [_witness(tmp_path, n) for n in range(3)]
    allowed = [s["signature"]["key_id"] for s in statements[:2]]  # only 2 trusted
    q = evaluate_witness_quorum(statements, host_id=HOST, sequence=SEQ, store_head=HEAD,
                                k=3, witness_set=allowed)
    assert q["distinct"] == 2 and q["verdict"] == "quorum_short"


def test_forged_witness_statement_excluded(tmp_path):
    good = [_witness(tmp_path, n) for n in range(2)]
    forged = _witness(tmp_path, 5)
    forged["store_head"] = HEAD  # keep head, but break the signed bytes elsewhere
    forged["witnessed_at"] = "2099-01-01T00:00:00Z"  # not what was signed → signature fails
    q = evaluate_witness_quorum(good + [forged], host_id=HOST, sequence=SEQ, store_head=HEAD, k=3)
    assert q["distinct"] == 2  # forged statement fails verify_chain_witness


# ── external anchoring ───────────────────────────────────────────────────────

def _sshsig_countersign(message: bytes, seed: bytes) -> tuple[str, str]:
    """Produce an external SSHSIG over `message` (namespace chp-store-head-anchor)
    from a fixed ed25519 seed — the out-of-mesh notary. Returns (did, armored)."""
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    did = sshsig.raw_to_did_key(raw_pub)
    with tempfile.TemporaryDirectory() as d:
        kf = Path(d) / "id"
        kf.write_bytes(priv.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.OpenSSH,
                                          serialization.NoEncryption()))
        os.chmod(kf, 0o600)
        mf = Path(d) / "msg"
        mf.write_bytes(message)
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(kf),
                        "-n", sshsig.STORE_HEAD_ANCHOR_NAMESPACE, str(mf)],
                       check=True, capture_output=True)
        return did, (Path(d) / "msg.sig").read_text()


def test_store_head_anchor_verifies_offline():
    msg = signing.store_head_anchor_message(HOST, SEQ, HEAD, TS)
    did, armored = _sshsig_countersign(msg, bytes(range(100, 132)))
    anchor = signing.build_store_head_anchor(HOST, SEQ, HEAD, anchored_at=TS,
                                             did=did, countersignature=armored)
    v = signing.verify_store_head_anchor(anchor)
    assert v.valid and v.checks["anchor"] and v.anchored_did == did


def test_cli_witness_quorum(tmp_path):
    """`chp witness quorum` exits 0 on met, 1 on short."""
    import argparse
    import json

    from chp_core.cli._core import cmd_witness_quorum

    statements = [_witness(tmp_path, n) for n in range(3)]
    f = tmp_path / "stmts.json"
    f.write_text(json.dumps(statements))
    met = argparse.Namespace(statements=str(f), host_id=HOST, sequence=SEQ,
                             store_head=HEAD, k=3, witness_set=None)
    assert cmd_witness_quorum(met) == 0
    short = argparse.Namespace(statements=str(f), host_id=HOST, sequence=SEQ,
                               store_head=HEAD, k=4, witness_set=None)
    assert cmd_witness_quorum(short) == 1


def test_tampered_store_head_anchor_fails():
    msg = signing.store_head_anchor_message(HOST, SEQ, HEAD, TS)
    did, armored = _sshsig_countersign(msg, bytes(range(100, 132)))
    anchor = signing.build_store_head_anchor(HOST, SEQ, HEAD, anchored_at=TS,
                                             did=did, countersignature=armored)
    # swap the store_head → the countersigned message no longer matches
    anchor["store_head"] = "c" * 64
    assert not signing.verify_store_head_anchor(anchor).valid
