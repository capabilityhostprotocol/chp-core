#!/usr/bin/env python3
"""Regenerate ALL spec/test-vectors/ deterministically from fixed seeds.

This is the tool the alignment-guard hints promise ("regenerate
spec/test-vectors/"). Every vector derives from fixed inputs — the CHP key seed
bytes(0..31), the fixture SSH key seed bytes(32..63), fixed ids/timestamps — and
ed25519 signatures are deterministic (RFC 8032), so a re-run MUST be
byte-identical to the committed files. CI-checkable:

    python scripts/gen-test-vectors.py && git diff --exit-code spec/test-vectors/

If canonicalization legitimately changes (a protocol change via the proposal
process, spec/proposals/), re-run this, commit the new bytes, and record it in
spec/CHANGELOG.md. The did-anchored vector shells out to `ssh-keygen -Y sign`
(OpenSSH ships on macOS/Linux runners).
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VEC = REPO / "spec" / "test-vectors"
sys.path.insert(0, str(REPO / "packages" / "python"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from chp_core import signing, sshsig  # noqa: E402
from chp_core.store import _compute_event_hash  # noqa: E402

CHP_SEED = bytes(range(32))
SSH_SEED = bytes(range(32, 64))
HOST = "vector-host"
TS = "2026-01-01T00:00:00Z"


def _write(path: Path, obj: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    print(f"  wrote {path.relative_to(REPO)}")


def _chp_key() -> signing.HostKey:
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(CHP_SEED)
    pub = base64.b64encode(priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).decode()
    return signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub)),
                           public_key_b64=pub, _private=priv)


def _echo_events() -> list[dict]:
    """The canonical two-event echo chain (started → completed), unhashed."""
    common = {"capability_id": "demo.cap", "host_id": HOST, "timestamp": TS,
              "payload": {"note": "café"},
              "correlation": {"correlation_id": "corr_test", "causation_id": None}}
    return [
        {**common, "event_id": "evt_test0002", "event_type": "execution_started",
         "invocation_id": "inv_test0002", "outcome": None},
        {**common, "event_id": "evt_test0001", "event_type": "execution_completed",
         "invocation_id": "inv_test0001", "outcome": "success"},
    ]


def _chain(events: list[dict]) -> list[dict]:
    prev = None
    for e in events:
        e["content_hash"] = _compute_event_hash(e, prev)
        e["prev_hash"] = prev
        prev = e["content_hash"]
    return events


def gen_canon() -> None:
    cases = [
        {"name": "ascii_string", "input": "hello"},
        {"name": "non_ascii_escaped", "input": "café"},
        {"name": "emoji_surrogate_pair", "input": "\U0001F512"},
        {"name": "control_chars", "input": "\b\t\n\f\r"},
        {"name": "c0_control_u0001", "input": "\x01"},
        {"name": "del_0x7f", "input": "\x7f"},
        {"name": "quote_and_backslash", "input": "a\"b\\c"},
        {"name": "key_sort_flat", "input": {"c": 1, "a": 2, "b": 3}},
        {"name": "key_sort_nested", "input": {"z": {"b": 1, "a": 2}, "a": [3, 2, 1]}},
        {"name": "integers_and_bools", "input": {"i": 42, "neg": -7, "t": True, "f": False, "n": None}},
        {"name": "empty_object", "input": {}},
        {"name": "empty_array", "input": []},
        {"name": "unicode_key_sort", "input": {"é": 1, "a": 2, "z": 3}},
        {"name": "nested_mixed", "input": {"event": {"payload": {"note": "café \U0001F512", "n": 1}, "ok": True}}},
    ]
    _write(VEC / "canon" / "cases.json", {
        "canonicalization": "chp-stable-v1",
        "note": ("canon(value) = json.dumps(value, sort_keys=True) per spec/chp-v0.2.md 2. "
                 "A conforming implementation MUST reproduce every expected_canon byte-for-byte. "
                 "Floats are intentionally absent - chp-stable-v1 forbids them in canonicalized content (2 rule 6)."),
        "cases": [{"name": c["name"], "input": c["input"],
                   "expected_canon": json.dumps(c["input"], sort_keys=True)} for c in cases],
    })


def gen_event_and_signed_bundle(key: signing.HostKey) -> None:
    started, completed = _echo_events()
    _write(VEC / "event.json", {
        "event": {k: v for k, v in started.items() if k not in ("content_hash", "prev_hash")},
        "prev_hash": None,
    })
    events = _chain(_echo_events())
    bundle = signing.sign_bundle(signing.build_bundle(HOST, events, created_at=TS), key)
    _write(VEC / "signed-bundle.json", bundle)
    _write(VEC / "expected.json", {
        "note": "Deterministic vectors for chp-stable-v1. Recompute to check a re-implementation.",
        "private_key_seed_hex": CHP_SEED.hex(),
        "public_key_b64": key.public_key_b64,
        "event_content_hash": events[0]["content_hash"],
        "chained": {
            "started_content_hash": events[0]["content_hash"],
            "completed_content_hash": events[1]["content_hash"],
            "prev_hash_of_completed": events[1]["prev_hash"],
        },
        "root_hash": bundle["root_hash"],
        "signature_b64": bundle["signature"]["signature"],
        "signed_over": "canonical bundle header (host_id, protocol_version, created_at, canonicalization, root_hash)",
        "host_identity_signature_b64": bundle["host_identity"]["signature"],
    })


def gen_governance_bundle(key: signing.HostKey) -> None:
    def ev(n: int, etype: str, outcome: str | None, payload: dict) -> dict:
        return {"event_id": f"evt_gov{n:04d}", "event_type": etype,
                "invocation_id": "inv_gov0001", "capability_id": "conformance.unsafe",
                "host_id": HOST, "timestamp": TS, "outcome": outcome, "payload": payload,
                "correlation": {"correlation_id": "gov_corr", "causation_id": None}}

    uri = "conformance.unsafe:1.0.0"
    reason = "guardrail 'g': requires human approval"
    events = _chain([
        ev(1, "safety_assessment_started", None, {"capability_uri": uri}),
        ev(2, "safety_assessment_completed", None,
           {"capability_uri": uri, "level": "low", "score": "0.0", "approved": False}),
        ev(3, "safety_guardrail_triggered", None, {"capability_uri": uri, "reason": reason}),
        ev(4, "safety_action_blocked", "denied", {"capability_uri": uri, "reason": reason}),
        ev(5, "execution_denied", "denied", {"reason": "safety_blocked"}),
    ])
    _write(VEC / "governance-bundle.json",
           signing.sign_bundle(signing.build_bundle(HOST, events, created_at=TS), key))


def gen_anchored_bundle(key: signing.HostKey) -> None:
    events = _chain(_echo_events())
    _write(VEC / "signed-bundle-anchored.json",
           signing.sign_bundle(signing.build_bundle(HOST, events, created_at=TS), key,
                               anchors=[{"type": "domain", "domain": "vector-host.example"}]))


def gen_did_anchored_bundle(key: signing.HostKey) -> None:
    ssh_priv = ed25519.Ed25519PrivateKey.from_private_bytes(SSH_SEED)
    raw_pub = ssh_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    did = sshsig.raw_to_did_key(raw_pub)
    message = signing.did_anchor_message(key.public_key_b64, HOST)
    with tempfile.TemporaryDirectory() as d:
        keyfile = Path(d) / "id_fixture"
        keyfile.write_bytes(ssh_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(keyfile, 0o600)
        msgfile = Path(d) / "msg"
        msgfile.write_bytes(message)
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(keyfile),
                        "-n", sshsig.DID_ANCHOR_NAMESPACE, str(msgfile)],
                       check=True, capture_output=True)
        armored = (Path(d) / "msg.sig").read_text()
    assert sshsig.verify_sshsig(armored, message, expected_raw_pubkey=raw_pub)
    events = _chain(_echo_events())
    _write(VEC / "did-anchored-bundle.json",
           signing.sign_bundle(signing.build_bundle(HOST, events, created_at=TS), key,
                               anchors=[{"type": "did", "did": did, "countersignature": armored}]))


def gen_ordering() -> None:
    """chp-causal-order-v1 determinism vector: 3 hosts, cross-host causation, a
    clock-skew case (child events wall-clock-EARLIER than their causal parent),
    and an equal-timestamp tiebreak that catches case-insensitive comparators
    ("host-B" < "host-a" byte-wise; a locale/casefold comparator flips it)."""
    from chp_core.ordering import order_events

    def ev(eid: str, host: str, seq: int, ts: str, inv: str, caused_by: str | None) -> dict:
        return {"event_id": eid, "event_type": "execution_started", "invocation_id": inv,
                "capability_id": "demo.cap", "host_id": host, "sequence": seq,
                "timestamp": f"2026-01-01T{ts}Z", "outcome": None, "payload": {},
                "correlation": {"correlation_id": "corr_order", "causation_id": caused_by}}

    events = [
        ev("evt_a1", "host-a", 1, "10:00:00", "inv-a1", None),
        ev("evt_a2", "host-a", 2, "10:00:02", "inv-a1", None),
        ev("evt_a3", "host-a", 3, "10:00:05", "inv-a2", None),
        ev("evt_a4", "host-a", 4, "10:00:09", "inv-a1", None),
        # host-B's clock is SKEWED EARLY — causal edges must still place these
        # after evt_a1 (their cause) despite earlier wall-clock timestamps.
        ev("evt_b1", "host-B", 1, "09:59:58", "inv-b1", "inv-a1"),
        ev("evt_b2", "host-B", 2, "09:59:59", "inv-b1", "inv-a1"),
        ev("evt_b3", "host-B", 3, "10:00:05", "inv-b2", None),  # ties evt_a3's timestamp
        ev("evt_c1", "host-c", 1, "10:00:02", "inv-c1", "inv-b1"),
        ev("evt_c2", "host-c", 2, "10:00:03", "inv-c1", "inv-b1"),
    ]
    # Deliberately shuffled input (fixed permutation — determinism must not
    # depend on input order).
    shuffled = [events[i] for i in (7, 2, 4, 0, 8, 5, 1, 6, 3)]
    expected = [e["event_id"] for e in order_events(shuffled)]
    # Hand-traced expectation — guards the generator against its own reference:
    assert expected == ["evt_a1", "evt_b1", "evt_b2", "evt_a2", "evt_c1",
                        "evt_c2", "evt_b3", "evt_a3", "evt_a4"], expected
    _write(VEC / "ordering.json", {
        "algorithm": "chp-causal-order-v1",
        "note": ("Deterministic cross-host ordering (chp-v0.2.md). An implementation MUST "
                 "reproduce expected_order exactly from events (input order is irrelevant). "
                 "Covers: causal edges overriding skewed wall clocks, and a byte-wise "
                 "host_id tiebreak that a case-insensitive comparator gets wrong."),
        "events": shuffled,
        "expected_order": expected,
    })


def gen_task_bundle(key_a: signing.HostKey) -> None:
    """Cross-host task bundle: host-a spawns work on host-b (cross-host
    causation), each host signs its own bundle, the task bundle aggregates."""
    priv_b = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
    pub_b = base64.b64encode(priv_b.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).decode()
    key_b = signing.HostKey(key_id=signing.key_id_for(base64.b64decode(pub_b)),
                            public_key_b64=pub_b, _private=priv_b)

    def ev(eid: str, host: str, seq: int, etype: str, inv: str,
           caused_by: str | None, outcome: str | None) -> dict:
        return {"event_id": eid, "event_type": etype, "invocation_id": inv,
                "capability_id": "demo.cap", "host_id": host, "sequence": seq,
                "timestamp": TS, "outcome": outcome, "payload": {"n": seq},
                "correlation": {"correlation_id": "task_corr", "causation_id": caused_by}}

    a_events = _chain([
        ev("evt_ta1", "task-host-a", 1, "execution_started", "inv-ta1", None, None),
        ev("evt_ta2", "task-host-a", 2, "execution_completed", "inv-ta1", None, "success"),
    ])
    b_events = _chain([
        ev("evt_tb1", "task-host-b", 1, "execution_started", "inv-tb1", "inv-ta1", None),
        ev("evt_tb2", "task-host-b", 2, "execution_completed", "inv-tb1", "inv-ta1", "success"),
    ])
    bundle_a = signing.sign_bundle(signing.build_bundle("task-host-a", a_events, created_at=TS), key_a)
    bundle_b = signing.sign_bundle(signing.build_bundle("task-host-b", b_events, created_at=TS), key_b)
    task = signing.build_task_bundle("task_corr", [bundle_b, bundle_a], created_at=TS)
    v = signing.verify_task_bundle(task)
    assert v.valid and v.checks["causal_closure"], v
    _write(VEC / "task-bundle.json", task)


def main() -> int:
    key = _chp_key()
    print("regenerating spec/test-vectors/ from fixed seeds:")
    gen_canon()
    gen_event_and_signed_bundle(key)
    gen_governance_bundle(key)
    gen_anchored_bundle(key)
    gen_did_anchored_bundle(key)
    gen_ordering()
    gen_task_bundle(key)
    # Self-check: everything we just wrote verifies.
    for name in ("signed-bundle", "governance-bundle", "signed-bundle-anchored", "did-anchored-bundle"):
        v = signing.verify_bundle(json.loads((VEC / f"{name}.json").read_text()))
        assert v.valid, f"{name} does not verify after regeneration"
    print("all regenerated vectors verify ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
