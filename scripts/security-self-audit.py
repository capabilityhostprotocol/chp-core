#!/usr/bin/env python3
"""CHP crypto / signed-evidence self-audit — adversarial verification.

Every check mounts a REAL attack against a core security claim (tamper an event, forge a
proof, swap a payload, present the wrong key) and asserts the verifier FAILS CLOSED — rejects
it. A single FAILED check means a signed-evidence guarantee has a hole. This is the internal,
reproducible evidence an external security audit will demand (roadmap-to-1.0 gate #1); it is
zero-wire and meant to run standing in CI as a regression on the guarantees.

    python scripts/security-self-audit.py            # exits 1 if any guarantee fails closed-ness
    python scripts/security-self-audit.py --json     # machine-readable summary

Claims covered: evidence-chain tamper-evidence · bundle signature + origin binding ·
approval-grant binding (0037) · mandate authority scope (0002/0026) · Merkle inclusion
(RFC 6962 / 0019) · payload confidentiality (0025/0030) · canonicalization determinism.
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1] / "packages" / "python"
sys.path.insert(0, str(_PKG))

from chp_core import LocalCapabilityHost, SQLiteEvidenceStore, capability, merkle, sealing, signing
from chp_core.signing import (
    build_approval_grant,
    build_mandate,
    generate_keypair,
    verify_approval_grant,
    verify_mandate,
)

_NOW = "2026-07-15T00:00:00Z"
_FAR = "2099-01-01T00:00:00Z"


# ── check registry ────────────────────────────────────────────────────────────
_CHECKS: list = []


def check(claim: str):
    def deco(fn):
        _CHECKS.append((claim, fn.__name__, fn))
        return fn
    return deco


def _reject(result_valid: bool, what: str) -> None:
    """Assert an attack was rejected (verifier returned NOT valid)."""
    assert result_valid is False, f"ATTACK NOT DETECTED: {what} was accepted"


# ── fixtures ───────────────────────────────────────────────────────────────────
def _host_with_events():
    host = LocalCapabilityHost("audit-host", store=SQLiteEvidenceStore(":memory:"))

    @capability(id="demo.echo", version="1.0.0", description="echo")
    async def echo(ctx, payload):
        return {"echo": payload}

    host.register(echo)
    res = asyncio.run(host.ainvoke("demo.echo", {"value": "x"}))
    corr = res.correlation.correlation_id
    return host, corr, host.store.export_correlation(corr)


# ── evidence chain: tamper-evidence ─────────────────────────────────────────────
@check("evidence-chain tamper-evidence")
def evidence_chain_valid_then_tamper_detected() -> None:
    host, corr, _ = _host_with_events()
    assert host.store.verify_chain(corr).valid, "a pristine chain must verify"
    # attack: rewrite a CHAIN-COMMITTED field (which capability ran) in a stored event; the
    # SHA256 chain must break. (The disclosed `payload` is committed separately by hash under
    # chp-event-hash-v2 — its integrity is a bundle/commitment check, exercised below.)
    with host.store._conn:  # noqa: SLF001 — self-audit reaches into internals deliberately
        row = host.store._conn.execute(  # noqa: SLF001
            "SELECT sequence, event_json FROM evidence_events WHERE correlation_id=? "
            "ORDER BY sequence ASC LIMIT 1", (corr,)).fetchone()
        doc = json.loads(row["event_json"])
        doc["capability_id"] = "demo.IMPERSONATED"
        host.store._conn.execute(  # noqa: SLF001
            "UPDATE evidence_events SET event_json=? WHERE sequence=?",
            (json.dumps(doc), row["sequence"]))
    _reject(host.store.verify_chain(corr).valid, "an event with a rewritten capability_id")


# ── bundle: signature + origin binding ──────────────────────────────────────────
@check("bundle signature + origin binding")
def bundle_verifies_then_tamper_and_keypin_rejected() -> None:
    host, corr, events = _host_with_events()
    key = generate_keypair(tempfile.mkdtemp())
    bundle = signing.sign_bundle(
        signing.build_bundle("audit-host", events, created_at=_NOW), key)
    assert signing.verify_bundle(bundle).valid, "a freshly signed bundle must verify"

    # attack 1: tamper an event inside the signed bundle — root/hash must no longer match
    tampered = json.loads(json.dumps(bundle))
    evs = tampered.get("events") or tampered.get("leaves") or []
    assert evs, "bundle must carry events to tamper"
    evs[0].setdefault("payload", {})
    evs[0]["payload"] = {"value": "FORGED"}
    _reject(signing.verify_bundle(tampered).valid, "a tampered event in a signed bundle")

    # attack 2: pin the signer to a DIFFERENT key id — a valid sig from an unpinned key loses
    other = generate_keypair(tempfile.mkdtemp())
    _reject(signing.verify_bundle(bundle, expected_key_id=other.key_id).valid,
            "a bundle signed by a non-pinned key")


# ── approval grant: binding (0037) ──────────────────────────────────────────────
@check("approval-grant binding (0037)")
def approval_grant_binding_fails_closed() -> None:
    key = generate_keypair(tempfile.mkdtemp())
    grant = build_approval_grant(key, invocation_id="inv-1", payload_commitment="pc-1",
                                 approval_id="ap-1", valid_until=_FAR)
    assert verify_approval_grant(grant, at_time=_NOW).valid, "a fresh grant must verify"

    # attack 1: repoint the grant at a different invocation — signature must break
    swapped = dict(grant); swapped["invocation_id"] = "inv-EVIL"
    _reject(verify_approval_grant(swapped, at_time=_NOW).valid, "an invocation-swapped grant")

    # attack 2: swap the payload commitment — signature must break (grant authorizes ONE payload)
    swapped2 = dict(grant); swapped2["payload_commitment"] = "pc-OTHER"
    _reject(verify_approval_grant(swapped2, at_time=_NOW).valid, "a payload-swapped grant")

    # attack 3: present it under a different approver pin
    _reject(verify_approval_grant(grant, at_time=_NOW, expected_approver_key="stranger").valid,
            "a grant verified against the wrong approver")

    # attack 4: use it after expiry / garbage input — fail closed
    _reject(verify_approval_grant(grant, at_time="2099-06-01T00:00:00Z").valid, "an expired grant")
    _reject(verify_approval_grant("not-a-dict", at_time=_NOW).valid, "a non-dict grant")


# ── mandate: delegated authority scope (0002 / 0026) ────────────────────────────
@check("mandate authority scope (0002/0026)")
def mandate_scope_fails_closed() -> None:
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    iso = lambda d: d.isoformat().replace("+00:00", "Z")  # noqa: E731
    key = generate_keypair(tempfile.mkdtemp())
    mandate = build_mandate("principal-a", key, delegate_id="steward-x", scope=["demo.echo"],
                            valid_from=iso(now - timedelta(minutes=1)),
                            valid_until=iso(now + timedelta(hours=1)), created_at=iso(now))
    assert verify_mandate(mandate, at_time=iso(now)).valid, "a fresh mandate must verify"

    # attack 1: tamper the delegate — signature must break
    forged = dict(mandate); forged["delegate_id"] = "steward-EVIL"
    _reject(verify_mandate(forged, at_time=iso(now)).valid, "a delegate-swapped mandate")

    # attack 2: use it for a capability OUTSIDE its scope
    _reject(verify_mandate(mandate, at_time=iso(now), capability_id="demo.danger").valid,
            "a mandate used out of scope")

    # attack 3: outside its validity window
    _reject(verify_mandate(mandate, at_time=iso(now - timedelta(days=1))).valid,
            "a mandate used before valid_from")


# ── Merkle inclusion: forgery rejection (RFC 6962 / 0019) ───────────────────────
@check("Merkle inclusion forgery rejection (0019)")
def merkle_inclusion_fails_closed() -> None:
    leaves = [f"leaf-{i}".encode() for i in range(7)]
    root = merkle.merkle_root(leaves)
    idx = 3
    path = merkle.inclusion_proof(leaves, idx)
    assert merkle.verify_inclusion(root, leaves[idx], idx, len(leaves), path), \
        "a real inclusion proof must verify"

    # attack 1: a leaf that is NOT in the tree, with the real path
    _reject(merkle.verify_inclusion(root, b"leaf-FORGED", idx, len(leaves), path),
            "a forged leaf under a real path")
    # attack 2: claim the leaf sits at a different index
    _reject(merkle.verify_inclusion(root, leaves[idx], idx + 1, len(leaves), path),
            "a leaf claimed at the wrong index")
    # attack 3: a truncated audit path
    _reject(merkle.verify_inclusion(root, leaves[idx], idx, len(leaves), path[:-1]),
            "a truncated audit path")
    # attack 4: an extended audit path (leftover entries)
    _reject(merkle.verify_inclusion(root, leaves[idx], idx, len(leaves), path + [b"\x00" * 32]),
            "an over-long audit path")


# ── payload confidentiality (0025 / 0030) ───────────────────────────────────────
@check("payload confidentiality (0025/0030)")
def sealing_fails_closed(tmp: str | None = None) -> None:
    td = Path(tempfile.mkdtemp())
    _host, _corr, events = _host_with_events()
    bundle = signing.build_bundle("audit-host", events, created_at=_NOW)

    # multi-recipient seal: recipients A + B can open; a stranger C cannot
    recip_a = sealing.generate_enc_keypair(td / "a")
    recip_b = sealing.generate_enc_keypair(td / "b")
    stranger = sealing.generate_enc_keypair(td / "c")
    pub_a = sealing.load_enc_public_key_b64(td / "a")
    pub_b = sealing.load_enc_public_key_b64(td / "b")
    sealed = sealing.seal_payloads(bundle, [pub_a, pub_b])

    # claim 1: the sealed bundle still verifies KEYLESS over ciphertext (evidence unbroken)
    assert signing.verify_bundle(sealed).valid, "a sealed bundle must still verify keyless"

    # claim 2: an intended recipient CAN unseal
    opened = sealing.unseal_bundle(sealed, recip_a)
    assert opened is not None, "an intended recipient must unseal"

    # attack: a NON-recipient must NOT be able to unseal
    leaked = False
    try:
        out = sealing.unseal_bundle(sealed, stranger)
        # some impls return the still-sealed bundle rather than raising; that is acceptable
        leaked = _bundle_has_cleartext(out)
    except Exception:
        leaked = False
    assert not leaked, "ATTACK NOT DETECTED: a non-recipient unsealed the payload"
    _ = recip_b  # (documents the 2nd valid recipient)


def _bundle_has_cleartext(bundle) -> bool:
    """True if any event payload is present in cleartext (no chp_sealed marker)."""
    if not isinstance(bundle, dict):
        return False
    for ev in (bundle.get("events") or bundle.get("leaves") or []):
        p = ev.get("payload")
        if isinstance(p, dict) and "chp_sealed" not in p and p:
            return True
    return False


# ── canonicalization determinism ────────────────────────────────────────────────
@check("canonicalization determinism")
def canon_is_deterministic() -> None:
    a = {"b": 2, "a": 1, "nested": {"y": [3, 2, 1], "x": True}}
    b = {"a": 1, "nested": {"x": True, "y": [3, 2, 1]}, "b": 2}  # same value, keys reordered
    for scheme in ("chp-stable-v1", "chp-jcs-v1"):
        canon = signing._canon_for(scheme)  # noqa: SLF001
        assert canon(a) == canon(b), f"{scheme}: key order changed the canonical bytes"
        assert canon(a) == canon(json.loads(json.dumps(a))), f"{scheme}: not idempotent"
    # the two schemes are a real dispatch seam (may differ), but each is internally stable
    assert signing._canon_for(None) is signing._canon  # noqa: SLF001


# ── runner ───────────────────────────────────────────────────────────────────
def main() -> int:
    as_json = "--json" in sys.argv
    results = []
    for claim, name, fn in _CHECKS:
        try:
            fn()
            results.append({"claim": claim, "check": name, "status": "PASS", "detail": ""})
        except Exception as exc:  # a failed attack-detection OR a broken check
            results.append({"claim": claim, "check": name, "status": "FAIL",
                            "detail": f"{type(exc).__name__}: {exc}"})

    failed = [r for r in results if r["status"] != "PASS"]
    if as_json:
        print(json.dumps({"total": len(results), "failed": len(failed),
                          "checks": results}, indent=2))
    else:
        for r in results:
            mark = "✓" if r["status"] == "PASS" else "✗"
            line = f"  {mark} {r['claim']:<42} {r['check']}"
            print(line if r["status"] == "PASS" else f"{line}\n      → {r['detail']}")
        print(f"\ncrypto/evidence self-audit: {len(results) - len(failed)}/{len(results)} "
              f"guarantees fail-closed" + ("" if not failed else f" — {len(failed)} HOLE(S)"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
