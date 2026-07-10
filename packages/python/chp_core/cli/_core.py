"""Core CHP CLI commands: host, serve-demo, invoke, replay, demo, validate-contract, verify-evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ..demo import build_demo_host
from ..http import create_http_server, serve_http
from ..types import JSON


def _resolve_store(store: str | None) -> str:
    if store is not None:
        return store
    from ..hooks import default_store_path
    return default_store_path()


def cmd_host(args: argparse.Namespace) -> int:
    print_json(request_json("GET", f"{args.url.rstrip('/')}/host"))
    return 0


def cmd_serve_demo(args: argparse.Namespace) -> int:
    host = build_demo_host(args.store)
    base = f"http://{args.bind}:{args.port}"
    print(f"Serving CHP host {host.host_id} at {base}")
    print("Routes: GET /host, GET /capabilities, POST /invoke, POST /replay, GET /replay/{correlation_id}")
    print()
    print("Try it (in another terminal):")
    print(f"""  chp invoke demo.echo --url {base} --payload '{{"text":"hello"}}' --correlation-id first-run""")
    print(f"  chp replay first-run --url {base}          # the evidence chain for that call")
    print(f"  curl -s {base}/export/first-run            # offline-verifiable evidence bundle")
    try:
        from ..signing import load_host_key, resolve_key_dir
        if load_host_key(resolve_key_dir(host.host_id)) is None:
            print()
            print("Evidence is at the hash-chain tier. Run `chp keygen` to sign bundles")
            print("(the `signed` tier — spec/chp-v0.2.md §3), then restart this host.")
    except Exception:  # the nudge must never break serving
        pass
    print(flush=True)
    try:
        serve_http(host, bind=args.bind, port=args.port)
    except KeyboardInterrupt:
        print("\nStopped CHP demo host.")
    return 0


def cmd_invoke(args: argparse.Namespace) -> int:
    body: JSON = {
        "capability_id": args.capability_id,
        "payload": parse_json_object(args.payload, "--payload"),
        "subject": parse_json_object(args.subject, "--subject"),
    }
    if args.correlation_id:
        body["correlation_id"] = args.correlation_id
    print_json(request_json("POST", f"{args.url.rstrip('/')}/invoke", body))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    body = {
        "correlation_id": args.correlation_id,
        "include_payloads": not args.no_payloads,
    }
    print_json(request_json("POST", f"{args.url.rstrip('/')}/replay", body))
    return 0


def cmd_demo_endpoint(_args: argparse.Namespace) -> int:
    server = create_http_server(build_demo_host(), port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    correlation_id = "demo-http-correlation"

    try:
        host_descriptor = request_json("GET", f"{base_url}/host")
        print_json(
            "Discovered Host",
            {
                "id": host_descriptor["id"],
                "capability_ids": [
                    capability["id"] for capability in host_descriptor["capabilities"]
                ],
            },
        )

        search = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "demo.search_information",
                "payload": {"query": "CHP vs MCP"},
                "correlation_id": correlation_id,
                "subject": {"id": "demo-agent", "type": "agent"},
            },
        )
        print_json("Search Invocation Result", search)

        denied = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "demo.deploy_preview",
                "payload": {"project": "chp"},
                "correlation_id": correlation_id,
                "subject": {"id": "demo-agent", "type": "agent"},
            },
        )
        print_json("Denied Invocation Result", denied)

        explanation = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "explain_execution",
                "payload": {"correlation_id": correlation_id},
                "correlation_id": f"{correlation_id}-explanation",
            },
        )
        print_json(
            "Evidence-Backed Explanation",
            {
                "facts": explanation["data"]["facts"],
                "inferences": explanation["data"]["inferences"],
            },
        )

        counterfactual = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "evaluate_counterfactual",
                "payload": {
                    "correlation_id": correlation_id,
                    "invariant": {
                        "id": "warn_on_search_tool",
                        "kind": "capability_id_matches",
                        "failure_behavior": "warn",
                        "parameters": {"capability_id": "demo.search_information"},
                    },
                },
                "correlation_id": f"{correlation_id}-counterfactual",
            },
        )
        print_json(
            "Counterfactual",
            {
                "would_have_warned": counterfactual["data"]["would_have_warned"],
                "violating_events": counterfactual["data"]["violating_events"],
            },
        )

        replay = request_json("GET", f"{base_url}/replay/{correlation_id}")
        print_json(
            "Replay",
            [
                {
                    "sequence": event["sequence"],
                    "event_type": event["event_type"],
                    "capability_id": event["capability_id"],
                    "outcome": event["outcome"],
                }
                for event in replay["events"]
            ],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    return 0


def cmd_validate_contract(args: argparse.Namespace) -> int:
    import sys
    from pathlib import Path

    descriptor_path = Path(args.descriptor)
    if not descriptor_path.exists():
        print(f"Error: file not found: {descriptor_path}", file=sys.stderr)
        return 1

    try:
        with descriptor_path.open() as f:
            descriptor = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in {descriptor_path}: {exc}", file=sys.stderr)
        return 1

    if args.schema:
        schema_path = Path(args.schema)
    else:
        schema_path = Path(__file__).resolve().parent.parent.parent.parent.parent / "schemas" / "capability-descriptor.schema.json"
        if not schema_path.exists():
            schema_path = Path(__file__).resolve().parent.parent.parent.parent.parent.parent / "schemas" / "capability-descriptor.schema.json"

    if not schema_path.exists():
        print(
            f"Error: schema not found at {schema_path}. Pass --schema <path> to specify.",
            file=sys.stderr,
        )
        return 1

    try:
        import jsonschema
    except ImportError:
        print(
            "Error: jsonschema is required: pip install chp-core[dev]",
            file=sys.stderr,
        )
        return 1

    with schema_path.open() as f:
        schema = json.load(f)

    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(descriptor), key=lambda e: list(e.path))

    if not errors:
        print(f"PASS  {descriptor_path}")
        return 0

    print(f"FAIL  {descriptor_path}  ({len(errors)} error(s))")
    for err in errors:
        path = " > ".join(str(p) for p in err.absolute_path) or "(root)"
        print(f"  [{path}]  {err.message}")
    return 1


def cmd_verify_evidence(args: argparse.Namespace) -> int:
    import sys

    # Bundle mode: verify an exported (optionally signed) evidence bundle offline.
    if getattr(args, "bundle", None):
        from .. import signing

        with open(args.bundle) as fh:
            bundle = json.load(fh)
        # Adapter provenance statements (supply chain, chp-v0.2.md §9).
        if bundle.get("kind") == "adapter-provenance":
            pv = signing.verify_provenance_statement(
                bundle, expected_key_id=getattr(args, "expect_key", None))
            print(json.dumps({
                "kind": "adapter-provenance",
                "package": bundle.get("package"),
                "version": bundle.get("version"),
                "publisher": (bundle.get("publisher") or {}).get("host_id"),
                "anchored_domain": pv.anchored_domain,
                "anchored_did": pv.anchored_did,
                "valid": pv.valid,
                "checks": pv.checks,
                "reason": pv.reason,
            }, indent=2))
            return 0 if pv.valid else 1
        # Mandates (delegated authority, chp-v0.2.md §10) dispatch on kind.
        if bundle.get("kind") == "mandate":
            mv = signing.verify_mandate(
                bundle, expected_principal_key=getattr(args, "expect_key", None))
            print(json.dumps({
                "kind": "mandate",
                "mandate_id": bundle.get("mandate_id"),
                "principal": (bundle.get("principal") or {}).get("host_id"),
                "delegate_id": bundle.get("delegate_id"),
                "scope": bundle.get("scope"),
                "valid_until": bundle.get("valid_until"),
                "anchored_domain": mv.anchored_domain,
                "anchored_did": mv.anchored_did,
                "valid": mv.valid,
                "checks": mv.checks,
                "reason": mv.reason,
            }, indent=2))
            return 0 if mv.valid else 1
        # Task bundles (cross-host, chp-v0.2.md §8) dispatch on kind.
        if bundle.get("kind") == "task-bundle":
            tv = signing.verify_task_bundle(bundle)
            print(json.dumps({
                "kind": "task-bundle",
                "assurance": tv.assurance,
                "valid": tv.valid,
                "checks": tv.checks,
                "hosts": tv.hosts,
                "reason": tv.reason,
            }, indent=2))
            return 0 if tv.valid else 1
        v = signing.verify_bundle(bundle, expected_key_id=getattr(args, "expect_key", None))
        print(json.dumps({
            "assurance": v.assurance,
            "valid": v.valid,
            "checks": v.checks,
            "reason": v.reason,
        }, indent=2))
        return 0 if v.valid else 1

    from ..store import SQLiteEvidenceStore

    # Chain mode: strict by default at the CLI (an unhashed/legacy event fails);
    # --lenient restores the tolerant library default.
    strict = not getattr(args, "lenient", False)
    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        result = store.verify_chain(args.session_id, strict=strict)
    finally:
        store.close()

    output = {
        "correlation_id": result.correlation_id,
        "event_count": result.event_count,
        "verified_count": result.verified_count,
        "unverified_count": result.unverified_count,
        "valid": result.valid,
        "strict": strict,
        "first_broken_sequence": result.first_broken_sequence,
    }
    print(json.dumps(output, indent=2))
    if not result.valid:
        print(f"Chain broken at sequence {result.first_broken_sequence}", file=sys.stderr)
        return 1
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    import sys
    from .. import signing

    try:
        key = signing.generate_keypair(
            args.key_dir or signing.DEFAULT_KEY_DIR, overwrite=args.overwrite
        )
    except signing.SigningUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except FileExistsError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "key_id": key.key_id,
        "public_key": key.public_key_b64,
        "key_dir": str(args.key_dir or signing.DEFAULT_KEY_DIR),
    }, indent=2))
    return 0


def cmd_anchor_did(args: argparse.Namespace) -> int:
    """Anchor the CHP host key to this node's Radicle DID (spec §3.1).

    The Radicle identity key (a standard OpenSSH ed25519 key, held in ssh-agent)
    countersigns the CHP public key via `ssh-keygen -Y sign` (SSHSIG). A verifier
    who trusts the DID transitively trusts the CHP key — offline, no CA/DNS."""
    import subprocess
    import sys
    import tempfile
    from pathlib import Path as _Path
    from .. import signing, sshsig

    key_dir = args.key_dir or signing.DEFAULT_KEY_DIR
    key = signing.load_host_key(key_dir)
    if key is None:
        print("no host key found; run `chp keygen` first", file=sys.stderr)
        return 1

    # The node's DID (did:key:z6Mk… = "did:key:" + NID).
    try:
        did = subprocess.run(["rad", "self", "--did"], check=True, capture_output=True,
                             text=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"could not read the Radicle DID (`rad self --did`): {exc}", file=sys.stderr)
        return 1
    try:
        did_raw_pub = sshsig.did_key_to_raw(did)
    except sshsig.SshsigError as exc:
        print(f"unexpected DID format {did!r}: {exc}", file=sys.stderr)
        return 1

    ssh_pub = _Path(args.ssh_key).expanduser()
    message = signing.did_anchor_message(key.public_key_b64, args.host_id)
    with tempfile.TemporaryDirectory() as tmp:
        msgfile = _Path(tmp) / "chp-anchor-msg"
        msgfile.write_bytes(message)
        # Signs via ssh-agent — the Radicle key must be loaded (`ssh-add -l`).
        proc = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(ssh_pub),
             "-n", sshsig.DID_ANCHOR_NAMESPACE, str(msgfile)],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print("ssh-keygen -Y sign failed (is the Radicle key loaded in "
                  f"ssh-agent? `ssh-add -l`): {proc.stderr.strip()}", file=sys.stderr)
            return 1
        armored = (msgfile.parent / (msgfile.name + ".sig")).read_text()

    # Verify our own product before persisting — never save a bad anchor.
    if not sshsig.verify_sshsig(armored, message, expected_raw_pubkey=did_raw_pub):
        print("produced countersignature does not verify against the DID — "
              "is the ssh key the Radicle identity key?", file=sys.stderr)
        return 1

    anchors = [a for a in signing.load_configured_anchors(key_dir) if a.get("type") != "did"]
    anchors.append({"type": "did", "did": did, "countersignature": armored})
    signing.save_configured_anchors(anchors, key_dir)
    # Invalidate the persisted attestation so the next serve rebuilds with the anchor.
    att_path = _Path(key_dir) / "attestation.json"
    if att_path.exists():
        att_path.unlink()
    print(json.dumps({"did": did, "key_id": key.key_id, "host_id": args.host_id,
                      "anchors_file": str(_Path(key_dir) / "anchors.json")}, indent=2))
    return 0


def _record_identity_event(store_path: str | None, host_id: str,
                           event_type: str, payload: dict) -> str | None:
    """Append a host-SELF identity event (IDENTITY_EVIDENCE_TYPES) to the
    evidence store — the host's own hash-chain is its key-transparency log."""
    if store_path is None:
        return None
    from ..store import SQLiteEvidenceStore
    from ..types import CorrelationContext, ExecutionEvidence, new_id

    store = SQLiteEvidenceStore(store_path)
    try:
        ev = ExecutionEvidence(
            event_id=new_id("evt"),
            event_type=event_type,
            invocation_id=new_id("inv"),
            capability_id="chp.host.identity",
            capability_version=None,
            host_id=host_id,
            correlation=CorrelationContext(correlation_id=f"host-identity-{host_id}"),
            payload=payload,
            redacted=False,
        )
        store.append(ev)
        return ev.event_id
    finally:
        store.close()


def cmd_rotate_key(args: argparse.Namespace) -> int:
    """Rotate the host key WITH CONTINUITY (spec §3.2): archive the old pair,
    old key signs a statement vouching for the new, emit key_rotated evidence."""
    import sys
    from .. import signing

    key_dir = args.key_dir or signing.DEFAULT_KEY_DIR
    try:
        new_key, statement = signing.rotate_keypair(key_dir)
    except signing.SigningUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    evt = _record_identity_event(args.store, args.host_id, "key_rotated", {
        "old_key_id": statement["old_key_id"],
        "new_key_id": statement["new_key_id"],
        "rotated_at": statement["rotated_at"],
    })
    print(json.dumps({"rotated": True, "old_key_id": statement["old_key_id"],
                      "new_key_id": new_key.key_id,
                      "continuity_verified": signing.verify_continuity(statement),
                      "evidence_id": evt}, indent=2))
    return 0


def cmd_revoke_key(args: argparse.Namespace) -> int:
    """Revoke the current host key (spec §3.2). Served in the identity document;
    resolution-time verifiers see it (offline verifiers cannot — tier limit)."""
    import sys
    from .. import signing

    key_dir = args.key_dir or signing.DEFAULT_KEY_DIR
    try:
        statement = signing.revoke_key(key_dir, reason=args.reason or "")
    except signing.SigningUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    evt = _record_identity_event(args.store, args.host_id, "key_revoked", {
        "revoked_key_id": statement["revoked_key_id"],
        "revoked_at": statement["revoked_at"],
        "reason": statement["reason"],
    })
    print(json.dumps({"revoked_key_id": statement["revoked_key_id"],
                      "evidence_id": evt}, indent=2))
    return 0


def cmd_export_evidence(args: argparse.Namespace) -> int:
    import sys
    from .. import signing
    from ..store import SQLiteEvidenceStore
    from ..types import utc_now

    store_path = _resolve_store(args.store)
    store = SQLiteEvidenceStore(store_path)
    try:
        events = store.export_correlation(args.session_id)
    finally:
        store.close()
    if not events:
        print(f"no events for correlation {args.session_id!r}", file=sys.stderr)
        return 1

    bundle = signing.build_bundle(args.host_id, events, created_at=utc_now())
    # Sign if a key is present (or explicitly requested); otherwise hash-chain tier.
    key = signing.load_host_key(args.key_dir or signing.DEFAULT_KEY_DIR)
    if args.sign and key is None:
        print("--sign requested but no host key found; run `chp keygen`", file=sys.stderr)
        return 2
    if key is not None and key.can_sign and (args.sign or not args.no_sign):
        bundle = signing.sign_bundle(bundle, key)

    text = json.dumps(bundle, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
        print(json.dumps({"out": args.out, "assurance": bundle["assurance"],
                          "events": len(events), "root_hash": bundle["root_hash"]}, indent=2))
    else:
        print(text)
    return 0


def cmd_retention_apply(args: argparse.Namespace) -> int:
    """Apply retention policies to an evidence store (chain-preserving), then
    optionally compact. Config JSON: {"retain_days":30, "stores":[...],
    "policies":[{"policy_id","retain_days","applies_to",...}]}."""
    import sys
    from ..store import SQLiteEvidenceStore
    from ..compliance import SQLiteComplianceManager
    from ..types import RetentionPolicy

    with open(args.config) as fh:
        cfg = json.load(fh)

    if cfg.get("policies"):
        policies = [RetentionPolicy(**p) for p in cfg["policies"]]
    else:
        policies = [RetentionPolicy(
            policy_id="default", applies_to=["*"],
            retain_days=int(cfg.get("retain_days", 30)),
            redact_payload_after_days=cfg.get("redact_payload_after_days"),
        )]
    stores = cfg.get("stores") or ([_resolve_store(args.store)])

    results = []
    for store_path in stores:
        store_path = os.path.expanduser(store_path)
        store = SQLiteEvidenceStore(store_path)
        try:
            if args.dry_run:
                # Report what WOULD be pruned without mutating.
                with store._lock:
                    row = store._conn.execute("SELECT COUNT(*) AS c FROM evidence_events").fetchone()
                results.append({"store": store_path, "dry_run": True, "events": int(row["c"])})
                continue
            report = SQLiteComplianceManager(store).apply_retention(policies)
            entry = {"store": store_path, "purged": report.events_purged,
                     "redacted": report.events_redacted, "inspected": report.events_inspected}
            if args.vacuum:
                # VACUUM reclaims freed pages. Plain VACUUM needs a full-size temp
                # copy (no headroom at 97% disk); callers on a tight disk should
                # move archives off-box first — deletes already stop growth.
                with store._lock:
                    store._conn.execute("VACUUM")
                entry["vacuumed"] = True
            results.append(entry)
        finally:
            store.close()

    print(json.dumps({"results": results}, indent=2))
    return 0


def request_json(method: str, url: str, body: JSON | None = None) -> JSON:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urlopen(request, timeout=5) as response:
            value = json.loads(response.read().decode("utf-8"))
    except HTTPError:
        raise  # the server answered — let callers surface its error body
    except (URLError, OSError) as exc:
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        reason = getattr(exc, "reason", exc)
        print(
            f"no CHP host responding at {base} ({reason}).\n"
            "Start one:  chp serve-demo          # batteries-included demo host\n"
            "       or:  chp serve-http --module your_app:create_host",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    if not isinstance(value, dict):
        raise ValueError("expected JSON object response")
    return value


def parse_json_object(raw: str, flag: str) -> JSON:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{flag} must be valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{flag} must be a JSON object")
    return value


def print_json(value: Any, data: Any | None = None) -> None:
    if data is None:
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    print(f"\n## {value}")
    print(json.dumps(data, indent=2, sort_keys=True))


# ---------------------------------------------------------------------------
# chp provenance — supply-chain statements (chp-v0.2.md §9, proposal 0001)
# ---------------------------------------------------------------------------

def _dist_name_version(filename: str) -> tuple[str, str]:
    """(package, version) from a wheel or sdist filename.

    Wheels: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl —
    distribution uses underscores; normalize back to hyphens (PEP 503-ish).
    Sdists: {name}-{version}.tar.gz.
    """
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        return parts[0].replace("_", "-"), parts[1]
    if filename.endswith(".tar.gz"):
        stem = filename[: -len(".tar.gz")]
        name, _, version = stem.rpartition("-")
        return name.replace("_", "-"), version
    raise ValueError(f"not a wheel or sdist: {filename}")


def cmd_provenance_sign(args: argparse.Namespace) -> int:
    import hashlib
    import sys
    from pathlib import Path

    from .. import signing
    from ..types import utc_now

    key_dir = args.key_dir or signing.resolve_key_dir(args.publisher_id)
    key = signing.load_host_key(key_dir)
    if key is None or not key.can_sign:
        print(f"no signing key in {key_dir} — run `chp keygen` first", file=sys.stderr)
        return 1
    anchors = signing.load_configured_anchors(key_dir) or None
    key_history = signing.load_key_history(key_dir) or None

    written = []
    for raw in args.files:
        p = Path(raw)
        if p.name.endswith(".chp-provenance.json"):
            continue  # allow globs over a dist dir that already has statements
        try:
            package, version = _dist_name_version(p.name)
        except ValueError as exc:
            print(f"skipping {p.name}: {exc}", file=sys.stderr)
            continue
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        stmt = signing.build_provenance_statement(
            package, version, sha, key,
            publisher_id=args.publisher_id, created_at=utc_now(), anchors=anchors,
            key_history=key_history)
        out = p.with_name(p.name + ".chp-provenance.json")
        out.write_text(json.dumps(stmt, indent=2, sort_keys=True) + "\n")
        written.append({"artifact": p.name, "package": package, "version": version,
                        "wheel_sha256": sha, "statement": str(out)})
    print(json.dumps({"publisher": args.publisher_id, "key_id": key.key_id,
                      "signed": written}, indent=2))
    return 0 if written else 1


def cmd_mandate_issue(args: argparse.Namespace) -> int:
    import sys
    from datetime import datetime, timedelta, timezone

    from .. import signing
    from ..types import utc_now

    key_dir = args.key_dir or signing.resolve_key_dir(args.principal_id)
    key = signing.load_host_key(key_dir)
    if key is None or not key.can_sign:
        print(f"no signing key in {key_dir} — run `chp keygen` first", file=sys.stderr)
        return 1
    anchors = signing.load_configured_anchors(key_dir) or None
    key_history = signing.load_key_history(key_dir) or None

    now = utc_now()
    valid_until = args.valid_until
    if valid_until is None:
        base = datetime.fromisoformat(now.replace("Z", "+00:00"))
        hours = float(args.ttl_hours)
        valid_until = (base + timedelta(hours=hours)).astimezone(
            timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mandate = signing.build_mandate(
        args.principal_id, key,
        delegate_id=args.delegate,
        scope=[s for s in (e.strip() for e in args.scope.split(",")) if s],
        valid_from=now, valid_until=valid_until, created_at=now,
        anchors=anchors, key_history=key_history)
    text = json.dumps(mandate, indent=2, sort_keys=True) + "\n"
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(text)
        print(json.dumps({"mandate_id": mandate["mandate_id"],
                          "delegate_id": args.delegate,
                          "scope": mandate["scope"],
                          "valid_until": valid_until,
                          "written": args.out}, indent=2))
    else:
        print(text, end="")
    return 0


def cmd_mandate_verify(args: argparse.Namespace) -> int:
    from .. import signing

    with open(args.mandate) as fh:
        mandate = json.load(fh)
    at_time = args.at_time
    if at_time is None:
        from ..types import utc_now
        at_time = utc_now()
    v = signing.verify_mandate(
        mandate, at_time=at_time, capability_id=args.capability,
        delegate_id=args.delegate, expected_principal_key=args.expect_key)
    print(json.dumps({
        "kind": "mandate",
        "mandate_id": mandate.get("mandate_id"),
        "principal": (mandate.get("principal") or {}).get("host_id"),
        "delegate_id": mandate.get("delegate_id"),
        "scope": mandate.get("scope"),
        "valid_until": mandate.get("valid_until"),
        "checked_at": at_time,
        "anchored_domain": v.anchored_domain, "anchored_did": v.anchored_did,
        "valid": v.valid, "checks": v.checks, "reason": v.reason,
    }, indent=2))
    return 0 if v.valid else 1


def cmd_provenance_verify(args: argparse.Namespace) -> int:
    import hashlib
    from pathlib import Path

    from .. import signing

    with open(args.statement) as fh:
        stmt = json.load(fh)
    sha = None
    if args.wheel:
        sha = hashlib.sha256(Path(args.wheel).read_bytes()).hexdigest()
    v = signing.verify_provenance_statement(
        stmt, expected_key_id=args.expect_key, wheel_sha256=sha)
    print(json.dumps({
        "kind": "adapter-provenance",
        "package": stmt.get("package"), "version": stmt.get("version"),
        "publisher": (stmt.get("publisher") or {}).get("host_id"),
        "anchored_domain": v.anchored_domain, "anchored_did": v.anchored_did,
        "artifact_checked": sha is not None,
        "valid": v.valid, "checks": v.checks, "reason": v.reason,
    }, indent=2))
    return 0 if v.valid else 1
