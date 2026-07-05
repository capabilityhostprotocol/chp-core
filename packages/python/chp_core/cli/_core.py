"""Core CHP CLI commands: host, serve-demo, invoke, replay, demo, validate-contract, verify-evidence."""

from __future__ import annotations

import argparse
import json
import os
import threading
from typing import Any
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
    print(f"Serving CHP host {host.host_id} at http://{args.bind}:{args.port}")
    print("Routes: GET /host, GET /capabilities, POST /invoke, POST /replay, GET /replay/{correlation_id}")
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
    with urlopen(request, timeout=5) as response:
        value = json.loads(response.read().decode("utf-8"))
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
