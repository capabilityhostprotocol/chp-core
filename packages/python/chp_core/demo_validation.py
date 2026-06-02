"""Validation helpers for the local CHP HTTP endpoint demo."""

from __future__ import annotations

import json
import threading
from urllib.request import Request, urlopen

from .checks import add_check
from .demo import build_demo_host
from .http import create_http_server
from .types import JSON


def validate_endpoint_demo() -> JSON:
    server = create_http_server(build_demo_host(), port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    correlation_id = "validated-endpoint-demo"
    checks: list[JSON] = []

    try:
        host_descriptor = request_json("GET", f"{base_url}/host")
        capability_ids = {
            capability["id"] for capability in host_descriptor.get("capabilities", [])
        }
        add_check(
            checks,
            "host_discovery",
            {"demo.search_information", "demo.deploy_preview", "explain_execution"}.issubset(capability_ids),
            {"capability_ids": sorted(capability_ids)},
        )

        search = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "demo.search_information",
                "payload": {"query": "CHP validation"},
                "correlation_id": correlation_id,
            },
        )
        add_check(
            checks,
            "successful_invocation",
            bool(search.get("success")) and search.get("outcome") == "success",
            {"outcome": search.get("outcome"), "evidence_ids": search.get("evidence_ids", [])},
        )

        denied = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "demo.deploy_preview",
                "payload": {"project": "chp"},
                "correlation_id": correlation_id,
            },
        )
        add_check(
            checks,
            "denied_invocation",
            denied.get("outcome") == "denied"
            and (denied.get("denial") or {}).get("code") == "invariant_failed",
            {"outcome": denied.get("outcome"), "denial": denied.get("denial")},
        )

        replay = request_json("GET", f"{base_url}/replay/{correlation_id}")
        event_types = [event["event_type"] for event in replay.get("events", [])]
        add_check(
            checks,
            "replay_contains_evidence",
            replay.get("event_count") == 3
            and event_types == [
                "execution_started",
                "execution_completed",
                "execution_denied",
            ],
            {"event_count": replay.get("event_count"), "event_types": event_types},
        )

        explanation = request_json(
            "POST",
            f"{base_url}/invoke",
            {
                "capability_id": "explain_execution",
                "payload": {"correlation_id": correlation_id},
                "correlation_id": f"{correlation_id}-explanation",
            },
        )
        add_check(
            checks,
            "explanation_references_evidence",
            bool(explanation.get("success"))
            and len((explanation.get("data") or {}).get("evidence_references", [])) == 3,
            {"evidence_references": (explanation.get("data") or {}).get("evidence_references", [])},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    return {
        "demo": "endpoint",
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "target_correlation_id": correlation_id,
    }


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
