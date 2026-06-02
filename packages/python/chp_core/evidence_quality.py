"""Evidence quality checks for local CHP traces."""

from __future__ import annotations

from .checks import add_check
from .protocol_checks import CORE_OUTCOMES
from .types import JSON


def build_evidence_quality_audit(
    events: list[JSON],
    *,
    target_correlation_id: str,
) -> JSON:
    checks: list[JSON] = []
    event_types = [str(event.get("event_type")) for event in events]
    outcomes = [event.get("outcome") for event in events if event.get("outcome") is not None]
    sequences = [
        int(event["sequence"])
        for event in events
        if isinstance(event.get("sequence"), int)
    ]
    invocation_ids = sorted(
        {
            str(event.get("invocation_id"))
            for event in events
            if event.get("invocation_id")
        }
    )

    add_check(
        checks,
        "trace_has_events",
        len(events) > 0,
        {"event_count": len(events)},
    )
    add_check(
        checks,
        "correlation_consistent",
        bool(events)
        and all(
            ((event.get("correlation") or {}).get("correlation_id") == target_correlation_id)
            for event in events
        ),
        {"target_correlation_id": target_correlation_id},
    )
    add_check(
        checks,
        "required_event_fields_present",
        bool(events)
        and all(
            event.get("event_id")
            and event.get("event_type")
            and event.get("invocation_id")
            and event.get("capability_id")
            and event.get("host_id")
            and event.get("timestamp")
            for event in events
        ),
        {"fields": ["event_id", "event_type", "invocation_id", "capability_id", "host_id", "timestamp"]},
    )
    add_check(
        checks,
        "sequence_strictly_increasing",
        len(sequences) == len(events) and sequences == sorted(set(sequences)),
        {"sequences": sequences},
    )
    add_check(
        checks,
        "execution_start_visible",
        "execution_started" in event_types
        or any(event_type in event_types for event_type in ["execution_denied", "execution_skipped"]),
        {"event_types": event_types},
    )
    add_check(
        checks,
        "terminal_outcome_visible",
        any(
            event_type in event_types
            for event_type in [
                "execution_completed",
                "execution_failed",
                "execution_denied",
                "execution_skipped",
            ]
        ),
        {"event_types": event_types, "outcomes": outcomes},
    )
    add_check(
        checks,
        "outcomes_are_known",
        all(outcome in CORE_OUTCOMES for outcome in outcomes),
        {"outcomes": outcomes, "known_outcomes": CORE_OUTCOMES},
    )
    add_check(
        checks,
        "failure_events_not_hidden",
        "failure" not in outcomes or "execution_failed" in event_types,
        {"event_types": event_types, "outcomes": outcomes},
    )
    add_check(
        checks,
        "denial_events_not_hidden",
        "denied" not in outcomes or "execution_denied" in event_types,
        {"event_types": event_types, "outcomes": outcomes},
    )
    add_check(
        checks,
        "redaction_state_recorded",
        bool(events) and all(isinstance(event.get("redacted"), bool) for event in events),
        {"unmarked_event_ids": [event.get("event_id") for event in events if not isinstance(event.get("redacted"), bool)]},
    )
    add_check(
        checks,
        "host_identity_present",
        bool(events) and all(event.get("host_id") for event in events),
        {"host_ids": sorted({str(event.get("host_id")) for event in events if event.get("host_id")})},
    )
    add_check(
        checks,
        "invocation_identity_present",
        bool(invocation_ids),
        {"invocation_ids": invocation_ids},
    )

    passed_count = sum(1 for check in checks if check["passed"])
    score = round(passed_count / len(checks), 3) if checks else 0
    failed_checks = [check["name"] for check in checks if not check["passed"]]
    return {
        "target_correlation_id": target_correlation_id,
        "passed": not failed_checks,
        "score": score,
        "event_count": len(events),
        "invocation_count": len(invocation_ids),
        "event_types": event_types,
        "outcomes": outcomes,
        "checks": checks,
        "failed_checks": failed_checks,
    }
