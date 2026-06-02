"""Reference capabilities shipped with the local CHP host."""

from __future__ import annotations

from .host import (
    CapabilityExecutionContext,
    LocalCapabilityHost,
    evaluate_invariant_against_event,
)
from .types import CapabilityDescriptor, InvariantDescriptor, JSON, utc_now


def trace_execution_descriptor() -> CapabilityDescriptor:
    return CapabilityDescriptor(
        id="trace_execution",
        version="0.1.0",
        description="Capture and correlate execution events from agents, tools, or systems.",
        input_schema={
            "type": "object",
            "required": ["source_id", "event_type"],
            "properties": {
                "source_id": {"type": "string"},
                "event_type": {"type": "string"},
                "timestamp": {"type": "string", "format": "date-time"},
                "correlation_hints": {"type": "object"},
                "summary": {"type": "string"},
            },
        },
        output_schema={"type": "object"},
        tags=["observability", "trace"],
        emits=["execution_started", "execution_observed", "execution_completed", "execution_failed"],
    )


def explain_execution_descriptor() -> CapabilityDescriptor:
    return CapabilityDescriptor(
        id="explain_execution",
        version="0.1.0",
        description="Produce an evidence-backed explanation of a trace.",
        input_schema={
            "type": "object",
            "properties": {
                "correlation_id": {"type": "string"},
                "include_inferences": {"type": "boolean"},
            },
        },
        output_schema={"type": "object"},
        tags=["observability", "explanation"],
        emits=["execution_started", "execution_completed", "execution_failed"],
    )


def evaluate_counterfactual_descriptor() -> CapabilityDescriptor:
    return CapabilityDescriptor(
        id="evaluate_counterfactual",
        version="0.1.0",
        description="Evaluate a trace against proposed constraints or invariants.",
        input_schema={
            "type": "object",
            "required": ["correlation_id", "invariant"],
            "properties": {
                "correlation_id": {"type": "string"},
                "invariant": {"type": "object"},
            },
        },
        output_schema={"type": "object"},
        tags=["observability", "counterfactual"],
        emits=["execution_started", "execution_completed", "execution_failed"],
    )


async def trace_execution(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    source_id = str(payload["source_id"])
    external_event_type = str(payload["event_type"])
    observed_at = payload.get("timestamp") or utc_now()
    hints = dict(payload.get("correlation_hints") or {})

    event = ctx.emit(
        "execution_observed",
        {
            "source_id": source_id,
            "external_event_type": external_event_type,
            "observed_at": observed_at,
            "summary": payload.get("summary"),
            "correlation_hints": hints,
        },
    )

    return {
        "accepted": True,
        "observed_event_id": event.event_id,
        "correlation_id": ctx.correlation_id,
    }


async def explain_execution(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    correlation_id = str(payload.get("correlation_id") or ctx.correlation_id)
    include_inferences = bool(payload.get("include_inferences", True))
    events = ctx.replay(correlation_id)

    facts = [
        {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "capability_id": event["capability_id"],
            "outcome": event.get("outcome"),
        }
        for event in events
    ]

    terminal = [event for event in events if event["event_type"] in {"execution_completed", "execution_failed", "execution_denied"}]
    failures = [event for event in terminal if event["event_type"] == "execution_failed"]
    denials = [event for event in terminal if event["event_type"] == "execution_denied"]
    completed = [event for event in terminal if event["event_type"] == "execution_completed"]

    inferences: list[JSON] = []
    if include_inferences:
        if denials:
            inferences.append(
                {
                    "statement": "At least one invocation was denied.",
                    "confidence": 1.0,
                    "evidence_ids": [event["event_id"] for event in denials],
                }
            )
        elif failures:
            inferences.append(
                {
                    "statement": "The trace contains failed execution attempts.",
                    "confidence": 1.0,
                    "evidence_ids": [event["event_id"] for event in failures],
                }
            )
        elif completed:
            inferences.append(
                {
                    "statement": "Observed invocations in this trace completed without recorded failure or denial.",
                    "confidence": 0.85,
                    "evidence_ids": [event["event_id"] for event in completed],
                }
            )

    explanation_event = ctx.emit(
        "explanation_generated",
        {
            "target_correlation_id": correlation_id,
            "fact_count": len(facts),
            "inference_count": len(inferences),
        },
    )

    return {
        "correlation_id": correlation_id,
        "facts": facts,
        "inferences": inferences,
        "evidence_references": [event["event_id"] for event in events],
        "explanation_event_id": explanation_event.event_id,
    }


async def evaluate_counterfactual(ctx: CapabilityExecutionContext, payload: JSON) -> JSON:
    correlation_id = str(payload["correlation_id"])
    invariant_payload = dict(payload["invariant"])
    invariant = InvariantDescriptor(
        id=str(invariant_payload.get("id", "proposed")),
        kind=str(invariant_payload["kind"]),
        description=str(invariant_payload.get("description", "")),
        enforcement=invariant_payload.get("enforcement", "host"),
        failure_behavior=invariant_payload.get("failure_behavior", "deny"),
        parameters=dict(invariant_payload.get("parameters") or {}),
    )

    events = ctx.replay(correlation_id)
    violations = []
    for event in events:
        reason = evaluate_invariant_against_event(invariant, event)
        if reason:
            violations.append(
                {
                    "event_id": event["event_id"],
                    "event_type": event["event_type"],
                    "capability_id": event["capability_id"],
                    "reason": reason,
                }
            )

    counterfactual_event = ctx.emit(
        "counterfactual_evaluated",
        {
            "target_correlation_id": correlation_id,
            "invariant_id": invariant.id,
            "violation_count": len(violations),
        },
    )

    return {
        "correlation_id": correlation_id,
        "invariant": invariant.to_dict(),
        "would_have_denied": bool(violations) and invariant.failure_behavior == "deny",
        "would_have_warned": bool(violations) and invariant.failure_behavior == "warn",
        "would_deny": bool(violations) and invariant.failure_behavior == "deny",
        "violating_events": violations,
        "facts": [
            {
                "statement": f"Evaluated {len(events)} evidence events against invariant {invariant.id}.",
                "evidence_ids": [event["event_id"] for event in events],
            }
        ],
        "counterfactual_event_id": counterfactual_event.event_id,
    }


def register_trace_execution(host: LocalCapabilityHost) -> CapabilityDescriptor:
    return host.register(trace_execution_descriptor(), trace_execution)


def register_explain_execution(host: LocalCapabilityHost) -> CapabilityDescriptor:
    return host.register(explain_execution_descriptor(), explain_execution)


def register_evaluate_counterfactual(host: LocalCapabilityHost) -> CapabilityDescriptor:
    return host.register(evaluate_counterfactual_descriptor(), evaluate_counterfactual)


def register_builtin_capabilities(host: LocalCapabilityHost) -> None:
    register_trace_execution(host)
    register_explain_execution(host)
    register_evaluate_counterfactual(host)
