#!/usr/bin/env python3
"""Agent/tool observability demo for CHP v0.1."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core import (  # noqa: E402
    CapabilityDescriptor,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    register_builtin_capabilities,
)


def print_json(label: str, value: object) -> None:
    print(f"\n## {label}")
    print(json.dumps(value, indent=2, sort_keys=True))


async def main() -> None:
    host = LocalCapabilityHost(
        "agent-operations-demo",
        store=SQLiteEvidenceStore(":memory:"),
    )
    register_builtin_capabilities(host)

    async def add(_ctx, payload):
        return {"result": payload["a"] + payload["b"]}

    async def multiply(_ctx, payload):
        return {"result": payload["a"] * payload["b"]}

    host.register(
        CapabilityDescriptor(
            id="tool.add",
            version="1.0.0",
            description="Add two numbers.",
            tags=["tool", "math"],
        ),
        add,
    )
    host.register(
        CapabilityDescriptor(
            id="tool.multiply",
            version="1.0.0",
            description="Multiply two numbers.",
            tags=["tool", "math"],
        ),
        multiply,
    )

    correlation = {"correlation_id": "demo-agent-run-001"}
    user_task = "Add 2 and 3, then double the result."

    await host.ainvoke(
        "trace_execution",
        {
            "source_id": "agent.local",
            "event_type": "agent_received_task",
            "summary": user_task,
        },
        correlation=correlation,
    )

    await host.ainvoke(
        "trace_execution",
        {
            "source_id": "agent.local",
            "event_type": "tool_selected",
            "summary": "Selected tool.add for the first arithmetic step.",
            "correlation_hints": {"tool": "tool.add"},
        },
        correlation=correlation,
    )
    add_result = await host.ainvoke("tool.add", {"a": 2, "b": 3}, correlation=correlation)

    await host.ainvoke(
        "trace_execution",
        {
            "source_id": "agent.local",
            "event_type": "tool_selected",
            "summary": "Selected tool.multiply to double the intermediate result.",
            "correlation_hints": {"tool": "tool.multiply"},
        },
        correlation=correlation,
    )
    final = await host.ainvoke(
        "tool.multiply",
        {"a": add_result.data["result"], "b": 2},
        correlation=correlation,
    )

    explanation = await host.ainvoke(
        "explain_execution",
        {"correlation_id": correlation["correlation_id"]},
    )

    counterfactual = await host.ainvoke(
        "evaluate_counterfactual",
        {
            "correlation_id": correlation["correlation_id"],
            "invariant": {
                "id": "deny_multiply_tool",
                "kind": "capability_id_matches",
                "description": "Deny use of the multiply tool.",
                "parameters": {"capability_id": "tool.multiply"},
            },
        },
    )

    trace = host.replay(correlation["correlation_id"])
    compact_trace = [
        {
            "sequence": event["sequence"],
            "event_type": event["event_type"],
            "capability_id": event["capability_id"],
            "outcome": event["outcome"],
        }
        for event in trace
    ]

    print(f"User task: {user_task}")
    print(f"Final answer: {final.data['result']}")
    print_json("Replay", compact_trace)
    print_json("Explanation", explanation.data)
    print_json("Counterfactual", counterfactual.data)


if __name__ == "__main__":
    asyncio.run(main())
