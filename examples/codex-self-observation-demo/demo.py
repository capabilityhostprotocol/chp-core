#!/usr/bin/env python3
"""Codex self-observation demo for CHP v0.1."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core import (  # noqa: E402
    LocalCapabilityHost,
    SQLiteEvidenceStore,
    record_codex_action,
    register_builtin_capabilities,
    replay_to_otel_spans,
)


def print_json(label: str, value: object) -> None:
    print(f"\n## {label}")
    print(json.dumps(value, indent=2, sort_keys=True))


def main() -> None:
    correlation_id = "codex-demo-001"
    host = LocalCapabilityHost(
        "codex-self-observation-demo",
        store=SQLiteEvidenceStore(":memory:"),
    )
    register_builtin_capabilities(host)

    record_codex_action(
        host,
        "codex.inspect_repository",
        {
            "task_intent": "Find the CHP v0.1 local host and tests.",
            "files_inspected": [
                "packages/python/chp_core/host.py",
                "packages/python/tests/test_local_host.py",
            ],
            "files_changed": [],
            "commands_run": ["rg", "sed"],
            "tests_run": [],
            "outcome": "success",
            "open_questions": [],
            "follow_up_actions": ["Modify the local host."],
        },
        correlation_id=correlation_id,
    )

    record_codex_action(
        host,
        "codex.modify_file",
        {
            "task_intent": "Add self-observation docs and examples.",
            "files_inspected": ["docs/design/codex-self-observation.md"],
            "files_changed": ["examples/codex-self-observation-demo/demo.py"],
            "commands_run": ["apply_patch"],
            "tests_run": [],
            "outcome": "success",
            "open_questions": [],
            "follow_up_actions": ["Run tests."],
        },
        correlation_id=correlation_id,
    )

    record_codex_action(
        host,
        "codex.run_tests",
        {
            "task_intent": "Verify the self-observation example.",
            "files_inspected": [],
            "files_changed": [],
            "commands_run": ["python examples/codex-self-observation-demo/demo.py"],
            "tests_run": ["demo"],
            "outcome": "success",
            "open_questions": [],
            "follow_up_actions": [],
        },
        correlation_id=correlation_id,
    )

    explanation = host.invoke(
        "explain_execution",
        {"correlation_id": correlation_id},
        correlation_id=f"{correlation_id}-explanation",
    )

    replay = host.replay(correlation_id)
    print_json(
        "Replay",
        [
            {
                "sequence": event["sequence"],
                "event_type": event["event_type"],
                "capability_id": event["capability_id"],
                "outcome": event["outcome"],
            }
            for event in replay
        ],
    )
    print_json("Explanation", explanation.data)
    print_json("OTel Mapping", replay_to_otel_spans(replay))


if __name__ == "__main__":
    main()
