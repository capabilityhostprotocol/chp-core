#!/usr/bin/env python3
"""Minimal CHP v0.1 conformance runner."""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages" / "python"))

from chp_core import (  # noqa: E402
    CapabilityDescriptor,
    InvariantDescriptor,
    LocalCapabilityHost,
    SQLiteEvidenceStore,
)
from sample_failing_hosts import BrokenNoEvidenceHost  # noqa: E402


Check = Callable[[Any], Awaitable[None]]


@dataclass(slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


def result_value(result: Any, name: str) -> Any:
    if isinstance(result, dict):
        return result.get(name)
    return getattr(result, name)


def evidence_ids(result: Any) -> list[str]:
    value = result_value(result, "evidence_ids")
    return list(value or [])


async def invoke_host(host: Any, *args: Any, **kwargs: Any) -> Any:
    if hasattr(host, "ainvoke"):
        return await host.ainvoke(*args, **kwargs)
    result = host.invoke(*args, **kwargs)
    if hasattr(result, "__await__"):
        return await result
    return result


async def build_passing_host() -> LocalCapabilityHost:
    host = LocalCapabilityHost("conformance-host", store=SQLiteEvidenceStore(":memory:"))

    async def echo(_ctx, payload):
        return {"echo": payload.get("value")}

    async def fail(_ctx, _payload):
        raise RuntimeError("expected failure")

    host.register(
        CapabilityDescriptor(
            id="conformance.echo",
            version="1.0.0",
            description="Echo a value.",
        ),
        echo,
    )
    host.register(
        CapabilityDescriptor(
            id="conformance.fail",
            version="1.0.0",
            description="Fail deterministically.",
        ),
        fail,
    )
    host.register(
        CapabilityDescriptor(
            id="conformance.guarded",
            version="1.0.0",
            description="Require payload.value.",
            invariants=[
                InvariantDescriptor(
                    id="requires_value",
                    kind="required_payload_fields",
                    enforcement="host",
                    parameters={"fields": ["value"]},
                )
            ],
        ),
        echo,
    )
    return host


async def check_declaration(host: Any) -> None:
    descriptor = host.discover()
    caps = descriptor.get("capabilities") or []
    assert descriptor["protocol_version"] == "0.1"
    assert any(cap["id"] == "conformance.echo" for cap in caps)


async def check_discovery(host: Any) -> None:
    descriptor = host.discover()
    assert descriptor["id"]
    assert isinstance(descriptor["capabilities"], list)
    for cap in descriptor["capabilities"]:
        assert cap["id"]
        assert cap["version"]
        assert "modes" in cap


async def check_invocation_envelope(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.echo",
        {"value": "ok"},
        correlation={"correlation_id": "conf-invoke"},
    )
    assert result_value(result, "success") is True
    assert result_value(result, "outcome") == "success"
    assert result_value(result, "data") == {"echo": "ok"}


async def check_correlation_propagation(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.echo",
        {"value": "corr"},
        correlation={"correlation_id": "conf-correlation"},
    )
    correlation = result_value(result, "correlation")
    if isinstance(correlation, dict):
        correlation_id = correlation["correlation_id"]
    else:
        correlation_id = correlation.correlation_id
    assert correlation_id == "conf-correlation"
    replay = host.replay("conf-correlation")
    assert replay
    assert {event["correlation"]["correlation_id"] for event in replay} == {"conf-correlation"}


async def check_success_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.echo",
        {"value": "evidence"},
        correlation={"correlation_id": "conf-success"},
    )
    assert len(evidence_ids(result)) >= 2
    event_types = [event["event_type"] for event in host.replay("conf-success")]
    assert "execution_started" in event_types
    assert "execution_completed" in event_types


async def check_failure_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.fail",
        {},
        correlation={"correlation_id": "conf-failure"},
    )
    assert result_value(result, "success") is False
    assert result_value(result, "outcome") == "failure"
    event_types = [event["event_type"] for event in host.replay("conf-failure")]
    assert "execution_started" in event_types
    assert "execution_failed" in event_types


async def check_denial_evidence(host: Any) -> None:
    result = await invoke_host(
        host,
        "conformance.guarded",
        {},
        correlation={"correlation_id": "conf-denial"},
    )
    assert result_value(result, "success") is False
    assert result_value(result, "outcome") == "denied"
    event_types = [event["event_type"] for event in host.replay("conf-denial")]
    assert event_types == ["execution_denied"]


async def check_replay_by_correlation(host: Any) -> None:
    await invoke_host(
        host,
        "conformance.echo",
        {"value": "replay"},
        correlation={"correlation_id": "conf-replay"},
    )
    replay = host.replay("conf-replay")
    assert len(replay) >= 2
    sequences = [event["sequence"] for event in replay]
    assert sequences == sorted(sequences)


async def check_pretool_governance(_host: Any) -> None:
    """Pre-tool governance emits evidence and honours block policies."""
    import os
    import tempfile

    from chp_core.hooks import process_pre_tool_use
    from chp_core.policy import BlockPattern, PolicyConfig
    from chp_core.store import SQLiteEvidenceStore

    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "conf-pretool-001",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "cwd": "/tmp",
        }
        result = process_pre_tool_use(payload, store_path, policy=None)
        assert not result.should_block, "expected pass without policy"

        policy = PolicyConfig(block_capability_ids=["claude_code.bash"], block_patterns=[])
        result2 = process_pre_tool_use(payload, store_path, policy=policy)
        assert result2.should_block, "expected block with policy"

        store = SQLiteEvidenceStore(store_path)
        events = store.by_correlation("conf-pretool-001")
        store.close()
        assert len(events) == 2, f"expected 2 events, got {len(events)}"
        types = [e["event_type"] for e in events]
        assert types.count("tool_use_requested") == 2, f"missing events: {types}"
    finally:
        os.unlink(store_path)


async def check_retrieval_capability(_host: Any) -> None:
    """retrieval.query emits retrieval_started + retrieval_completed with source_refs."""
    import os
    import tempfile

    from chp_core import (
        InMemoryKeywordRetrievalCapability,
        LocalCapabilityHost,
        SQLiteEvidenceStore,
        register_retrieval_capability,
    )

    docs = [
        {"source_id": "doc-1", "content": "the quick brown fox", "title": "Doc 1"},
        {"source_id": "doc-2", "content": "lazy dog sleeps deeply", "title": "Doc 2"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        store_path = f.name
    try:
        store = SQLiteEvidenceStore(store_path)
        host = LocalCapabilityHost("conf-retrieval", store=store)
        cap = InMemoryKeywordRetrievalCapability(docs)
        register_retrieval_capability(host, cap)

        result = await host.ainvoke(
            "retrieval.query",
            {"query": "quick fox", "top_k": 2},
            correlation={"correlation_id": "conf-retrieval-001"},
        )
        assert result.success, f"invoke failed: {result}"

        events = host.replay("conf-retrieval-001")
        types = [e["event_type"] for e in events]
        assert "retrieval_started" in types, f"missing retrieval_started: {types}"
        assert "retrieval_completed" in types, f"missing retrieval_completed: {types}"

        completed = next(e for e in events if e["event_type"] == "retrieval_completed")
        assert "source_refs" in (completed.get("payload") or {}), "missing source_refs in payload"
        store.close()
    finally:
        os.unlink(store_path)


CHECKS: list[tuple[str, Check]] = [
    ("capability declaration", check_declaration),
    ("capability discovery", check_discovery),
    ("invocation through envelope", check_invocation_envelope),
    ("correlation propagation", check_correlation_propagation),
    ("evidence emission on success", check_success_evidence),
    ("evidence emission on failure", check_failure_evidence),
    ("evidence emission on denial", check_denial_evidence),
    ("replay by correlation id", check_replay_by_correlation),
    ("pre-tool governance", check_pretool_governance),
    ("retrieval capability", check_retrieval_capability),
]


async def run(sample: str) -> list[CheckResult]:
    if sample == "passing":
        host = await build_passing_host()
    elif sample == "failing-no-evidence":
        host = BrokenNoEvidenceHost()
    else:
        raise ValueError(f"unknown sample host: {sample}")

    results = []
    for name, check in CHECKS:
        try:
            await check(host)
            results.append(CheckResult(name, True))
        except Exception as exc:  # noqa: BLE001
            results.append(CheckResult(name, False, str(exc) or exc.__class__.__name__))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CHP v0.1 conformance checks.")
    parser.add_argument(
        "--sample",
        choices=["passing", "failing-no-evidence"],
        default="passing",
        help="Built-in sample host to test.",
    )
    args = parser.parse_args()

    results = asyncio.run(run(args.sample))
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        suffix = f" - {result.detail}" if result.detail else ""
        print(f"{status} {result.name}{suffix}")

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
