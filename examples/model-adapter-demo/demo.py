"""Multi-model adapter demo — all three providers on one CHP host.

Uses mocked clients so no API keys are required.
Run with: python examples/model-adapter-demo/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages" / "python"))

from chp_core import LocalCapabilityHost, SQLiteEvidenceStore, register_adapter
from chp_core.adapters.claude import ClaudeAdapter
from chp_core.adapters.openai import OpenAIAdapter
from chp_core.adapters.gemini import GeminiAdapter


def _mock_claude_client() -> MagicMock:
    response = MagicMock()
    response.usage.input_tokens = 25
    response.usage.output_tokens = 48
    response.stop_reason = "end_turn"
    response.model_dump.return_value = {
        "id": "msg_demo",
        "content": [{"type": "text", "text": "CHP is an execution evidence layer for agents."}],
    }
    client = MagicMock()
    client.messages.create.return_value = response
    return client


def _mock_openai_client() -> MagicMock:
    usage = MagicMock()
    usage.prompt_tokens = 20
    usage.completion_tokens = 35
    choice = MagicMock()
    choice.finish_reason = "stop"
    choice.message.content = "CHP wraps LLM tool calls as evidenced capabilities."
    response = MagicMock()
    response.usage = usage
    response.choices = [choice]
    response.model_dump.return_value = {"id": "cmpl_demo", "choices": []}
    client = MagicMock()
    client.chat.completions.create.return_value = response
    return client


def _mock_gemini_client() -> MagicMock:
    usage = MagicMock()
    usage.prompt_token_count = 15
    usage.candidates_token_count = 30
    candidate = MagicMock()
    candidate.finish_reason = "STOP"
    response = MagicMock()
    response.usage_metadata = usage
    response.candidates = [candidate]
    response.text = "CHP makes agent execution observable and replayable."
    client = MagicMock()
    client.generate_content.return_value = response
    return client


def main() -> None:
    host = LocalCapabilityHost("demo-model-host", store=SQLiteEvidenceStore(":memory:"))

    register_adapter(host, ClaudeAdapter(model="claude-opus-4-5", client=_mock_claude_client()))
    register_adapter(host, OpenAIAdapter(model="gpt-4o", client=_mock_openai_client()))
    register_adapter(host, GeminiAdapter(model="gemini-2.0-flash", client=_mock_gemini_client()))

    prompt = "What is the Capability Host Protocol?"
    correlation_id = "demo-multi-model"

    print(f"\nInvoking all three model adapters (correlation: {correlation_id})\n")

    host.invoke(
        "claude.messages.create",
        {"messages": [{"role": "user", "content": prompt}], "max_tokens": 256},
        correlation_id=correlation_id,
    )

    host.invoke(
        "openai.chat.completions.create",
        {"messages": [{"role": "user", "content": prompt}]},
        correlation_id=correlation_id,
    )

    host.invoke(
        "gemini.generate_content",
        {"contents": prompt},
        correlation_id=correlation_id,
    )

    replay = host.replay(correlation_id)
    print(f"Evidence trace ({len(replay)} events):\n")
    for event in replay:
        seq = event["sequence"]
        etype = event["event_type"]
        cap = event["capability_id"]
        outcome = event.get("outcome") or "-"
        payload = event.get("payload", {})
        if etype in ("model_invocation_started", "model_invocation_completed"):
            extra = {k: payload[k] for k in ("model_id", "provider", "prompt_tokens", "completion_tokens", "finish_reason") if k in payload}
            print(f"  [{seq:2d}] {etype:<35} {cap:<35}  {json.dumps(extra)}")
        else:
            print(f"  [{seq:2d}] {etype:<35} {cap:<35}  outcome={outcome}")

    print("\nQuery: model_invocation_completed events only")
    completed = host.query_evidence(outcome=None)
    completed_model = [e for e in completed if e["event_type"] == "model_invocation_completed"]
    for e in completed_model:
        p = e["payload"]
        print(f"  {p['provider']:10}  {p['model_id']:25}  tokens={p['prompt_tokens']+p['completion_tokens']}")

    print(f"\nTotal events in correlation: {host.evidence_count(correlation_id)}")


if __name__ == "__main__":
    main()
