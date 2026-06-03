from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import LocalCapabilityHost, SQLiteEvidenceStore, register_adapter
from chp_core.adapters.claude import ClaudeAdapter
from chp_core.adapters.openai import OpenAIAdapter
from chp_core.adapters.gemini import GeminiAdapter


def _make_host() -> LocalCapabilityHost:
    return LocalCapabilityHost("test-model-host", store=SQLiteEvidenceStore(":memory:"))


class ClaudeAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_invoke_emits_model_evidence(self) -> None:
        mock_response = MagicMock()
        mock_response.usage.input_tokens = 12
        mock_response.usage.output_tokens = 34
        mock_response.stop_reason = "end_turn"
        mock_response.model_dump.return_value = {"id": "msg_abc", "content": []}

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        host = _make_host()
        adapter = ClaudeAdapter(model="claude-opus-4-5", client=mock_client)
        register_adapter(host, adapter)

        result = await host.ainvoke(
            "claude.messages.create",
            {
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": 64,
            },
            correlation={"correlation_id": "corr-claude"},
        )

        self.assertTrue(result.success)

        event_types = [e["event_type"] for e in host.replay("corr-claude")]
        self.assertIn("model_invocation_started", event_types)
        self.assertIn("model_invocation_completed", event_types)

        completed = next(e for e in host.replay("corr-claude") if e["event_type"] == "model_invocation_completed")
        self.assertEqual(completed["payload"]["provider"], "anthropic")
        self.assertEqual(completed["payload"]["prompt_tokens"], 12)
        self.assertEqual(completed["payload"]["completion_tokens"], 34)
        self.assertEqual(completed["payload"]["finish_reason"], "end_turn")

    async def test_missing_anthropic_raises_import_error(self) -> None:
        host = _make_host()
        adapter = ClaudeAdapter(model="claude-opus-4-5")
        register_adapter(host, adapter)

        with patch.dict("sys.modules", {"anthropic": None}):
            adapter._client = None
            result = await host.ainvoke(
                "claude.messages.create",
                {"messages": [], "max_tokens": 1},
                correlation={"correlation_id": "corr-no-anthropic"},
            )
        self.assertFalse(result.success)
        self.assertIn("ImportError", result.error["type"])


class OpenAIAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_invoke_emits_model_evidence(self) -> None:
        mock_usage = MagicMock()
        mock_usage.prompt_tokens = 10
        mock_usage.completion_tokens = 20

        mock_choice = MagicMock()
        mock_choice.finish_reason = "stop"

        mock_response = MagicMock()
        mock_response.usage = mock_usage
        mock_response.choices = [mock_choice]
        mock_response.model_dump.return_value = {"id": "cmpl_xyz", "choices": []}

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        host = _make_host()
        adapter = OpenAIAdapter(model="gpt-4o", client=mock_client)
        register_adapter(host, adapter)

        result = await host.ainvoke(
            "openai.chat.completions.create",
            {"messages": [{"role": "user", "content": "Hi"}]},
            correlation={"correlation_id": "corr-openai"},
        )

        self.assertTrue(result.success)

        event_types = [e["event_type"] for e in host.replay("corr-openai")]
        self.assertIn("model_invocation_started", event_types)
        self.assertIn("model_invocation_completed", event_types)

        completed = next(e for e in host.replay("corr-openai") if e["event_type"] == "model_invocation_completed")
        self.assertEqual(completed["payload"]["provider"], "openai")
        self.assertEqual(completed["payload"]["prompt_tokens"], 10)
        self.assertEqual(completed["payload"]["completion_tokens"], 20)
        self.assertEqual(completed["payload"]["finish_reason"], "stop")


class GeminiAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_invoke_emits_model_evidence(self) -> None:
        mock_usage = MagicMock()
        mock_usage.prompt_token_count = 8
        mock_usage.candidates_token_count = 16

        mock_candidate = MagicMock()
        mock_candidate.finish_reason = "STOP"

        mock_response = MagicMock()
        mock_response.usage_metadata = mock_usage
        mock_response.candidates = [mock_candidate]
        mock_response.text = "Hello from Gemini."

        mock_genai_client = MagicMock()
        mock_genai_client.generate_content.return_value = mock_response

        host = _make_host()
        adapter = GeminiAdapter(model="gemini-2.0-flash", client=mock_genai_client)
        register_adapter(host, adapter)

        result = await host.ainvoke(
            "gemini.generate_content",
            {"contents": "Explain CHP."},
            correlation={"correlation_id": "corr-gemini"},
        )

        self.assertTrue(result.success)

        event_types = [e["event_type"] for e in host.replay("corr-gemini")]
        self.assertIn("model_invocation_started", event_types)
        self.assertIn("model_invocation_completed", event_types)

        completed = next(e for e in host.replay("corr-gemini") if e["event_type"] == "model_invocation_completed")
        self.assertEqual(completed["payload"]["provider"], "google")
        self.assertEqual(completed["payload"]["prompt_tokens"], 8)
        self.assertEqual(completed["payload"]["completion_tokens"], 16)

    async def test_model_invocation_started_contains_prompt_hash(self) -> None:
        mock_response = MagicMock()
        mock_response.usage_metadata.prompt_token_count = 1
        mock_response.usage_metadata.candidates_token_count = 1
        mock_response.candidates = []
        mock_response.text = ""

        mock_client = MagicMock()
        mock_client.generate_content.return_value = mock_response

        host = _make_host()
        adapter = GeminiAdapter(model="gemini-2.0-flash", client=mock_client)
        register_adapter(host, adapter)

        await host.ainvoke(
            "gemini.generate_content",
            {"contents": "Test."},
            correlation={"correlation_id": "corr-hash"},
        )

        started = next(
            e for e in host.replay("corr-hash") if e["event_type"] == "model_invocation_started"
        )
        self.assertIn("prompt_hash", started["payload"])
        self.assertGreater(len(started["payload"]["prompt_hash"]), 0)


if __name__ == "__main__":
    unittest.main()
