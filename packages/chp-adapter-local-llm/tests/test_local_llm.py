"""Tests for chp-adapter-local-llm using a fake backend — no Ollama required."""

from __future__ import annotations

from typing import Any

import pytest

from chp_adapter_local_llm import LocalLLMAdapter, LocalLLMConfig
from chp_adapter_local_llm.adapter import _normalize_model_entry, _normalize_model_info
from chp_core import LocalCapabilityHost, register_adapter


# ---------------------------------------------------------------------------
# Fake backend
# ---------------------------------------------------------------------------

class FakeBackend:
    def __init__(self):
        self._models = [
            {"name": "llama3.2:latest", "size": 2_000_000_000, "modified_at": "2025-01-01T00:00:00Z"},
            {"name": "mistral:7b", "size": 4_000_000_000, "modified_at": "2025-01-02T00:00:00Z"},
        ]

    async def list_models(self) -> list[dict[str, Any]]:
        return list(self._models)

    async def model_info(self, model: str) -> dict[str, Any]:
        return {
            "details": {
                "parameter_size": "3.2B",
                "quantization_level": "Q4_K_M",
                "family": "llama",
            },
            "model_info": {"llama.context_length": 131072},
        }

    async def generate(self, model: str, prompt: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "response": f"echo: {prompt[:20]}",
            "prompt_eval_count": len(prompt.split()),
            "eval_count": 5,
        }

    async def chat(self, model: str, messages: list[dict], **kwargs: Any) -> dict[str, Any]:
        last = messages[-1].get("content", "")
        return {
            "message": {"role": "assistant", "content": f"reply: {last[:20]}"},
            "prompt_eval_count": 10,
            "eval_count": 8,
        }


def _host_with_fake() -> tuple[LocalCapabilityHost, FakeBackend]:
    fake = FakeBackend()
    config = LocalLLMConfig(_backend=fake)
    adapter = LocalLLMAdapter(config)
    host = LocalCapabilityHost()
    register_adapter(host, adapter)
    return host, fake


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------

def test_list_models_returns_models():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.list_models", {})
    assert result.success
    data = result.data
    assert data["backend"] == "injected"
    assert len(data["models"]) == 2
    assert data["models"][0]["name"] == "llama3.2:latest"


def test_list_models_evidence_recorded():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.list_models", {})
    assert result.success
    assert result.evidence_ids


# ---------------------------------------------------------------------------
# model_info
# ---------------------------------------------------------------------------

def test_model_info_returns_info():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.model_info", {"model": "llama3.2:latest"})
    assert result.success
    data = result.data
    assert data["model"] == "llama3.2:latest"
    assert isinstance(data["info"], dict)


def test_model_info_allowed_list_blocks_disallowed():
    fake = FakeBackend()
    config = LocalLLMConfig(_backend=fake, allowed_models=["llama3.2:latest"])
    host = LocalCapabilityHost()
    register_adapter(host, LocalLLMAdapter(config))
    result = host.invoke("chp.adapters.local_llm.model_info", {"model": "mistral:7b"})
    assert not result.success
    assert result.error or result.denial


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

def test_generate_returns_text():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.generate", {"prompt": "hello world"})
    assert result.success
    data = result.data
    assert "text" in data
    assert data["prompt_tokens"] > 0
    assert data["completion_tokens"] == 5
    assert data["latency_ms"] >= 0


def test_generate_prompt_not_in_evidence():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.generate", {"prompt": "SECRET_PROMPT_XYZ"})
    assert result.success
    # Prompt text must not appear in the replay record (evidence chain)
    replay = host.replay_result(result.invocation_id)
    replay_str = str(replay.to_dict())
    assert "SECRET_PROMPT_XYZ" not in replay_str


def test_generate_with_options():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.generate", {
        "prompt": "test", "temperature": 0.5, "max_tokens": 100,
    })
    assert result.success


# ---------------------------------------------------------------------------
# chat
# ---------------------------------------------------------------------------

def test_chat_returns_message():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.chat", {
        "messages": [{"role": "user", "content": "hello"}],
    })
    assert result.success
    data = result.data
    assert data["message"]["role"] == "assistant"
    assert data["prompt_tokens"] == 10
    assert data["completion_tokens"] == 8


def test_chat_messages_not_in_evidence():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.chat", {
        "messages": [{"role": "user", "content": "SECRET_CHAT_CONTENT"}],
    })
    assert result.success
    replay = host.replay_result(result.invocation_id)
    assert "SECRET_CHAT_CONTENT" not in str(replay.to_dict())


def test_chat_multi_turn():
    host, fake = _host_with_fake()
    result = host.invoke("chp.adapters.local_llm.chat", {
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is 2+2?"},
            {"role": "assistant", "content": "4"},
            {"role": "user", "content": "And 3+3?"},
        ],
    })
    assert result.success


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def test_normalize_model_entry_ollama():
    raw = {"name": "llama3.2:latest", "size": 2_000_000_000, "modified_at": "2025-01-01"}
    out = _normalize_model_entry(raw, "ollama")
    assert out["name"] == "llama3.2:latest"
    assert out["size_bytes"] == 2_000_000_000


def test_normalize_model_entry_llama_cpp():
    raw = {"id": "mistral-7b", "object": "model"}
    out = _normalize_model_entry(raw, "llama_cpp")
    assert out["name"] == "mistral-7b"
    assert out["size_bytes"] is None


def test_normalize_model_info_ollama():
    raw = {
        "details": {"parameter_size": "7B", "quantization_level": "Q8_0", "family": "mistral"},
        "model_info": {"llama.context_length": 8192},
    }
    out = _normalize_model_info(raw, "ollama")
    assert out["parameter_size"] == "7B"
    assert out["context_length"] == 8192
