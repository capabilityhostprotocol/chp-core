"""chp-adapter-local-llm — local LLM inference as governed CHP capabilities.

Probes Ollama first (GET /api/tags); falls back to any llama.cpp-compatible
OpenAI endpoint (GET /v1/models). Backend can also be pinned via config.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_local_llm import LocalLLMAdapter, LocalLLMConfig

    host = LocalCapabilityHost()
    register_adapter(host, LocalLLMAdapter(LocalLLMConfig()))
    result = host.invoke("chp.adapters.local_llm.list_models", {})
"""

from __future__ import annotations

from .adapter import LocalLLMAdapter, LocalLLMConfig

__all__ = ["LocalLLMAdapter", "LocalLLMConfig"]
