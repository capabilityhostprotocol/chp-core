"""chp-adapter-vllm — Apple Silicon native generation as governed CHP capabilities.

Composes to a local vLLM OpenAI-compatible server (the vllm-metal plugin runs
vLLM on Apple Silicon via an MLX/Metal backend). Every HTTP call routes through
chp.adapters.http — the adapter imports no HTTP library.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_vllm import VLLMAdapter, VLLMConfig

    host = LocalCapabilityHost()
    register_adapter(host, VLLMAdapter(VLLMConfig(base_url="http://localhost:8092")))
    result = host.invoke("chp.adapters.vllm.generate", {"prompt": "Hello", "model": "..."})
"""

from __future__ import annotations

from .adapter import VLLMAdapter, VLLMConfig

__all__ = ["VLLMAdapter", "VLLMConfig"]
