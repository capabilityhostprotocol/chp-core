"""chp-adapter-tei — Metal-accelerated text embeddings as governed CHP capabilities.

Wraps a local HuggingFace Text Embeddings Inference (TEI) server. Same capability
shape as chp.adapters.huggingface.embed, but 5–50x faster via a Metal-native
(Apple Silicon) or CUDA backend — a swappable production embeddings substrate.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_tei import TEIAdapter, TEIConfig

    host = LocalCapabilityHost()
    register_adapter(host, TEIAdapter(TEIConfig(base_url="http://localhost:8090")))
    result = host.invoke("chp.adapters.tei.embed", {"inputs": ["hello"]})
"""

from __future__ import annotations

from .adapter import TEIAdapter, TEIConfig

__all__ = ["TEIAdapter", "TEIConfig"]
