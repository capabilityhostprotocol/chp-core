"""chp-adapter-mlx — Apple Silicon native generation as governed CHP capabilities.

Composes to a local ``mlx_lm.server`` (Apple's MLX framework — the fastest local
inference path on Apple Silicon). The server is OpenAI-compatible, so the wire
shape matches the vLLM/local_llm adapters and the gateway routes MLX as another
inference owner. Every HTTP call routes through chp.adapters.http — the adapter
imports no HTTP library.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_mlx import MLXAdapter, MLXConfig

    host = LocalCapabilityHost()
    register_adapter(host, MLXAdapter(MLXConfig(base_url="http://localhost:8081")))
    result = host.invoke("chp.adapters.mlx.status", {})  # is MLX installed + serving?
"""

from __future__ import annotations

from .adapter import MLXAdapter, MLXConfig

__all__ = ["MLXAdapter", "MLXConfig"]
