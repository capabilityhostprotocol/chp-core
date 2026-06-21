"""chp-adapter-smolagents — a governed code-writing meta-agent over CHP capabilities.

Wraps smolagents' CodeAgent as the CHP capability ``chp.adapters.smolagents.run``.
The agent's tools are CHP capabilities themselves: each tool call routes back
through the host router (``ctx.ainvoke``) with a full evidence chain. smolagents
is isolated in ``_backends.py``; the adapter imports it indirectly.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_smolagents import SmolagentsAdapter, SmolagentsConfig

    host = LocalCapabilityHost()
    register_adapter(host, SmolagentsAdapter(SmolagentsConfig(model_id="...")))
    result = host.invoke("chp.adapters.smolagents.run", {
        "task": "Find the most downloaded text-generation model.",
        "tools": ["chp.adapters.huggingface.search_models"],
    })
"""

from __future__ import annotations

from .adapter import SmolagentsAdapter, SmolagentsConfig

__all__ = ["SmolagentsAdapter", "SmolagentsConfig"]
