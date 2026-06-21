"""SmolagentsAdapter — a governed code-writing meta-agent over CHP capabilities.

Wraps smolagents' CodeAgent as a single CHP capability, ``run``. The agent's
tools are themselves CHP capabilities: each requested capability id is exposed
to the agent as a tool whose invocation routes back through the host router via
``ctx.ainvoke``. This makes CHP an agent that can chain its own governed
capabilities, with a full evidence trail underneath every tool call.

The async bridge: the agent runs synchronously in a worker thread
(``asyncio.to_thread``); when it calls a tool, the tool schedules
``ctx.ainvoke(cap_id, payload)`` back onto the host event loop via
``run_coroutine_threadsafe`` and blocks for the result.

Evidence policy:
  Emitted: task length, tool names exposed, model id, step count, answer length, latency.
  NOT emitted: task text, generated code, tool payloads, or the final answer text.

The adapter imports no smolagents code directly — all of it is isolated in
``_backends.py`` so the adapter stays dependency-light and testable.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "smolagents_run_started",
    "smolagents_tool_invoked",
    "smolagents_run_completed",
    "smolagents_run_failed",
]


def _tool_name(cap_id: str) -> str:
    """Turn a CHP capability id into a clean smolagents tool identifier.

    'chp.adapters.echo.shout' → 'echo_shout' (strip the chp.adapters. prefix).
    """
    short = cap_id
    for prefix in ("chp.adapters.", "chp."):
        if short.startswith(prefix):
            short = short[len(prefix):]
            break
    return short.replace(".", "_").replace("-", "_")


@dataclass
class SmolagentsConfig:
    model_type: str = "openai_server"
    model_id: str = ""
    api_base: str = ""
    api_key: str = ""
    max_steps: int = 6
    tool_timeout: float = 120.0
    allowed_tools: list[str] | None = None  # None → any capability id may be exposed
    _backend: Any = field(default=None, repr=False)

    def resolved_model_id(self) -> str:
        return self.model_id or os.environ.get("SMOLAGENTS_MODEL", "")

    def resolved_api_base(self) -> str:
        return self.api_base or os.environ.get("SMOLAGENTS_API_BASE", "http://localhost:8092/v1")

    def resolved_api_key(self) -> str:
        return self.api_key or os.environ.get("SMOLAGENTS_API_KEY", "EMPTY")


class SmolagentsAdapter(BaseAdapter):
    """Run a smolagents CodeAgent whose tools are governed CHP capabilities."""

    adapter_id = "chp.adapters.smolagents"
    adapter_name = "Smolagents"
    adapter_description = (
        "A code-writing meta-agent (smolagents CodeAgent) whose tools are CHP "
        "capabilities, invoked through the host router with full evidence chains."
    )
    adapter_category = "ai"
    adapter_tags = ["smolagents", "agent", "meta-agent", "tools", "codeagent"]

    def __init__(self, config: SmolagentsConfig | None = None) -> None:
        self._config = config or SmolagentsConfig()

    def _be(self) -> Any:
        if self._config._backend is not None:
            return self._config._backend
        from . import _backends
        return _backends

    def _check_tool_allowed(self, cap_id: str) -> None:
        allowed = self._config.allowed_tools
        if allowed is not None and cap_id not in allowed:
            raise ValueError(f"Capability {cap_id!r} is not in allowed_tools: {allowed}")

    @capability(
        id="chp.adapters.smolagents.run",
        version="1.0.0",
        description=(
            "Run a smolagents CodeAgent on a task, exposing the listed CHP capabilities "
            "as tools. Each tool call routes back through the host router. Task text, "
            "generated code, and the answer are never recorded in evidence."
        ),
        category="ai",
        provider="smolagents",
        risk="high",
        side_effects=["code_execution", "llm_inference"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "task": {"type": "string", "minLength": 1, "description": "The task for the agent to solve"},
                "tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "CHP capability ids to expose to the agent as tools, e.g. ['chp.adapters.huggingface.search_models']",
                },
                "model_id": {"type": "string", "description": "Override the configured model id"},
                "max_steps": {"type": "integer", "minimum": 1, "maximum": 20, "description": "Override the configured max agent steps"},
            },
            "required": ["task"],
            "additionalProperties": False,
        },
    )
    async def run(self, ctx: Any, payload: dict) -> dict:
        task: str = payload["task"]
        tool_ids: list[str] = payload.get("tools") or []
        model_id: str = payload.get("model_id") or self._config.resolved_model_id()
        max_steps: int = payload.get("max_steps") or self._config.max_steps

        if not model_id:
            raise ValueError("No model_id specified and none configured (set SMOLAGENTS_MODEL).")

        for cap_id in tool_ids:
            self._check_tool_allowed(cap_id)

        loop = asyncio.get_running_loop()
        be = self._be()

        def _make_bridge(cap_id: str):
            def _call(payload_obj: Any) -> Any:
                import json as _json
                p = _json.loads(payload_obj) if isinstance(payload_obj, str) else (payload_obj or {})
                ctx.emit("smolagents_tool_invoked", {"tool": cap_id}, redacted=False)
                fut = asyncio.run_coroutine_threadsafe(ctx.ainvoke(cap_id, p), loop)
                res = fut.result(timeout=self._config.tool_timeout)
                if not getattr(res, "success", False):
                    return {"error": getattr(res, "error", "capability failed")}
                return res.data
            return _call

        tools = [
            be.make_tool(
                _tool_name(cap_id),
                f"Invoke CHP capability '{cap_id}'. Call it as {_tool_name(cap_id)}(payload={{...}}) "
                "where payload is the capability's input dict. Returns the capability's result dict.",
                _make_bridge(cap_id),
            )
            for cap_id in tool_ids
        ]

        ctx.emit("smolagents_run_started", {
            "task_length": len(task),
            "tool_names": tool_ids,
            "model_id": model_id,
            "max_steps": max_steps,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            model = be.build_model(
                self._config.model_type, model_id,
                self._config.resolved_api_base(), self._config.resolved_api_key(),
            )
            result = await asyncio.to_thread(be.run_agent, model, tools, task, max_steps)
        except Exception as exc:
            ctx.emit("smolagents_run_failed", {
                "model_id": model_id, "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        answer = result.get("answer", "")
        steps = result.get("steps", 0)
        ctx.emit("smolagents_run_completed", {
            "model_id": model_id,
            "tool_names": tool_ids,
            "steps": steps,
            "answer_length": len(answer),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "answer": answer,
            "tool_names": tool_ids,
            "steps": steps,
            "model_id": model_id,
            "latency_ms": latency_ms,
        }
