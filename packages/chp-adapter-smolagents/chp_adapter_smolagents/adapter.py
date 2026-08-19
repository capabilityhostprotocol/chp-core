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
    model_cap_id: str = "chp.adapters.local_llm.chat"  # used when model_type == "chp_cap"
    model_timeout: float = 300.0  # a governed model call may warm a cold model; don't cut it short
    max_steps: int = 6
    tool_timeout: float = 120.0
    temperature: float = 0.0  # deterministic agentic completions (tool-calling/reasoning); overridable
    planning_interval: int | None = None  # re-plan every N steps (steadier multi-step orchestration)
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
                "model_type": {"type": "string", "enum": ["chp_cap", "openai_server", "mlx", "transformers"],
                               "description": "Override the model backend for this run — e.g. 'openai_server' + api_base to reach a governed cross-node inference gateway (tools run here, inference on a GPU node)"},
                "api_base": {"type": "string", "description": "OpenAI-compatible base URL for model_type=openai_server (e.g. a chp-home inference gateway on localhost)"},
                "max_steps": {"type": "integer", "minimum": 1, "maximum": 20, "description": "Override the configured max agent steps"},
                "agent_type": {"type": "string", "enum": ["code", "tool"],
                               "description": "code=CodeAgent (Python over tools, needs a capable code model); tool=ToolCallingAgent (JSON tool_calls, reliable with small/local models)"},
                "tool_schemas": {"type": "object",
                                 "description": "optional {cap_id: {input_schema, description}} so each tool gets a typed, scoped signature the model can call (vs an opaque payload object)"},
                "managed_agents": {"type": "array", "items": {"type": "object"},
                                   "description": "specialist sub-agents the manager can delegate to: [{name, description, tools:[cap_ids], agent_type?}] — multi-agent orchestrator-workers"},
                "num_ctx": {"type": "integer", "minimum": 256, "maximum": 262144,
                            "description": "context window for the model's completions (forwarded to the model cap, e.g. local_llm.chat) — raise it when exposing many tools so their schemas don't overflow the default context"},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0,
                                "description": "sampling temperature for the model's agentic completions — default 0 (deterministic tool-calling/reasoning; raise only for creative tasks)"},
                "planning_interval": {"type": "integer", "minimum": 1, "maximum": 20,
                                      "description": "make the agent re-plan every N steps — steadier multi-step / multi-agent orchestration"},
            },
            "required": ["task"],
            "additionalProperties": False,
        },
    )
    async def run(self, ctx: Any, payload: dict) -> dict:
        task: str = payload["task"]
        tool_ids: list[str] = payload.get("tools") or []
        model_id: str = payload.get("model_id") or self._config.resolved_model_id()
        # per-run backend override: point one run at a cross-node inference gateway (openai_server +
        # api_base) without reconfiguring the node's default (usually chp_cap → local_llm.chat).
        model_type: str = payload.get("model_type") or self._config.model_type
        api_base: str = payload.get("api_base") or self._config.resolved_api_base()
        max_steps: int = payload.get("max_steps") or self._config.max_steps
        agent_type: str = payload.get("agent_type") or "code"
        num_ctx = payload.get("num_ctx")   # forwarded to the model cap so many-tool prompts fit
        temperature = payload.get("temperature")
        if temperature is None:
            temperature = self._config.temperature
        planning_interval = payload.get("planning_interval") or self._config.planning_interval

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

        # Scoped tool definitions: the caller supplies each cap's input_schema + description via
        # `tool_schemas` (so the model gets a typed signature, not an opaque payload). The caller
        # already knows the tool list, so it scopes the definitions — conformance-clean (no direct
        # host introspection). Falls back to an opaque payload when a schema isn't supplied.
        tool_schemas: dict[str, Any] = payload.get("tool_schemas") or {}

        def _build_tools(cap_ids: list[str]) -> list:
            built = []
            for cap_id in cap_ids:
                spec = tool_schemas.get(cap_id) or {}
                desc_text = spec.get("description") or (
                    f"Invoke CHP capability '{cap_id}'. Returns the capability's result dict.")
                built.append(be.make_tool(_tool_name(cap_id), desc_text, _make_bridge(cap_id),
                                          spec.get("input_schema")))
            return built

        tools = _build_tools(tool_ids)

        ctx.emit("smolagents_run_started", {
            "task_length": len(task),
            "tool_names": tool_ids,
            "model_id": model_id,
            "max_steps": max_steps,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            if model_type == "chp_cap":
                # Model completions served by a governed CHP capability over the mesh, not a raw URL.
                def _model_invoke(model_payload: dict) -> Any:
                    if num_ctx and isinstance(model_payload, dict):
                        model_payload.setdefault("num_ctx", num_ctx)   # thread ctx to local_llm.chat
                    fut = asyncio.run_coroutine_threadsafe(
                        ctx.ainvoke(self._config.model_cap_id, model_payload), loop)
                    res = fut.result(timeout=self._config.model_timeout)
                    if not getattr(res, "success", False):
                        raise RuntimeError(getattr(res, "error", "model capability failed"))
                    return res.data
                model = be.make_chp_model(model_id, _model_invoke, temperature=temperature)
            else:
                model = be.build_model(
                    model_type, model_id,
                    api_base, self._config.resolved_api_key(),
                )
            # Multi-agent delegation: build each managed sub-agent (its own scoped tools + name +
            # description) so the manager can delegate subtasks to it by name (orchestrator-workers).
            managed_agents = []
            for sub in (payload.get("managed_agents") or []):
                managed_agents.append(be.build_agent(
                    model, _build_tools(sub.get("tools") or []),
                    sub.get("agent_type", "tool"), max_steps,
                    name=sub["name"], description=sub["description"]))
            result = await asyncio.to_thread(be.run_agent, model, tools, task, max_steps,
                                             agent_type, managed_agents or None, planning_interval)
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
