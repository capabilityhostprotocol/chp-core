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
                "model_cap_id": {"type": "string",
                                 "description": "per-run model chat cap for model_type=chp_cap (e.g. "
                                                "chp.adapters.freetoken.chat) — overrides the adapter default"},
                "model_max_tokens": {"type": "integer", "minimum": 256, "maximum": 32768,
                                     "description": "per-step completion budget for model_type=chp_cap (reasoning "
                                                    "models need headroom for analysis + tool_calls; defaults to a "
                                                    "roomy value for freetoken, retried with 2x on an empty length turn)"},
                "model_reasoning_effort": {"type": "string", "enum": ["minimal", "low", "medium", "high"],
                                           "description": "reasoning budget for a gpt-oss/harmony chp_cap model; "
                                                          "defaults to 'low' for freetoken (decisive tool-calling), "
                                                          "overridable per run (None = server default)"},
                "api_base": {"type": "string", "description": "OpenAI-compatible base URL for model_type=openai_server (e.g. a chp-home inference gateway on localhost)"},
                "max_steps": {"type": "integer", "minimum": 1, "maximum": 20, "description": "Override the configured max agent steps"},
                "agent_type": {"type": "string", "enum": ["code", "tool"],
                               "description": "code=CodeAgent (Python over tools, needs a capable code model); tool=ToolCallingAgent (JSON tool_calls, reliable with small/local models — and runs a step's independent tool calls IN PARALLEL)"},
                "max_tool_threads": {"type": "integer", "minimum": 1, "maximum": 64,
                                     "description": "agent_type=tool: cap the parallel tool-call thread pool (a step's independent tool calls run concurrently). Default = the library's pool size."},
                "tool_schemas": {"type": "object",
                                 "description": "optional {cap_id: {input_schema, description}} so each tool gets a typed, scoped signature the model can call (vs an opaque payload object)"},
                "tool_routes": {"type": "object",
                                "description": "optional {cap_id: remote_base_url} — CROSS-NODE tools: a "
                                               "routed cap is invoked on that remote CHP host via "
                                               "chp.adapters.host.invoke (governed federated invocation), "
                                               "so the agent's model (here) can drive a capability on "
                                               "another node. Un-routed caps invoke locally."},
                "tool_route_api_key": {"type": "string",
                                       "description": "bearer token for the routed remote host(s), if required"},
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
        max_tool_threads = payload.get("max_tool_threads")   # agent_type=tool: parallel tool-call pool cap

        if not model_id:
            raise ValueError("No model_id specified and none configured (set SMOLAGENTS_MODEL).")

        for cap_id in tool_ids:
            self._check_tool_allowed(cap_id)

        loop = asyncio.get_running_loop()
        be = self._be()

        # CROSS-NODE agent capabilities: `tool_routes` maps a cap_id -> the remote CHP host's base_url.
        # A routed tool call goes through chp.adapters.host.invoke (governed federated HTTP invocation) so
        # an agent whose MODEL runs on node A can drive a CAPABILITY that lives on node B. Un-routed caps
        # invoke locally via ctx.ainvoke as before.
        tool_routes: dict[str, str] = payload.get("tool_routes") or {}
        route_api_key = payload.get("tool_route_api_key")

        def _make_bridge(cap_id: str):
            base_url = tool_routes.get(cap_id)

            def _call(payload_obj: Any) -> Any:
                import json as _json
                p = _json.loads(payload_obj) if isinstance(payload_obj, str) else (payload_obj or {})
                ctx.emit("smolagents_tool_invoked", {"tool": cap_id, "remote": bool(base_url)}, redacted=False)
                if base_url:   # cross-node: route through the host adapter's federated invoke
                    hp: dict[str, Any] = {"base_url": base_url, "capability_id": cap_id, "payload": p}
                    if route_api_key:
                        hp["api_key"] = route_api_key
                    fut = asyncio.run_coroutine_threadsafe(ctx.ainvoke("chp.adapters.host.invoke", hp), loop)
                    res = fut.result(timeout=self._config.tool_timeout)
                    if not getattr(res, "success", False):
                        return {"error": getattr(res, "error", "cross-node host.invoke failed")}
                    d = res.data or {}
                    if d.get("outcome") != "completed":
                        return {"error": d.get("error") or f"remote capability {d.get('outcome')}"}
                    return d.get("data")
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
                mcap = payload.get("model_cap_id") or self._config.model_cap_id

                def _model_invoke(model_payload: dict) -> Any:
                    # num_ctx is an ollama concept: ONLY local_llm.chat accepts it. freetoken.chat / mlx.chat
                    # declare additionalProperties:false, so injecting num_ctx makes them reject the whole
                    # payload (schema-violation → denied). Thread it only to the cap that takes it.
                    if num_ctx and "local_llm" in mcap and isinstance(model_payload, dict):
                        model_payload.setdefault("num_ctx", num_ctx)
                    last_err = ""
                    # A sovereign model on the mesh can fail transiently (cold load / brief 503 / concurrent
                    # queue), which would otherwise kill the whole agent step. Retry the model call ONCE, and
                    # surface a LEGIBLE reason (status + outcome) instead of a bare RuntimeError(None) when the
                    # cap returns success=False with no error string.
                    for attempt in range(2):
                        fut = asyncio.run_coroutine_threadsafe(ctx.ainvoke(mcap, model_payload), loop)
                        res = fut.result(timeout=self._config.model_timeout)
                        if getattr(res, "success", False):
                            return res.data
                        _den = getattr(res, "denial", None)
                        _dcode = getattr(_den, "code", None)
                        _dmsg = getattr(_den, "message", None)
                        last_err = (getattr(res, "error", None) or _dmsg
                                    or (f"{mcap} denied [{_dcode}]" if _dcode else None)
                                    or f"{mcap} returned {getattr(res, 'outcome', 'failure')!r} (no detail)")
                    raise RuntimeError(last_err)
                _mcap = payload.get("model_cap_id") or self._config.model_cap_id
                _is_ft = "freetoken" in _mcap
                # ft serve / gpt-oss won't emit tool_calls without tool_choice; freetoken.chat accepts it
                # (local_llm.chat's schema does not), so only nudge when the cap supports it.
                _tc = "auto" if _is_ft else None
                # Reasoning models (gpt-oss) spend the completion budget on analysis before content/tool_calls;
                # the cap's small default (2048) starves the loop. gpt-oss-20b serves at 32k ctx, so give a
                # roomy default (per-run overridable) — make_chp_model also retries with 2x headroom on an
                # empty finish_reason=length turn.
                _mt = payload.get("model_max_tokens") or (8192 if _is_ft else None)
                # gpt-oss over-reasons in a tool loop (repeats a tool / burns the budget); 'low' keeps it
                # decisive. Default low for freetoken agentic runs; per-run overridable (None = server default).
                _re = payload.get("model_reasoning_effort") or ("low" if _is_ft else None)
                model = be.make_chp_model(model_id, _model_invoke, temperature=temperature,
                                          tool_choice=_tc, max_tokens=_mt, reasoning_effort=_re)
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
                                             agent_type, managed_agents or None, planning_interval,
                                             max_tool_threads)
        except Exception as exc:
            ctx.emit("smolagents_run_failed", {
                "model_id": model_id, "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        answer = result.get("answer", "")
        steps = result.get("steps", 0)
        calls = result.get("calls", [])            # tool / sub-agent names the manager actually invoked
        managed = [sub["name"] for sub in (payload.get("managed_agents") or [])]   # the worker roster
        ctx.emit("smolagents_run_completed", {
            "model_id": model_id,
            "tool_names": tool_ids,
            "calls": calls,
            "managed": managed,
            "steps": steps,
            "answer_length": len(answer),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "answer": answer,
            "tool_names": tool_ids,
            "calls": calls,
            "managed": managed,
            "steps": steps,
            "model_id": model_id,
            "latency_ms": latency_ms,
        }
