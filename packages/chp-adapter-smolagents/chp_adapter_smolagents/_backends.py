"""smolagents backend — the only file that imports smolagents.

Isolated here so adapter.py stays free of the smolagents dependency and can be
unit-tested with an injected fake backend (no LLM, no agent execution).

The adapter supplies plain sync callables (each bridging to a CHP capability via
the host router); this module wraps them as smolagents Tools, builds the model,
and runs a CodeAgent.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable


def _tool_calls_from_content(content: str) -> list[dict]:
    """Best-effort: extract tool calls a model emitted as TEXT in its content (instead of the
    structured tool_calls channel). Handles OpenAI-nested ({"function": {"name","arguments"}}) and
    flat ({"name","arguments"}) JSON objects; dedupes repeats. Returns [{name, arguments}, ...]."""
    if not content:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    # match brace-balanced JSON objects up to one level of nesting (covers the tool-call shapes)
    for m in re.finditer(r"\{(?:[^{}]|\{[^{}]*\})*\}", content):
        try:
            obj = json.loads(m.group(0))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(obj, dict):
            continue
        fn = obj.get("function") if isinstance(obj.get("function"), dict) else obj
        name = fn.get("name") if isinstance(fn, dict) else None
        if not name:
            continue
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:  # noqa: BLE001
                pass
        key = name + json.dumps(args, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "arguments": args if args is not None else {}})
    return out


# JSON-schema types → the set smolagents accepts for Tool.inputs.
_JSON_TO_SMOL = {"string": "string", "integer": "integer", "number": "number",
                 "boolean": "boolean", "array": "array", "object": "object", "null": "null"}


def make_tool(name: str, description: str, func: Callable[[dict], Any],
              input_schema: dict | None = None) -> Any:
    """Wrap a CHP capability as a smolagents Tool. When the cap's ``input_schema`` is given, expose
    its ``properties`` as TYPED, described inputs (a scoped signature the model can actually call —
    ``memory_set(key, value)`` not ``memory_set(payload=<object>)``); non-``required`` props are
    marked nullable. ``forward(**kwargs)`` assembles the payload dict for the bridge. With no schema
    it falls back to a single opaque ``payload`` object."""
    from smolagents import Tool

    class _CHPTool(Tool):
        # smolagents reads these as class attributes
        pass

    tool = _CHPTool.__new__(_CHPTool)
    tool.name = name
    tool.description = description
    props = (input_schema or {}).get("properties") or {}
    required = set((input_schema or {}).get("required") or [])
    if props:
        inputs: dict[str, Any] = {}
        for key, spec in props.items():
            spec = spec or {}
            jtype = spec.get("type")
            if isinstance(jtype, list):                       # e.g. ["string", "null"]
                jtype = next((t for t in jtype if t != "null"), "any")
            entry = {"type": _JSON_TO_SMOL.get(jtype, "any"),
                     "description": spec.get("description", key)}
            if key not in required:
                entry["nullable"] = True                      # smolagents: optional input
            inputs[key] = entry
        tool.inputs = inputs
        tool.forward = lambda **kw: func({k: v for k, v in kw.items() if v is not None})
    elif input_schema is not None:
        # DECLARED but empty (a no-arg cap, e.g. system.resource.usage / home.node.logs). Expose a real
        # NO-ARG tool — not an opaque payload:object, which some models 400 on when a tool set is all-opaque.
        tool.inputs = {}
        tool.forward = lambda: func({})  # type: ignore[assignment]
    else:
        # UNKNOWN schema → one opaque payload object (the model passes a free-form JSON payload).
        tool.inputs = {"payload": {"type": "object",
                       "description": "JSON object passed as the CHP capability payload."}}
        tool.forward = lambda payload: func(payload)  # type: ignore[assignment]
    tool.output_type = "object"
    tool.is_initialized = True
    return tool


def build_model(model_type: str, model_id: str, api_base: str, api_key: str) -> Any:
    """Construct a smolagents model from config."""
    if model_type == "openai_server":
        from smolagents import OpenAIServerModel

        return OpenAIServerModel(model_id=model_id, api_base=api_base, api_key=api_key or "EMPTY")
    if model_type == "mlx":
        from smolagents import MLXModel

        return MLXModel(model_id=model_id)
    if model_type == "transformers":
        from smolagents import TransformersModel

        return TransformersModel(model_id=model_id)
    raise ValueError(f"Unknown model_type: {model_type!r}. Use 'openai_server', 'mlx', or 'transformers'.")


def make_chp_model(model_id: str, invoke: Callable[[dict], dict], *,
                   temperature: float | None = None) -> Any:
    """A smolagents Model whose completions are served by a CHP capability (e.g.
    ``chp.adapters.local_llm.chat``) invoked through the host router, instead of a raw
    OpenAI ``/v1`` endpoint. Every model call is then governed + evidenced, and can target
    any node over the mesh — so the memory-heavy model runs on a headroom host while the
    orchestrator stays central.

    ``invoke(payload) -> chat-cap result dict`` is a sync bridge the adapter supplies (it
    schedules ``ctx.ainvoke`` onto the host loop). Message/tool normalization reuses
    smolagents' own ``_prepare_completion_kwargs`` so we send exactly what OpenAIServerModel
    would; the cap applies its safe num_ctx / keep_alive / think-off defaults.
    """
    from smolagents.models import (
        ChatMessage,
        ChatMessageToolCall,
        ChatMessageToolCallFunction,
        MessageRole,
        Model,
    )

    class _CHPCapModel(Model):
        def __init__(self) -> None:
            super().__init__()
            self.model_id = model_id

        def generate(self, messages, stop_sequences=None, response_format=None,
                     tools_to_call_from=None, **kwargs):
            ck = self._prepare_completion_kwargs(
                messages=messages,
                stop_sequences=stop_sequences,
                response_format=response_format,
                tools_to_call_from=tools_to_call_from,
                model=self.model_id,
            )
            # local_llm.chat wants content as a plain string; smolagents emits it as a list of
            # content parts (OpenAI multimodal shape) — flatten to text. Only forward keys the
            # cap's schema accepts (additionalProperties: False).
            def _flatten(content: Any) -> str:
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    return "".join(p.get("text", "") for p in content if isinstance(p, dict))
                return "" if content is None else str(content)

            messages = [{"role": m["role"], "content": _flatten(m.get("content"))}
                        for m in ck["messages"]]
            payload: dict[str, Any] = {"model": self.model_id, "messages": messages}
            if ck.get("tools"):
                payload["tools"] = ck["tools"]
            if temperature is not None:   # deterministic agentic completions (tool-calling/reasoning)
                payload["temperature"] = temperature
            res = invoke(payload) or {}
            msg = res.get("message", {}) or {}
            raw_calls = msg.get("tool_calls") or res.get("tool_calls") or []
            if not raw_calls:  # model emitted the call as text in content — parse it out
                raw_calls = [{"function": c} for c in _tool_calls_from_content(msg.get("content") or "")]
            tool_calls = [
                ChatMessageToolCall(
                    id=tc.get("id") or f"call_{i}",
                    type="function",
                    function=ChatMessageToolCallFunction(
                        name=(tc.get("function", {}) or {}).get("name", ""),
                        arguments=(tc.get("function", {}) or {}).get("arguments"),
                    ),
                )
                for i, tc in enumerate(raw_calls)
            ] or None
            return ChatMessage(
                role=MessageRole.ASSISTANT,
                content=msg.get("content") or "",
                tool_calls=tool_calls,
                raw=res,
            )

    return _CHPCapModel()


def build_agent(model: Any, tools: list[Any], agent_type: str = "code", max_steps: int = 6,
                *, name: str | None = None, description: str | None = None,
                managed_agents: list[Any] | None = None, planning_interval: int | None = None) -> Any:
    """Construct a smolagents agent. agent_type selects the action channel: 'code' → CodeAgent
    (writes Python over the tools), 'tool' → ToolCallingAgent (JSON tool_calls, reliable with small
    models). name/description make it delegatable as a managed sub-agent; managed_agents are the
    specialist sub-agents this (manager) agent may delegate to; planning_interval makes it re-plan
    every N steps (steadier multi-step orchestration)."""
    kwargs: dict[str, Any] = {"tools": tools, "model": model, "max_steps": max_steps}
    if name:
        kwargs["name"] = name
    if description:
        kwargs["description"] = description
    if managed_agents:
        kwargs["managed_agents"] = managed_agents
    if planning_interval:
        kwargs["planning_interval"] = planning_interval
    if agent_type == "tool":
        from smolagents import ToolCallingAgent
        return ToolCallingAgent(**kwargs)
    from smolagents import CodeAgent
    return CodeAgent(**kwargs)


def run_agent(model: Any, tools: list[Any], task: str, max_steps: int,
              agent_type: str = "code", managed_agents: list[Any] | None = None,
              planning_interval: int | None = None) -> dict:
    """Build the (manager) agent and run the task; returns answer + step count."""
    agent = build_agent(model, tools, agent_type, max_steps, managed_agents=managed_agents,
                        planning_interval=planning_interval)
    answer = agent.run(task)

    steps = 0
    try:
        steps = len([s for s in agent.memory.steps if type(s).__name__ == "ActionStep"])
    except Exception:
        steps = 0

    return {"answer": str(answer), "steps": steps}
