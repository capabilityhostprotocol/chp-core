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


def _resolve_tool_name(name: str, known: list[str] | None) -> str:
    """Map a name a model emitted (e.g. harmony's ``commercial.assess_fit``, or the task-text short form)
    to an actually-registered tool name (e.g. ``agency_commercial_assess_fit``). Exact first, then a
    normalized (alnum-only) suffix/substring match when it's unambiguous; else the name is passed through."""
    if not known or name in known:
        return name
    norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
    n = norm(name)
    for k in known:                                   # exact match ignoring separators/case
        if norm(k) == n:
            return k
    cand = [k for k in known if norm(k).endswith(n) or n.endswith(norm(k))]
    if len(cand) == 1:
        return cand[0]
    cand = [k for k in known if n and (n in norm(k) or norm(k) in n)]
    return cand[0] if len(cand) == 1 else name


def _tool_calls_from_content(content: str, known_names: list[str] | None = None) -> list[dict]:
    """Best-effort: extract tool calls a model emitted as TEXT in its content instead of the structured
    tool_calls channel. Covers (1) gpt-oss HARMONY syntax that ft serve's parser sometimes leaks verbatim
    — ``...to=functions.NAME...<|message|>{args}`` — where the name lives in the marker, not the JSON; and
    (2) OpenAI-nested ({"function":{"name","arguments"}}) / flat ({"name","arguments"}) JSON objects.
    Names are resolved against ``known_names`` (the registered tools). Dedupes. Returns [{name,arguments}]."""
    if not content:
        return []
    out: list[dict] = []
    seen: set[str] = set()

    def _add(name: str, args: Any) -> None:
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:  # noqa: BLE001
                pass
        name = _resolve_tool_name(name, known_names)
        key = name + json.dumps(args, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            out.append({"name": name, "arguments": args if args is not None else {}})

    # (1) harmony tool-call channel: the function name is in `to=functions.NAME`, args after `<|message|>`
    for m in re.finditer(r"to=functions\.([A-Za-z0-9_.\-]+)", content):
        mm = re.search(r"<\|message\|>\s*(\{(?:[^{}]|\{[^{}]*\})*\})", content[m.end():])
        if mm:
            try:
                _add(m.group(1), json.loads(mm.group(1)))
            except Exception:  # noqa: BLE001
                pass
    # (2) bare JSON objects carrying their own name (OpenAI-nested or flat)
    for m in re.finditer(r"\{(?:[^{}]|\{[^{}]*\})*\}", content):
        try:
            obj = json.loads(m.group(0))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(obj, dict):
            continue
        fn = obj.get("function") if isinstance(obj.get("function"), dict) else obj
        name = fn.get("name") if isinstance(fn, dict) else None
        if name:
            _add(name, fn.get("arguments"))
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
                   temperature: float | None = None, tool_choice: str | None = None,
                   max_tokens: int | None = None, reasoning_effort: str | None = None) -> Any:
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
                # nudge tool-calling: without tool_choice some servers (ft serve / gpt-oss) default to a
                # prose/reasoning turn and never emit tool_calls. Only sent when the model cap accepts it
                # (e.g. freetoken.chat) — local_llm.chat's schema forbids it, so the caller opts in.
                if tool_choice:
                    payload["tool_choice"] = tool_choice
            if temperature is not None:   # deterministic agentic completions (tool-calling/reasoning)
                payload["temperature"] = temperature
            if max_tokens is not None:
                # reasoning models (gpt-oss via ft serve) spend the completion budget on an analysis
                # channel BEFORE the content/tool_calls; the cap's small default (2048) can be exhausted
                # by reasoning alone, yielding finish_reason:length with empty content + no tool_calls —
                # which the agent loop sees as "failed to generate output". Give the loop headroom.
                payload["max_tokens"] = max_tokens
            if reasoning_effort is not None:
                # keep a reasoning model DECISIVE in the tool loop: 'low' stops gpt-oss over-reasoning
                # (which exhausts the budget or repeats a tool instead of advancing). Cap forwards it iff supported.
                payload["reasoning_effort"] = reasoning_effort
            # registered tool names — used to resolve a name a leaked/harmony tool-call emitted (which may
            # be the short/task-text form) back to the actually-registered tool.
            known = [n for n in (getattr(t, "name", None) for t in (tools_to_call_from or [])) if n]
            res = invoke(payload) or {}

            def _is_empty(r: dict) -> bool:
                m = r.get("message", {}) or {}
                return not (m.get("content") or m.get("tool_calls") or r.get("tool_calls")
                            or _tool_calls_from_content((m.get("content") or ""), known))

            # Reasoning-overflow recovery: a reasoning model can spend the whole completion budget on its
            # analysis channel and return finish_reason='length' with NO content and NO tool_calls — which
            # the agent loop reports as the opaque "failed to generate output". Retry ONCE with doubled
            # headroom (bounded) before giving up.
            if _is_empty(res) and res.get("finish_reason") == "length" and payload.get("max_tokens"):
                payload = {**payload, "max_tokens": min(int(payload["max_tokens"]) * 2, 32768)}
                res = invoke(payload) or {}
            msg = res.get("message", {}) or {}
            raw_calls = msg.get("tool_calls") or res.get("tool_calls") or []
            from_content = False
            if not raw_calls:  # model emitted the call as text in content — parse it out
                raw_calls = [{"function": c} for c in _tool_calls_from_content(msg.get("content") or "", known)]
                from_content = bool(raw_calls)
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
            content = "" if from_content else (msg.get("content") or "")  # drop the raw harmony/JSON we parsed
            if not content and not tool_calls:
                # Still nothing after the headroom retry — surface WHY (finish_reason + token counts) as
                # legible content instead of a blank turn the loop reports as "failed to generate output".
                content = (f"[no model output: finish_reason={res.get('finish_reason')!r}, "
                           f"completion_tokens={res.get('completion_tokens')}; the completion budget "
                           f"may be too small for this model's reasoning — raise max_tokens]")
            return ChatMessage(
                role=MessageRole.ASSISTANT,
                content=content,
                tool_calls=tool_calls,
                raw=res,
            )

    return _CHPCapModel()


def build_agent(model: Any, tools: list[Any], agent_type: str = "code", max_steps: int = 6,
                *, name: str | None = None, description: str | None = None,
                managed_agents: list[Any] | None = None, planning_interval: int | None = None,
                max_tool_threads: int | None = None) -> Any:
    """Construct a smolagents agent. agent_type selects the action channel: 'code' → CodeAgent
    (writes Python over the tools), 'tool' → ToolCallingAgent (JSON tool_calls, reliable with small
    models — and it runs a step's independent tool calls CONCURRENTLY on a thread pool). name/description
    make it delegatable as a managed sub-agent; managed_agents are the specialist sub-agents this
    (manager) agent may delegate to; planning_interval makes it re-plan every N steps (steadier multi-step
    orchestration); max_tool_threads caps that parallel tool-call pool (ToolCallingAgent only)."""
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
        if max_tool_threads:                          # bound the parallel tool-call pool (else the library default)
            kwargs["max_tool_threads"] = max_tool_threads
        return ToolCallingAgent(**kwargs)
    from smolagents import CodeAgent
    return CodeAgent(**kwargs)


def run_agent(model: Any, tools: list[Any], task: str, max_steps: int,
              agent_type: str = "code", managed_agents: list[Any] | None = None,
              planning_interval: int | None = None, max_tool_threads: int | None = None) -> dict:
    """Build the (manager) agent and run the task; returns answer + step count + the delegation trace.

    ``calls`` is the ordered list of tool / managed-sub-agent names the manager actually invoked (a
    managed agent is called by name, like a tool) — so a swarm run is no longer opaque (a pure manager
    has no direct tools, so ``tool_names`` is empty and only ``calls`` shows what ran)."""
    agent = build_agent(model, tools, agent_type, max_steps, managed_agents=managed_agents,
                        planning_interval=planning_interval, max_tool_threads=max_tool_threads)
    answer = agent.run(task)

    steps, calls = 0, []
    try:
        action_steps = [s for s in agent.memory.steps if type(s).__name__ == "ActionStep"]
        steps = len(action_steps)
        for s in action_steps:                              # smolagents records each ToolCall(name=…)
            for tc in (getattr(s, "tool_calls", None) or []):
                name = getattr(tc, "name", None)
                if name:
                    calls.append(name)
    except Exception:
        steps, calls = steps, calls

    return {"answer": str(answer), "steps": steps, "calls": calls}
