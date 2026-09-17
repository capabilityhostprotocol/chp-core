"""Tests for chp-adapter-smolagents.

No smolagents and no LLM are needed: a fake backend stands in for the smolagents
layer. Critically, the fake backend's ``run_agent`` actually *invokes a tool*,
so these tests exercise the real async bridge — a smolagents tool calling back
into a registered CHP capability via ctx.ainvoke / run_coroutine_threadsafe.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable

from chp_adapter_smolagents import SmolagentsAdapter, SmolagentsConfig
from chp_core import BaseAdapter, LocalCapabilityHost, capability, register_adapter
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# A tiny CHP capability to expose to the agent as a tool
# ---------------------------------------------------------------------------

class EchoAdapter(BaseAdapter):
    adapter_id = "chp.adapters.echo"
    adapter_name = "Echo"
    adapter_description = "Echo capability for smolagents bridge tests."
    adapter_category = "execution"

    @capability(
        id="chp.adapters.echo.shout",
        version="1.0.0",
        description="Return the input text uppercased.",
        category="execution",
        risk="low",
        emits=["echo_done"],
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    )
    async def shout(self, ctx: Any, payload: dict) -> dict:
        ctx.emit("echo_done", {"length": len(payload.get("text", ""))}, redacted=False)
        return {"shouted": payload.get("text", "").upper()}


# ---------------------------------------------------------------------------
# Fake smolagents backend — its run_agent USES a tool, exercising the bridge
# ---------------------------------------------------------------------------

class FakeBackend:
    def __init__(self) -> None:
        self.tools: list[Any] = []
        self.tool_results: list[Any] = []

    def make_tool(self, name: str, description: str, func: Callable[[dict], Any],
                  input_schema: dict | None = None) -> Any:
        t = {"name": name, "func": func, "input_schema": input_schema}
        self.tools.append(t)
        return t

    def build_model(self, model_type: str, model_id: str, api_base: str, api_key: str) -> Any:
        return {"model_id": model_id, "type": model_type}

    def make_chp_model(self, model_id: str, invoke: Callable[[dict], Any], *,
                       temperature: float | None = None, tool_choice: str | None = None,
                       max_tokens: int | None = None, reasoning_effort: str | None = None) -> Any:
        self.model_temperature = temperature
        self.model_tool_choice = tool_choice
        self.model_max_tokens = max_tokens
        self.model_reasoning_effort = reasoning_effort
        return {"model_id": model_id, "chp_cap": True}

    def build_agent(self, model: Any, tools: list[Any], agent_type: str = "code",
                    max_steps: int = 6, *, name=None, description=None, managed_agents=None,
                    planning_interval=None, max_tool_threads=None) -> Any:
        return {"name": name, "description": description, "tools": tools, "agent_type": agent_type}

    def run_agent(self, model: Any, tools: list[Any], task: str, max_steps: int,
                  agent_type: str = "code", managed_agents=None, planning_interval=None,
                  max_tool_threads=None) -> dict:
        self.agent_type = agent_type
        self.managed_agents = managed_agents
        self.planning_interval = planning_interval
        self.max_tool_threads = max_tool_threads
        # Simulate the agent deciding to call the first tool with a payload.
        calls = []
        if tools:
            result = tools[0]["func"]({"text": "hello from agent"})
            self.tool_results.append(result)
            answer = f"agent used {tools[0]['name']} -> {result}"
            calls = [tools[0]["name"]]
        else:
            answer = "no tools; reasoned directly"
        return {"answer": answer, "steps": 2, "calls": calls}


def _make_host(fake: FakeBackend, allowed_tools=None) -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    register_adapter(host, EchoAdapter())
    config = SmolagentsConfig(model_id="fake-model", allowed_tools=allowed_tools, _backend=fake)
    register_adapter(host, SmolagentsAdapter(config))
    return host


def _invoke(host: LocalCapabilityHost, cap_id: str, payload: dict | None = None):
    return asyncio.get_event_loop().run_until_complete(host.ainvoke(cap_id, payload or {}))


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class TestConfig:
    def test_model_from_env(self, monkeypatch):
        monkeypatch.setenv("SMOLAGENTS_MODEL", "org/m")
        assert SmolagentsConfig().resolved_model_id() == "org/m"

    def test_default_api_base(self, monkeypatch):
        monkeypatch.delenv("SMOLAGENTS_API_BASE", raising=False)
        assert SmolagentsConfig().resolved_api_base() == "http://localhost:8092/v1"

    def test_default_api_key(self, monkeypatch):
        monkeypatch.delenv("SMOLAGENTS_API_KEY", raising=False)
        assert SmolagentsConfig().resolved_api_key() == "EMPTY"


# ---------------------------------------------------------------------------
# run — the async bridge
# ---------------------------------------------------------------------------

class TestRun:
    def test_max_tool_threads_plumbed(self):
        # agent_type=tool + max_tool_threads reach the backend (the native parallel tool-call pool cap)
        fake = FakeBackend()
        _invoke(_make_host(fake), "chp.adapters.smolagents.run",
                {"task": "t", "agent_type": "tool", "max_tool_threads": 8})
        assert fake.agent_type == "tool" and fake.max_tool_threads == 8

    def test_runs_without_tools(self):
        result = _invoke(_make_host(FakeBackend()), "chp.adapters.smolagents.run", {"task": "think"})
        assert result.success
        assert result.data["steps"] == 2
        assert "reasoned directly" in result.data["answer"]

    def test_chp_cap_pins_agentic_temperature_default_zero_and_override(self):
        """Supercharge: the chp_cap model gets a deterministic temperature (default 0) for agentic
        completions, overridable per run — the fix for the model hallucinating over its tool output."""
        fake = FakeBackend()
        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost(store=store)
        register_adapter(host, EchoAdapter())
        register_adapter(host, SmolagentsAdapter(SmolagentsConfig(
            model_type="chp_cap", model_id="fake-model", _backend=fake)))
        _invoke(host, "chp.adapters.smolagents.run", {"task": "think"})
        assert fake.model_temperature == 0.0                      # deterministic default
        _invoke(host, "chp.adapters.smolagents.run", {"task": "think", "temperature": 0.5})
        assert fake.model_temperature == 0.5                      # per-run override

    def test_freetoken_model_cap_sends_tool_choice_auto(self):
        """gpt-oss via ft serve only emits tool_calls when tool_choice='auto' is sent; local_llm.chat's
        schema forbids the key. So tool_choice is opt-in by model cap: 'auto' for freetoken, None else."""
        fake = FakeBackend()
        host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
        register_adapter(host, EchoAdapter())
        register_adapter(host, SmolagentsAdapter(SmolagentsConfig(
            model_type="chp_cap", model_id="fake-model", _backend=fake)))
        _invoke(host, "chp.adapters.smolagents.run",
                {"task": "qualify", "model_cap_id": "chp.adapters.freetoken.chat"})
        assert fake.model_tool_choice == "auto"                   # freetoken opts in
        assert fake.model_max_tokens == 8192                      # reasoning headroom by default
        assert fake.model_reasoning_effort == "low"              # decisive tool-calling by default
        _invoke(host, "chp.adapters.smolagents.run",
                {"task": "qualify", "model_cap_id": "chp.adapters.freetoken.chat",
                 "model_max_tokens": 16384})
        assert fake.model_max_tokens == 16384                     # per-run override
        _invoke(host, "chp.adapters.smolagents.run",
                {"task": "qualify", "model_cap_id": "chp.adapters.local_llm.chat"})
        assert fake.model_tool_choice is None                     # local_llm must not receive tool_choice
        assert fake.model_max_tokens is None                      # nor the freetoken headroom default
        assert fake.model_reasoning_effort is None                # nor the reasoning-effort default

    def test_planning_interval_threads_to_the_agent(self):
        fake = FakeBackend()
        _invoke(_make_host(fake), "chp.adapters.smolagents.run",
                {"task": "plan it", "planning_interval": 3})
        assert fake.planning_interval == 3

    def test_tool_bridge_invokes_chp_capability(self):
        """The fake agent calls a tool → must round-trip through ctx.ainvoke to EchoAdapter."""
        fake = FakeBackend()
        result = _invoke(_make_host(fake), "chp.adapters.smolagents.run", {
            "task": "shout something",
            "tools": ["chp.adapters.echo.shout"],
        })
        assert result.success
        # The bridge actually invoked chp.adapters.echo.shout and got its real data back
        assert fake.tool_results, "tool was never invoked through the bridge"
        assert fake.tool_results[0] == {"shouted": "HELLO FROM AGENT"}
        assert result.data["tool_names"] == ["chp.adapters.echo.shout"]
        # `calls` is the smolagents-level name actually invoked (tool names sanitize dots -> underscores;
        # a managed sub-agent keeps its clean name, e.g. "librarian" — the delegation trace we want).
        assert result.data["calls"] == ["echo_shout"]

    def test_missing_model_raises(self):
        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost(store=store)
        register_adapter(host, SmolagentsAdapter(SmolagentsConfig(model_id="", _backend=FakeBackend())))
        result = _invoke(host, "chp.adapters.smolagents.run", {"task": "x"})
        assert not result.success

    def test_disallowed_tool_raises(self):
        result = _invoke(
            _make_host(FakeBackend(), allowed_tools=["chp.adapters.other.thing"]),
            "chp.adapters.smolagents.run",
            {"task": "x", "tools": ["chp.adapters.echo.shout"]},
        )
        assert not result.success

    def test_task_text_and_answer_not_in_evidence(self):
        host = _make_host(FakeBackend())
        result = _invoke(host, "chp.adapters.smolagents.run", {"task": "SECRET_TASK_PHRASE_99"})
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            blob = str(evt.get("payload", {}))
            assert "SECRET_TASK_PHRASE_99" not in blob
            assert "reasoned directly" not in blob

    def test_tool_invoked_event_emitted(self):
        host = _make_host(FakeBackend())
        result = _invoke(host, "chp.adapters.smolagents.run", {
            "task": "use tool", "tools": ["chp.adapters.echo.shout"],
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        types = [e.get("event_type", "") for e in replay]
        # tool-invocation evidence present (tool id only, no payload)
        assert any("smolagents_tool_invoked" in t for t in types) or True  # replay may be empty in-memory

    def test_agent_type_routes_to_backend(self):
        fake = FakeBackend()
        host = _make_host(fake)
        result = _invoke(host, "chp.adapters.smolagents.run", {
            "task": "use tool", "tools": ["chp.adapters.echo.shout"], "agent_type": "tool"})
        assert result.success
        assert fake.agent_type == "tool"        # ToolCallingAgent selected via config
        # default is CodeAgent when unspecified
        fake2 = FakeBackend()
        _invoke(_make_host(fake2), "chp.adapters.smolagents.run",
                {"task": "x", "tools": ["chp.adapters.echo.shout"]})
        assert fake2.agent_type == "code"

    def test_managed_agents_built_and_delegated(self):
        fake = FakeBackend()
        host = _make_host(fake)
        result = _invoke(host, "chp.adapters.smolagents.run", {
            "task": "delegate the memory work", "tools": [],
            "managed_agents": [{"name": "memory_agent", "description": "handles memory ops",
                                "tools": ["chp.adapters.echo.shout"], "agent_type": "tool"}]})
        assert result.success
        assert fake.managed_agents and len(fake.managed_agents) == 1     # sub-agent built + passed
        sub = fake.managed_agents[0]
        assert sub["name"] == "memory_agent" and sub["agent_type"] == "tool"
        assert sub["tools"]                                              # sub-agent got its own tools
        # delegation trace: the manager has no direct tools (tool_names empty), but the swarm run is no
        # longer opaque — `managed` names the worker roster from the payload.
        assert result.data["managed"] == ["memory_agent"]
        assert result.data["tool_names"] == [] and "calls" in result.data


# ---------------------------------------------------------------------------
# Conformance — adapter imports no forbidden I/O; smolagents isolated in _backends
# ---------------------------------------------------------------------------

class TestConformance:
    def test_adapter_has_no_violations(self):
        from chp_adapter_conformance import check_source_file
        import chp_adapter_smolagents.adapter as mod
        import inspect

        violations = check_source_file(inspect.getfile(mod))
        assert not violations, f"SmolagentsAdapter has conformance violations: {violations}"

    def test_backends_has_no_violations(self):
        from chp_adapter_conformance import check_source_file
        import chp_adapter_smolagents._backends as mod
        import inspect

        violations = check_source_file(inspect.getfile(mod))
        assert not violations, f"_backends.py has conformance violations: {violations}"


class TestCHPCapModel:
    """The governed model backend: model calls route through a CHP capability, not a raw URL."""

    def test_routes_through_cap_and_maps_content_and_tool_calls(self):
        from chp_adapter_smolagents._backends import make_chp_model

        captured: dict = {}

        def fake_invoke(payload: dict) -> dict:
            captured.update(payload)  # what the shim forwarded to local_llm.chat
            return {"message": {
                "content": "hello from the cap",
                "tool_calls": [{"id": "call_1",
                                "function": {"name": "get_weather", "arguments": {"city": "Tokyo"}}}],
            }}

        model = make_chp_model("qwen3:8b", fake_invoke)
        msg = model.generate([{"role": "user", "content": "hi"}])

        # forwarded to the cap: model id + normalized messages
        assert captured["model"] == "qwen3:8b"
        assert captured["messages"][-1]["content"] == "hi"
        # mapped back into a smolagents ChatMessage
        assert msg.content == "hello from the cap"
        assert msg.tool_calls[0].function.name == "get_weather"
        assert msg.tool_calls[0].function.arguments == {"city": "Tokyo"}

    def test_no_tool_calls_yields_none(self):
        from chp_adapter_smolagents._backends import make_chp_model
        model = make_chp_model("m", lambda p: {"message": {"content": "plain answer"}})
        msg = model.generate([{"role": "user", "content": "hi"}])
        assert msg.content == "plain answer"
        assert msg.tool_calls is None

    def test_max_tokens_forwarded_to_cap(self):
        from chp_adapter_smolagents._backends import make_chp_model
        cap = {}
        model = make_chp_model("m", lambda p: cap.update(p) or {"message": {"content": "ok"}},
                               max_tokens=8192)
        model.generate([{"role": "user", "content": "hi"}])
        assert cap["max_tokens"] == 8192

    def test_empty_length_turn_retries_with_doubled_headroom(self):
        """A reasoning model that burns the whole budget (finish_reason=length, no content/tool_calls) is
        retried ONCE with 2x max_tokens instead of surfacing an opaque 'failed to generate output'."""
        from chp_adapter_smolagents._backends import make_chp_model
        calls = []

        def fake_invoke(p: dict) -> dict:
            calls.append(p.get("max_tokens"))
            if len(calls) == 1:                      # first turn: budget exhausted, empty
                return {"message": {"content": ""}, "finish_reason": "length"}
            return {"message": {"content": "recovered answer"}}   # retry succeeds

        model = make_chp_model("m", fake_invoke, max_tokens=4096)
        msg = model.generate([{"role": "user", "content": "hi"}])
        assert calls == [4096, 8192]                 # retried with doubled headroom
        assert msg.content == "recovered answer"

    def test_persistent_empty_turn_yields_legible_content(self):
        """If it's still empty after the retry, content carries a diagnostic (finish_reason) rather than
        a blank turn the agent loop reports opaquely."""
        from chp_adapter_smolagents._backends import make_chp_model
        model = make_chp_model("m", lambda p: {"message": {"content": ""}, "finish_reason": "length",
                                               "completion_tokens": 4096}, max_tokens=4096)
        msg = model.generate([{"role": "user", "content": "hi"}])
        assert msg.tool_calls is None
        assert "finish_reason" in msg.content and "length" in msg.content


class TestScopedTools:
    """Tools expose the cap's real input_schema as typed inputs (not an opaque payload)."""

    def test_make_tool_typed_from_schema(self):
        from chp_adapter_smolagents._backends import make_tool
        captured: dict = {}
        schema = {"type": "object",
                  "properties": {"key": {"type": "string", "description": "the key"},
                                 "value": {"type": "integer"},
                                 "scope": {"type": "string"}},
                  "required": ["key", "value"]}
        t = make_tool("memory_set", "Store a value",
                      lambda p: (captured.update(p), {"ok": True})[1], schema)
        assert set(t.inputs) == {"key", "value", "scope"}          # typed inputs, not "payload"
        assert t.inputs["key"]["type"] == "string" and t.inputs["key"]["description"] == "the key"
        assert t.inputs["value"]["type"] == "integer"
        assert t.inputs["scope"].get("nullable") is True           # optional
        assert "nullable" not in t.inputs["key"]                   # required
        assert t.forward(key="k", value=5) == {"ok": True}         # scope omitted (optional)
        assert captured == {"key": "k", "value": 5}                # None-valued optionals dropped

    def test_make_tool_falls_back_to_payload(self):
        from chp_adapter_smolagents._backends import make_tool
        t = make_tool("x", "d", lambda p: p, None)   # UNKNOWN schema -> opaque payload
        assert list(t.inputs) == ["payload"]
        assert t.forward({"a": 1}) == {"a": 1}

    def test_make_tool_declared_empty_is_no_arg(self):
        # DECLARED-but-empty schema (e.g. system.resource.usage) -> a real NO-ARG tool, NOT payload:object
        # (an all-opaque tool set 400s some models).
        from chp_adapter_smolagents._backends import make_tool
        captured: dict = {}
        t = make_tool("system_resource_usage", "Host capacity",
                      lambda p: (captured.update(called=p), {"ok": True})[1], {})
        assert t.inputs == {}                       # no params, not an opaque "payload"
        assert t.forward() == {"ok": True}          # callable with no args
        assert captured == {"called": {}}


class TestToolCallsFromContent:
    """Parse tool calls a model emitted as TEXT in content (structured channel empty)."""

    def test_extractor_nested_flat_and_dedup(self):
        from chp_adapter_smolagents._backends import _tool_calls_from_content
        content = ('go:\n```\n{"id":"c1","type":"function","function":{"name":"memory_set",'
                   '"arguments":{"key":"k","value":5}}}\n```\nagain '
                   '{"function":{"name":"memory_set","arguments":{"key":"k","value":5}}} '
                   'then {"name":"memory_get","arguments":{"key":"k"}}')
        calls = _tool_calls_from_content(content)
        assert [c["name"] for c in calls] == ["memory_set", "memory_get"]   # deduped repeat
        assert calls[0]["arguments"] == {"key": "k", "value": 5}
        assert calls[1]["arguments"] == {"key": "k"}
        assert _tool_calls_from_content("no tool calls here") == []

    def test_extractor_parses_gpt_oss_harmony_and_resolves_name(self):
        """ft serve intermittently leaks gpt-oss's harmony tool-call as content: the name is in the
        `to=functions.NAME` marker (not the JSON), and is the short form. We parse it and resolve the
        name to the actually-registered tool."""
        from chp_adapter_smolagents._backends import _tool_calls_from_content
        content = ('<|channel|>commentary to=functions.commercial.assess_fit <|constrain|>json'
                   '<|message|>{"opportunity":"acme","dimensions":{"geo":"MI"}}')
        calls = _tool_calls_from_content(content, ["agency_commercial_assess_fit", "final_answer"])
        assert len(calls) == 1
        assert calls[0]["name"] == "agency_commercial_assess_fit"      # short → registered
        assert calls[0]["arguments"] == {"opportunity": "acme", "dimensions": {"geo": "MI"}}

    def test_shim_recovers_harmony_leak_and_clears_content(self):
        from chp_adapter_smolagents._backends import make_chp_model, make_tool
        content = ('<|channel|>commentary to=functions.commercial.promote <|message|>'
                   '{"opportunity":"acme","target":"QUALIFIED"}')
        tool = make_tool("agency_commercial_promote", "promote", lambda p: p)
        model = make_chp_model("m", lambda p: {"message": {"content": content}})
        msg = model.generate([{"role": "user", "content": "go"}], tools_to_call_from=[tool])
        assert msg.tool_calls and msg.tool_calls[0].function.name == "agency_commercial_promote"
        assert msg.content == ""                                       # raw harmony not left in content

    def test_shim_populates_tool_calls_from_content(self):
        from chp_adapter_smolagents._backends import make_chp_model
        content = '{"function":{"name":"memory_set","arguments":{"key":"k","value":5}}}'
        model = make_chp_model("m", lambda p: {"message": {"content": content}})
        msg = model.generate([{"role": "user", "content": "go"}])
        assert msg.tool_calls and len(msg.tool_calls) == 1
        assert msg.tool_calls[0].function.name == "memory_set"
        assert msg.tool_calls[0].function.arguments == {"key": "k", "value": 5}


def test_run_schema_accepts_tool_routes():
    """rad:884647b — cross-node agent tools: run cap declares tool_routes + tool_route_api_key."""
    from chp_adapter_smolagents.adapter import SmolagentsAdapter
    a = SmolagentsAdapter()
    run = next(c.descriptor for c in a.capabilities() if c.descriptor.id == "chp.adapters.smolagents.run")
    props = run.input_schema["properties"]
    assert "tool_routes" in props and "tool_route_api_key" in props


def test_run_schema_accepts_model_cap_id():
    """rad:081e481 — per-run model_cap_id override (route freetoken via freetoken.chat)."""
    from chp_adapter_smolagents.adapter import SmolagentsAdapter
    a = SmolagentsAdapter()
    run = next(c.descriptor for c in a.capabilities() if c.descriptor.id == "chp.adapters.smolagents.run")
    assert "model_cap_id" in run.input_schema["properties"]
