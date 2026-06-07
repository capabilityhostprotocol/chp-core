"""Tests for agent interface serialization — §7.2."""

from __future__ import annotations

from chp_core.agent_interface import (
    capabilities_to_tool_list,
    capability_to_anthropic_tool,
    capability_to_openai_tool,
)
from chp_core.types import CapabilityDescriptor, CostHint, SafetyHint


def _desc(**kwargs) -> CapabilityDescriptor:
    defaults = dict(id="test.capability", version="0.1.0", description="A test capability.")
    defaults.update(kwargs)
    return CapabilityDescriptor(**defaults)


# ---------------------------------------------------------------------------
# Anthropic format
# ---------------------------------------------------------------------------

def test_anthropic_basic_shape():
    tool = capability_to_anthropic_tool(_desc())
    assert tool["name"] == "test_capability"
    assert tool["description"] == "A test capability."
    assert "input_schema" in tool
    assert tool["input_schema"]["type"] == "object"


def test_anthropic_uses_declared_input_schema():
    schema = {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}
    tool = capability_to_anthropic_tool(_desc(input_schema=schema))
    assert tool["input_schema"] == schema


def test_anthropic_dot_in_id_replaced():
    tool = capability_to_anthropic_tool(_desc(id="state_machine.create"))
    assert tool["name"] == "state_machine_create"


def test_anthropic_safety_hints_appended_to_description():
    hint = SafetyHint(reversible=False, destructive=True)
    tool = capability_to_anthropic_tool(_desc(safety_hint=hint))
    assert "irreversible" in tool["description"]
    assert "destructive" in tool["description"]


def test_anthropic_safe_capability_no_hint_suffix():
    tool = capability_to_anthropic_tool(_desc(safety_hint=SafetyHint()))  # all-safe defaults
    assert "[" not in tool["description"]


# ---------------------------------------------------------------------------
# OpenAI format
# ---------------------------------------------------------------------------

def test_openai_basic_shape():
    tool = capability_to_openai_tool(_desc())
    assert tool["type"] == "function"
    assert "function" in tool
    fn = tool["function"]
    assert fn["name"] == "test_capability"
    assert "parameters" in fn


def test_openai_safety_hints_in_description():
    hint = SafetyHint(requires_human_review=True)
    tool = capability_to_openai_tool(_desc(safety_hint=hint))
    assert "requires human review" in tool["function"]["description"]


# ---------------------------------------------------------------------------
# List conversion
# ---------------------------------------------------------------------------

def test_capabilities_to_tool_list_anthropic():
    descs = [_desc(id="a.b"), _desc(id="c.d")]
    tools = capabilities_to_tool_list(descs, format="anthropic")
    assert len(tools) == 2
    assert tools[0]["name"] == "a_b"


def test_capabilities_to_tool_list_openai():
    descs = [_desc(id="a.b")]
    tools = capabilities_to_tool_list(descs, format="openai")
    assert tools[0]["type"] == "function"


# ---------------------------------------------------------------------------
# CostHint round-trip
# ---------------------------------------------------------------------------

def test_cost_hint_in_descriptor_to_dict():
    desc = _desc(cost_hint=CostHint(token_estimate=500, latency_ms_p50=120))
    d = desc.to_dict()
    assert d["cost_hint"]["token_estimate"] == 500
    assert d["cost_hint"]["latency_ms_p50"] == 120


def test_no_hint_omitted_from_dict():
    desc = _desc()
    d = desc.to_dict()
    assert "cost_hint" not in d
    assert "safety_hint" not in d
