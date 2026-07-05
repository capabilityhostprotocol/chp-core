"""Agent interface serialization for CHP.

Converts CapabilityDescriptor objects into tool call formats used by
AI agent frameworks (Anthropic and OpenAI). Cost/safety hints on the
descriptor are described in spec/chp-governance-v0.2.md.
"""

from __future__ import annotations

from typing import Literal

from .types import CapabilityDescriptor


def capability_to_anthropic_tool(descriptor: CapabilityDescriptor) -> dict:
    """Serialize a CapabilityDescriptor to Anthropic tool call format."""
    description = descriptor.description
    if descriptor.safety_hint is not None:
        hints = []
        if not descriptor.safety_hint.reversible:
            hints.append("irreversible")
        if descriptor.safety_hint.destructive:
            hints.append("destructive")
        if descriptor.safety_hint.requires_human_review:
            hints.append("requires human review")
        if hints:
            description = f"{description} [{', '.join(hints)}]"

    input_schema: dict = descriptor.input_schema or {}
    if not input_schema:
        input_schema = {"type": "object", "properties": {}}

    return {
        "name": descriptor.id.replace(".", "_"),
        "description": description,
        "input_schema": input_schema,
    }


def capability_to_openai_tool(descriptor: CapabilityDescriptor) -> dict:
    """Serialize a CapabilityDescriptor to OpenAI tool call format."""
    description = descriptor.description
    if descriptor.safety_hint is not None:
        hints = []
        if not descriptor.safety_hint.reversible:
            hints.append("irreversible")
        if descriptor.safety_hint.destructive:
            hints.append("destructive")
        if descriptor.safety_hint.requires_human_review:
            hints.append("requires human review")
        if hints:
            description = f"{description} [{', '.join(hints)}]"

    parameters: dict = descriptor.input_schema or {}
    if not parameters:
        parameters = {"type": "object", "properties": {}}

    return {
        "type": "function",
        "function": {
            "name": descriptor.id.replace(".", "_"),
            "description": description,
            "parameters": parameters,
        },
    }


def capabilities_to_tool_list(
    descriptors: list[CapabilityDescriptor],
    format: Literal["anthropic", "openai"] = "anthropic",
) -> list[dict]:
    """Convert a list of CapabilityDescriptors to a tool list for an AI agent."""
    if format == "openai":
        return [capability_to_openai_tool(d) for d in descriptors]
    return [capability_to_anthropic_tool(d) for d in descriptors]
