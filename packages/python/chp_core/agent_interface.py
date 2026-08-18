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


# ── Frontend-as-capability: the human-render projection ───────────────────────
# A UI component IS a capability whose invocation is a render: category="component",
# a "render" mode, input_schema=props, emits=events. capability_to_component is the
# sibling of capability_to_anthropic_tool — the SAME descriptor projects to an agent
# tool (machine), a component manifest (human), or a gateway endpoint (API). One
# capability set, three authority-bounded renders.

def is_render_capability(descriptor: CapabilityDescriptor) -> bool:
    """True when a descriptor is a render-capability (a UI component)."""
    return descriptor.category == "component" or "render" in descriptor.modes


def capability_to_component(descriptor: CapabilityDescriptor) -> dict:
    """Project a render-capability into a component manifest (mirrors chp-runtime's
    ComponentDefinition). props ← input_schema, events ← emits, dependencies ←
    depends_on, contentHash ← metadata['content_hash'] (the bundle digest that pins
    exactly which bytes render, the visual peer of a capability's contractDigest)."""
    props: dict = descriptor.input_schema or {}
    if not props:
        props = {"type": "object", "properties": {}}

    manifest: dict = {
        "name": descriptor.id,
        "version": descriptor.version,
        "description": descriptor.description,
        "propsSchema": props,
        "events": list(descriptor.emits),
        "componentDependencies": descriptor.depends_on or [],
    }
    content_hash = descriptor.metadata.get("content_hash") if descriptor.metadata else None
    if content_hash:
        manifest["contentHash"] = content_hash
    return manifest


def capabilities_to_component_list(
    descriptors: list[CapabilityDescriptor],
) -> list[dict]:
    """Component manifests for the render-capabilities in a set (non-render caps skipped) —
    the human-consumer peer of capabilities_to_tool_list."""
    return [capability_to_component(d) for d in descriptors if is_render_capability(d)]
