"""Decorator helpers for declaring capabilities from ordinary functions."""

from __future__ import annotations

import inspect
import typing
from typing import Any, Callable

from .types import (
    AssuranceMetadata,
    AutonomyProfile,
    CapabilityDescriptor,
    CapabilityIdempotency,
    CapabilityStatus,
    HostRequirements,
    InvariantDescriptor,
    JSON,
    PolicyDescriptor,
    RetryPolicy,
)

# Python annotation -> JSON Schema type. Unmapped annotations (Optional[int],
# custom classes, unannotated params) fall back to an unconstrained property.
_JSON_TYPES: dict[Any, str] = {
    bool: "boolean", int: "integer", float: "number",
    str: "string", list: "array", dict: "object",
}
# Fallback for stringized annotations (PEP 563 / `from __future__ import
# annotations`) that get_type_hints could not resolve.
_JSON_TYPE_NAMES: dict[str, str] = {
    "bool": "boolean", "int": "integer", "float": "number",
    "str": "string", "list": "array", "List": "array",
    "dict": "object", "Dict": "object",
}


def _json_type(annotation: Any) -> str | None:
    if isinstance(annotation, str):        # unresolved stringized annotation
        return _JSON_TYPE_NAMES.get(annotation)
    return _JSON_TYPES.get(annotation)


def schema_from_type_hints(fn: Callable[..., Any]) -> dict | None:
    """A JSON-Schema object built from a function's annotated parameters.

    Resolves stringized annotations (`from __future__ import annotations`, PEP 563)
    via ``get_type_hints``, falling back to the raw annotation name. Skips ``ctx`` /
    ``payload`` / ``self`` and ``*args`` / ``**kwargs``. A parameter WITHOUT a default
    is ``required`` — a missing one has no handler fallback, so it must be denied at
    schema validation (``input_schema_validation_failed``) rather than crash the handler
    with a ``TypeError``; a parameter WITH a default stays optional (its default applies).
    Returns ``None`` when there are no usable parameters. Pure and opt-in — nothing
    infers schemas unless asked.
    """
    try:
        hints = typing.get_type_hints(fn)
    except Exception:
        hints = {}
    props: dict[str, dict] = {}
    required: list[str] = []
    for name, param in inspect.signature(fn).parameters.items():
        if name in ("ctx", "payload", "self"):
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        json_type = _json_type(hints.get(name, param.annotation))
        props[name] = {"type": json_type} if json_type else {}
        if param.default is inspect.Parameter.empty:
            required.append(name)
    if not props:
        return None
    schema: dict = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def capability(
    *,
    id: str,
    version: str,
    description: str,
    # extended identity
    name: str | None = None,
    category: str | None = None,
    provider: str | None = None,
    status: CapabilityStatus = "draft",
    # invocation contract
    modes: list[str] | None = None,
    input_schema: JSON | None = None,
    infer_schema: bool = False,
    output_schema: JSON | None = None,
    idempotency: CapabilityIdempotency = "optional",
    side_effects: list[str] | None = None,
    # governance
    invariants: list[InvariantDescriptor] | None = None,
    risk: str = "low",
    # observability
    emits: list[str] | None = None,
    assurance: AssuranceMetadata | None = None,
    # organization
    owner: str | None = None,
    tags: list[str] | None = None,
    metadata: JSON | None = None,
    # structured optional sub-objects
    host_requirements: HostRequirements | None = None,
    policy: PolicyDescriptor | None = None,
    autonomy: AutonomyProfile | None = None,
    # reliability (proposal 0038)
    timeout_s: float | None = None,
    retry: "RetryPolicy | None" = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Attach a CHP capability descriptor to a function.

    The decorated function can be registered with ``LocalCapabilityHost.register``.
    Ordinary functions receive payload fields as keyword arguments. Handlers that
    explicitly accept ``ctx`` and ``payload`` keep the lower-level handler shape.

    Pass ``infer_schema=True`` to derive ``input_schema`` from the function's type
    hints (via :func:`schema_from_type_hints`) when one is not given explicitly — the
    same inference the ``CapabilityServer`` surface uses. Off by default, so existing
    capabilities keep their behavior.
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        resolved_input_schema = input_schema
        if not resolved_input_schema and infer_schema:
            resolved_input_schema = schema_from_type_hints(fn)
        descriptor = CapabilityDescriptor(
            id=id,
            version=version,
            description=description,
            name=name,
            category=category,
            provider=provider,
            status=status,
            modes=modes or ["sync"],
            input_schema=resolved_input_schema or {},
            output_schema=output_schema or {},
            idempotency=idempotency,
            side_effects=side_effects or [],
            invariants=invariants or [],
            risk=risk,  # type: ignore[arg-type]
            emits=emits
            or [
                "execution_started",
                "execution_completed",
                "execution_failed",
                "execution_denied",
                "execution_skipped",
            ],
            assurance=assurance or AssuranceMetadata(),
            owner=owner,
            tags=tags or [],
            metadata=metadata or {},
            host_requirements=host_requirements,
            policy=policy,
            autonomy=autonomy,
            timeout_s=timeout_s,
            retry=retry,
        )
        setattr(fn, "__chp_descriptor__", descriptor)
        return fn

    return decorate


def get_capability_descriptor(fn: Callable[..., Any]) -> CapabilityDescriptor | None:
    descriptor = getattr(fn, "__chp_descriptor__", None)
    return descriptor if isinstance(descriptor, CapabilityDescriptor) else None


def adapt_callable(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Adapt a decorated ordinary function to the host handler shape."""

    signature = inspect.signature(fn)
    params = list(signature.parameters.values())

    async def handler(ctx: Any, payload: JSON) -> Any:
        if len(params) >= 2 and params[0].name == "ctx" and params[1].name == "payload":
            result = fn(ctx, payload)
        elif len(params) == 1 and params[0].name == "payload":
            result = fn(payload)
        else:
            result = fn(**payload)
        return await result if inspect.isawaitable(result) else result

    return handler
