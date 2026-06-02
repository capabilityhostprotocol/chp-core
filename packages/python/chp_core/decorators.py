"""Decorator helpers for declaring capabilities from ordinary functions."""

from __future__ import annotations

import inspect
from typing import Any, Callable

from .types import (
    AssuranceMetadata,
    CapabilityDescriptor,
    CapabilityIdempotency,
    CapabilityStatus,
    HostRequirements,
    InvariantDescriptor,
    JSON,
    PolicyDescriptor,
)


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
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Attach a CHP capability descriptor to a function.

    The decorated function can be registered with ``LocalCapabilityHost.register``.
    Ordinary functions receive payload fields as keyword arguments. Handlers that
    explicitly accept ``ctx`` and ``payload`` keep the lower-level handler shape.
    """

    descriptor = CapabilityDescriptor(
        id=id,
        version=version,
        description=description,
        name=name,
        category=category,
        provider=provider,
        status=status,
        modes=modes or ["sync"],
        input_schema=input_schema or {},
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
    )

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
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
