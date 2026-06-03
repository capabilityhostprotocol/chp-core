"""Adapter primitives for grouping and registering CHP capabilities."""

from __future__ import annotations

import inspect
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ..decorators import adapt_callable, get_capability_descriptor
from ..host import CapabilityHandler, LocalCapabilityHost
from ..types import CapabilityDescriptor


@dataclass(slots=True)
class HostedCapability:
    """A capability descriptor and handler supplied by an adapter."""

    descriptor: CapabilityDescriptor
    handler: CapabilityHandler
    enabled: bool = True


class CapabilityAdapter(Protocol):
    """Structural protocol for CHP capability adapters.

    Any object with ``adapter_id`` and ``capabilities()`` satisfies this
    protocol and can be passed to ``register_adapter``.
    """

    adapter_id: str

    def capabilities(self) -> Iterable[HostedCapability]:
        """Return hosted capabilities declared by this adapter."""


class BaseAdapter:
    """Base class for CHP capability adapters.

    Subclass this, declare ``adapter_id``, and decorate methods with
    ``@capability`` from ``chp_core``. All decorated methods are discovered
    automatically by ``capabilities()``.

    Class attributes for adapter metadata::

        adapter_id          # required — stable identity string
        adapter_name        # human-readable name (defaults to adapter_id)
        adapter_description # optional description
        adapter_version     # semver string, default "1.0.0"
        adapter_tags        # list of string tags for discovery

    Override ``on_register(host)`` for any setup that requires the host
    (e.g. registering secondary capabilities, emitting startup evidence).

    Example::

        from chp_core import capability, BaseAdapter, LocalCapabilityHost, register_adapter

        class MathAdapter(BaseAdapter):
            adapter_id = "math"
            adapter_name = "Math Capabilities"

            @capability(id="math.add", version="1.0.0", description="Add two numbers.")
            async def add(self, ctx, payload):
                return {"sum": payload["a"] + payload["b"]}

            @capability(id="math.mul", version="1.0.0", description="Multiply two numbers.")
            async def multiply(self, ctx, payload):
                return {"product": payload["a"] * payload["b"]}

        host = LocalCapabilityHost()
        register_adapter(host, MathAdapter())
    """

    adapter_id: str
    adapter_name: str | None = None
    adapter_description: str | None = None
    adapter_version: str = "1.0.0"
    adapter_tags: list[str] = []
    adapter_category: str | None = None

    def capabilities(self) -> Iterable[HostedCapability]:
        """Yield capabilities from all ``@capability``-decorated methods."""
        for _, method in inspect.getmembers(self, predicate=inspect.ismethod):
            descriptor = get_capability_descriptor(method.__func__)
            if descriptor is not None:
                yield HostedCapability(descriptor=descriptor, handler=adapt_callable(method))

    def on_register(self, host: LocalCapabilityHost) -> None:
        """Called after all capabilities from this adapter are registered."""

    def metadata(self) -> dict[str, Any]:
        """Return adapter identity metadata."""
        return {
            "adapter_id": self.adapter_id,
            "adapter_name": self.adapter_name or self.adapter_id,
            "adapter_description": self.adapter_description,
            "adapter_version": self.adapter_version,
            "adapter_tags": list(self.adapter_tags),
            "adapter_category": self.adapter_category,
        }


class SimpleAdapter(BaseAdapter):
    """Adapter wrapping a list of ``@capability``-decorated functions.

    Use when you have standalone functions and don't need a class::

        from chp_core import capability, SimpleAdapter, LocalCapabilityHost, register_adapter

        @capability(id="math.add", version="1.0.0", description="Add two numbers.")
        def add(a: int, b: int):
            return {"sum": a + b}

        host = LocalCapabilityHost()
        register_adapter(host, SimpleAdapter("math", [add]))
    """

    def __init__(
        self,
        adapter_id: str,
        functions: Sequence[Any],
        *,
        name: str | None = None,
        description: str | None = None,
        version: str = "1.0.0",
        tags: list[str] | None = None,
    ) -> None:
        self.adapter_id = adapter_id
        self.adapter_name = name
        self.adapter_description = description
        self.adapter_version = version
        self.adapter_tags = tags or []
        self._functions = list(functions)

    def capabilities(self) -> Iterable[HostedCapability]:
        for fn in self._functions:
            descriptor = get_capability_descriptor(fn)
            if descriptor is not None:
                yield HostedCapability(descriptor=descriptor, handler=adapt_callable(fn))


def register_adapter(
    host: LocalCapabilityHost,
    adapter: CapabilityAdapter,
) -> list[CapabilityDescriptor]:
    """Register all capabilities from *adapter* with *host*, skipping duplicates.

    Calls ``adapter.on_register(host)`` after registration if the method exists.
    """
    registered = register_hosted_capabilities(host, list(adapter.capabilities()))
    on_register = getattr(adapter, "on_register", None)
    if callable(on_register):
        on_register(host)
    return registered


CHP_ADAPTER_GROUP = "chp.adapters"
"""Entry-point group name for installed CHP adapter packages.

Third-party adapter packages declare their adapter class under this group in
``pyproject.toml``::

    [project.entry-points."chp.adapters"]
    linear = "chp_linear:LinearAdapter"

The adapter class must satisfy the ``CapabilityAdapter`` protocol (i.e. expose
``adapter_id`` and ``capabilities()``). Using ``BaseAdapter`` as the base class
is the recommended pattern.
"""


def discover_adapters(group: str = CHP_ADAPTER_GROUP) -> dict[str, type]:
    """Return installed adapter classes keyed by entry-point name.

    Loads all entry points under *group* (default ``chp.adapters``) from the
    current Python environment. Returns an empty dict if none are installed.

    Example::

        adapters = discover_adapters()
        # {"linear": <class 'chp_linear.LinearAdapter'>, ...}
    """
    from importlib.metadata import entry_points

    return {ep.name: ep.load() for ep in entry_points(group=group)}


def auto_register_adapters(
    host: LocalCapabilityHost,
    group: str = CHP_ADAPTER_GROUP,
) -> list[CapabilityDescriptor]:
    """Instantiate and register all installed adapters in *group* with *host*.

    Each adapter class is instantiated with no arguments, so adapters that
    require configuration (API keys, etc.) must be registered manually via
    ``register_adapter`` instead.

    Registration failures per adapter are isolated — one broken adapter will
    not prevent others from loading. Errors are surfaced as warnings.

    Example::

        host = LocalCapabilityHost()
        auto_register_adapters(host)
        # all pip-installed chp.adapters are now registered
    """
    import warnings

    registered: list[CapabilityDescriptor] = []
    for name, adapter_cls in discover_adapters(group).items():
        try:
            registered.extend(register_adapter(host, adapter_cls()))
        except Exception as exc:
            warnings.warn(
                f"chp: failed to auto-register adapter {name!r}: {exc}",
                stacklevel=2,
            )
    return registered


def register_hosted_capabilities(
    host: LocalCapabilityHost,
    capabilities: Sequence[HostedCapability],
) -> list[CapabilityDescriptor]:
    registered: list[CapabilityDescriptor] = []
    for capability in capabilities:
        descriptor = register_capability_once(
            host,
            capability.descriptor,
            capability.handler,
            enabled=capability.enabled,
        )
        if descriptor is not None:
            registered.append(descriptor)
    return registered


def register_capability_once(
    host: LocalCapabilityHost,
    descriptor: CapabilityDescriptor,
    handler: CapabilityHandler,
    *,
    enabled: bool = True,
) -> CapabilityDescriptor | None:
    capability_ids = {
        capability["id"]
        for capability in host.discover().get("capabilities", [])
    }
    if descriptor.id in capability_ids:
        return None
    return host.register(descriptor, handler, enabled=enabled)
