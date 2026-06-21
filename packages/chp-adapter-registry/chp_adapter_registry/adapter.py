"""RegistryAdapter — governed capability discovery over the host catalog.

Three capabilities:

* ``list_capabilities`` — filter by category, namespace, tags, status, risk;
  returns serialized capability descriptors.
* ``get_capability`` — fetch one descriptor by exact capability ID.
* ``describe_host`` — return the host descriptor (identity + full catalog).

By default the registry's own capabilities are excluded from ``list_capabilities``
results to keep the interface clean. Set ``include_registry_capabilities=True``
in config to include them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

_OWN_IDS = {
    "chp.adapters.registry.list_capabilities",
    "chp.adapters.registry.get_capability",
    "chp.adapters.registry.describe_host",
}

_EMITS = ["registry_query", "registry_result", "registry_error"]


@dataclass
class RegistryConfig:
    """Config for RegistryAdapter.

    ``include_registry_capabilities`` — if True, the registry's own capabilities
    appear in ``list_capabilities`` results (default False to avoid circular
    confusion).
    """

    include_registry_capabilities: bool = False


class RegistryAdapter(BaseAdapter):
    """Meta-adapter: live capability catalog as governed capabilities."""

    adapter_id = "chp.adapters.registry"
    adapter_name = "Capability Registry"
    adapter_description = "Discover and inspect CHP capabilities registered on the host."
    adapter_category = "core"
    adapter_tags = ["registry", "discovery", "meta"]

    def __init__(self, config: RegistryConfig | None = None) -> None:
        self._config = config or RegistryConfig()
        self._host: Any = None

    def on_register(self, host: Any) -> None:
        self._host = host

    # ------------------------------------------------------------------
    # list_capabilities
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.registry.list_capabilities",
        version="1.0.0",
        description="List capabilities registered on the host with optional filters.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Filter by capability category."},
                "namespace": {"type": "string", "description": "Filter by ID prefix (e.g. 'chp.adapters.github')."},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter capabilities that carry ALL listed tags.",
                },
                "status": {
                    "type": "string",
                    "enum": ["draft", "experimental", "certified", "deprecated"],
                },
                "risk": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                },
                "limit": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["registry", "discovery"],
    )
    async def list_capabilities(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            ctx.emit("registry_error", {"reason": "host_not_bound"}, redacted=False)
            raise RuntimeError("RegistryAdapter not registered with a host")

        discover_kwargs: dict[str, Any] = {}
        if payload.get("category"):
            discover_kwargs["category"] = payload["category"]
        if payload.get("namespace"):
            discover_kwargs["namespace"] = payload["namespace"]
        if payload.get("tags"):
            discover_kwargs["tags"] = payload["tags"]
        if payload.get("status"):
            discover_kwargs["status"] = payload["status"]
        if payload.get("risk"):
            discover_kwargs["risk"] = payload["risk"]

        ctx.emit("registry_query", {
            "op": "list_capabilities",
            "filters": {k: v for k, v in payload.items() if k != "limit" and v is not None},
        }, redacted=False)

        host_dict = self._host.discover(**discover_kwargs)
        caps = host_dict.get("capabilities", [])

        if not self._config.include_registry_capabilities:
            caps = [c for c in caps if c["id"] not in _OWN_IDS]

        limit = payload.get("limit")
        if limit is not None:
            caps = caps[:limit]

        ctx.emit("registry_result", {
            "op": "list_capabilities",
            "count": len(caps),
        }, redacted=False)

        return {"capabilities": caps, "count": len(caps)}

    # ------------------------------------------------------------------
    # get_capability
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.registry.get_capability",
        version="1.0.0",
        description="Fetch a capability descriptor by its exact ID.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Capability ID (without version suffix)."},
            },
            "required": ["id"],
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["registry", "discovery"],
    )
    async def get_capability(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            ctx.emit("registry_error", {"reason": "host_not_bound"}, redacted=False)
            raise RuntimeError("RegistryAdapter not registered with a host")

        cap_id = payload["id"]

        ctx.emit("registry_query", {
            "op": "get_capability",
            "id": cap_id,
        }, redacted=False)

        host_dict = self._host.discover()
        caps = host_dict.get("capabilities", [])
        match = next((c for c in caps if c["id"] == cap_id), None)

        if match is None:
            ctx.emit("registry_error", {
                "reason": "not_found", "id": cap_id,
            }, redacted=False)
            raise ValueError(f"Capability not found: {cap_id!r}")

        ctx.emit("registry_result", {
            "op": "get_capability",
            "id": cap_id,
        }, redacted=False)

        return {"capability": match}

    # ------------------------------------------------------------------
    # describe_host
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.registry.describe_host",
        version="1.0.0",
        description="Return the host descriptor with its full capability catalog.",
        category="core",
        risk="low",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        emits=_EMITS,
        tags=["registry", "discovery"],
    )
    async def describe_host(self, ctx: Any, payload: dict) -> dict:
        if self._host is None:
            ctx.emit("registry_error", {"reason": "host_not_bound"}, redacted=False)
            raise RuntimeError("RegistryAdapter not registered with a host")

        ctx.emit("registry_query", {"op": "describe_host"}, redacted=False)

        host_dict = self._host.discover()

        ctx.emit("registry_result", {
            "op": "describe_host",
            "capability_count": len(host_dict.get("capabilities", [])),
        }, redacted=False)

        return host_dict
