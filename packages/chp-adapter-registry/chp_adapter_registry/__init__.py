"""chp-adapter-registry — governed capability discovery registry.

Exposes ``list_capabilities``, ``get_capability``, and ``describe_host``
as CHP capabilities backed by the host's live catalog.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_registry import RegistryAdapter, RegistryConfig

    host = LocalCapabilityHost()
    register_adapter(host, RegistryAdapter())  # binds via on_register(host)
"""

from __future__ import annotations

from .adapter import RegistryAdapter, RegistryConfig

__all__ = ["RegistryAdapter", "RegistryConfig"]
