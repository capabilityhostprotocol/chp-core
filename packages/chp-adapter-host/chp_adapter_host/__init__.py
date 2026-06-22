"""chp-adapter-host — report and update the CHP runtime on a node.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_host import HostAdapter

    host = LocalCapabilityHost()
    register_adapter(host, HostAdapter())
    host.invoke("chp.adapters.host.version", {})
"""

from __future__ import annotations

from .adapter import HostAdapter

__all__ = ["HostAdapter"]
