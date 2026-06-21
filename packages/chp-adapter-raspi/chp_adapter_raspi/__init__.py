"""chp-adapter-raspi — Raspberry Pi physical-world access as governed CHP capabilities.

Platform guard: capabilities fail gracefully on non-Pi platforms with a clear
RuntimeError so chp-host doesn't crash during dev on a Mac.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_raspi import RaspberryPiAdapter, RaspberryPiConfig

    host = LocalCapabilityHost()
    register_adapter(host, RaspberryPiAdapter(RaspberryPiConfig()))
    result = host.invoke("chp.adapters.raspi.system_stats", {})
"""

from __future__ import annotations

from .adapter import RaspberryPiAdapter, RaspberryPiConfig

__all__ = ["RaspberryPiAdapter", "RaspberryPiConfig"]
