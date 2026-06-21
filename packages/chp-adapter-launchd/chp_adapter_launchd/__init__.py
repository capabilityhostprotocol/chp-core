"""chp-adapter-launchd — govern macOS launchd services as CHP capabilities.

Manage long-running LaunchAgent services (list/status/start/stop/install/uninstall)
with evidence. Scoped by a managed label prefix (default ``com.chp.``) so it only
touches CHP's own services. launchctl + plist I/O is isolated in ``_backends.py``.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_launchd import LaunchdAdapter, LaunchdConfig

    host = LocalCapabilityHost()
    register_adapter(host, LaunchdAdapter(LaunchdConfig()))
    result = host.invoke("chp.adapters.launchd.list", {})
"""

from __future__ import annotations

from .adapter import LaunchdAdapter, LaunchdConfig

__all__ = ["LaunchdAdapter", "LaunchdConfig"]
