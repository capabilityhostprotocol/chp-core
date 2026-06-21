"""chp-adapter-audit — queryable audit log over the CHP host evidence store.

Exposes three capabilities: ``query_invocations``, ``get_invocation``, and
``stats``. Uses ``on_register(host)`` to capture the host's evidence store.
An injectable ``store`` on the config allows tests to bypass the host.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_audit import AuditAdapter, AuditConfig

    host = LocalCapabilityHost()
    register_adapter(host, AuditAdapter())  # binds to host.store automatically
"""

from __future__ import annotations

from .adapter import AuditAdapter, AuditConfig

__all__ = ["AuditAdapter", "AuditConfig"]
