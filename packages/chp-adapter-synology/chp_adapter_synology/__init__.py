"""chp-adapter-synology — Synology DSM operations as governed CHP capabilities.

Auth via DSM session token (SID). Credentials are NEVER stored in evidence.
Injectable SynologyBackend for tests — no live NAS required.

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_synology import SynologyAdapter, SynologyConfig

    host = LocalCapabilityHost()
    register_adapter(host, SynologyAdapter(SynologyConfig()))
    result = host.invoke("chp.adapters.synology.file_list", {"path": "/homes"})
"""

from __future__ import annotations

from .adapter import SynologyAdapter, SynologyConfig

__all__ = ["SynologyAdapter", "SynologyConfig"]
