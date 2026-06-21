"""Build and serve a real CHP host from a named set of installed adapters.

This turns the 45+ ``chp-adapter-*`` packages — which otherwise only run
in-process — into addressable host processes. Pick the adapters by their
entry-point name (``aws``, ``vector``, ...); they are instantiated with no
arguments (in-memory/default backends) exactly like ``auto_register_adapters``,
and registration is fail-soft so one broken adapter never sinks the host.
"""

from __future__ import annotations

import warnings
from pathlib import Path

from chp_core import LocalCapabilityHost, register_adapter
from chp_core.adapters import discover_adapters
from chp_core.store import SQLiteEvidenceStore


class AdapterBuildResult:
    """Outcome of building a host: which adapters registered, which were skipped."""

    def __init__(self) -> None:
        self.registered: list[str] = []
        self.skipped: dict[str, str] = {}  # name -> reason

    def summary(self) -> str:
        lines = [f"  {n:<16} registered" for n in self.registered]
        lines += [f"  {n:<16} skipped ({reason})" for n, reason in self.skipped.items()]
        return "\n".join(lines)


def build_adapter_host(
    adapters: list[str],
    *,
    host_id: str = "chp-host",
    store_path: str | Path = ".chp/host.sqlite",
    metadata: dict | None = None,
) -> tuple[LocalCapabilityHost, AdapterBuildResult]:
    """Build a ``LocalCapabilityHost`` serving the named installed adapters.

    *adapters* are entry-point names from the ``chp.adapters`` group. Unknown
    names and adapters that fail to instantiate are recorded in the result's
    ``skipped`` map rather than raising, so the host always comes up.
    """
    installed = discover_adapters()
    host = LocalCapabilityHost(
        host_id,
        store=SQLiteEvidenceStore(str(store_path)),
        metadata=metadata or {"description": f"CHP adapter host: {', '.join(adapters)}"},
    )

    result = AdapterBuildResult()
    for name in adapters:
        adapter_cls = installed.get(name)
        if adapter_cls is None:
            result.skipped[name] = "not installed"
            warnings.warn(
                f"adapter {name!r} is not installed (chp.adapters entry points); skipping",
                stacklevel=2,
            )
            continue
        try:
            register_adapter(host, adapter_cls())
            result.registered.append(name)
        except Exception as exc:  # one broken adapter must not break the host
            result.skipped[name] = f"error: {exc}"
            warnings.warn(f"failed to register adapter {name!r}: {exc}", stacklevel=2)

    return host, result


def available_adapters() -> list[str]:
    """Return the sorted names of all installed ``chp.adapters`` entry points."""
    return sorted(discover_adapters().keys())
