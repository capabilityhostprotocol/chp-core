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

    _register_openapi_mounts(host, result)
    return host, result


def _register_openapi_mounts(host: LocalCapabilityHost, result: AdapterBuildResult) -> None:
    """Register an openapi-backed adapter per entry in ``~/.chp/openapi-mounts.json``:
    ``[{"name": "anchore", "spec": "<local path or url>", "base_url": "..."}]``. This mounts a service's
    OpenAPI spec as governed ``chp.adapters.openapi.<name>.*`` capabilities *as config* — no package per
    service. Fail-soft; a no-op if the file or chp-adapter-openapi is absent."""
    import json
    import os

    mounts_path = os.path.join(os.path.expanduser("~/.chp"), "openapi-mounts.json")
    try:
        mounts = json.loads(open(mounts_path, encoding="utf-8").read())
    except Exception:
        return
    try:
        from chp_adapter_openapi.adapter import OpenAPIAdapter, OpenAPIConfig
    except Exception:
        warnings.warn("openapi-mounts present but chp-adapter-openapi is not installed; skipping", stacklevel=2)
        return
    for m in (mounts if isinstance(mounts, list) else []):
        name, spec = (m or {}).get("name"), (m or {}).get("spec")
        if not name or not spec:
            continue
        label = f"openapi:{name}"
        try:
            register_adapter(host, OpenAPIAdapter(OpenAPIConfig(
                name=name, spec=spec, base_url=m.get("base_url") or None,
                methods=m.get("methods"), include=m.get("include"), max_ops=m.get("max_ops"))))
            result.registered.append(label)
        except Exception as exc:
            result.skipped[label] = f"error: {exc}"
            warnings.warn(f"failed to mount openapi {name!r}: {exc}", stacklevel=2)


def available_adapters() -> list[str]:
    """Return the sorted names of all installed ``chp.adapters`` entry points."""
    return sorted(discover_adapters().keys())
