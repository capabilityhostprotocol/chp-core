"""capabilities.txt discovery projection (proposal 0049, Tier C; CHP-SUP-009/010/011).

Projects a host's capability definitions into a capabilities.txt document — a lightweight,
machine-discoverable capability surface. It is a DISCOVERY projection ONLY: not an execution or
authorization document (CHP-SUP-009). It lists each capability's id/version/description plus href
pointers to its bindings and offers, and encodes NO admission/authorization/qualification
conclusions — those are contextual and derived at admission, never advertised as facts. The
capability id is canonical across interfaces (CHP-SUP-011), and the projection is stable
(CHP-SUP-010): the same supply yields the same document.
"""

from __future__ import annotations

from typing import Any

from .types import JSON

# Fields a discovery projection MUST NEVER carry — advertising them would turn discovery into a
# false claim of admission/authorization/qualification (CHP-SUP-009).
_FORBIDDEN = frozenset({"admitted", "authorized", "approved", "qualified", "trusted", "grant"})


def _field(cap: Any, name: str) -> Any:
    return cap.get(name) if isinstance(cap, dict) else getattr(cap, name, None)


def project_capabilities_txt(
    *,
    host: JSON,
    capabilities: list[Any],
    chp_version: str = "0.1",
    base_href: str = "/capabilities",
) -> JSON:
    """Project ``capabilities`` (CapabilityDefinitions or dicts) into a capabilities.txt document
    for ``host`` ({id, name}). Discovery-only: id/version/description + href pointers to
    bindings/offers, no admission/authorization fields (see module docstring)."""
    caps: list[JSON] = []
    for c in capabilities:
        cid = _field(c, "id")
        caps.append({
            "id": cid,
            "version": _field(c, "version"),
            "description": _field(c, "description") or "",
            "bindings": {"href": f"{base_href}/{cid}/bindings"},
            "offers": {"href": f"{base_href}/{cid}/offers"},
        })
    doc: JSON = {"chp": chp_version, "host": host, "capabilities": caps}
    # Defensive: a discovery projection must never advertise a permanent conclusion. This asserts
    # the invariant on our own output rather than trusting the inputs.
    _assert_discovery_only(doc)
    return doc


def host_capabilities_txt(descriptor: JSON, *, chp_version: str = "0.1",
                          base_href: str = "/capabilities") -> JSON:
    """Project a LIVE host descriptor (from ``LocalCapabilityHost.discover()`` / GET /host) into a
    capabilities.txt document — the end-to-end discovery link (CHP-SUP-009/010/011): a running CHP
    host self-publishes its semantic capabilities without a hand-authored feed. The descriptor's
    capability entries (id/version/description) are projected discovery-only; admission/authorization
    is never advertised (project_capabilities_txt enforces this)."""
    host = {k: descriptor[k] for k in ("id", "name") if descriptor.get(k) is not None}
    return project_capabilities_txt(
        host=host, capabilities=descriptor.get("capabilities", []),
        chp_version=chp_version, base_href=base_href)


def _assert_discovery_only(doc: JSON) -> None:
    def scan(obj: Any) -> None:
        if isinstance(obj, dict):
            bad = _FORBIDDEN & {k for k, v in obj.items() if v}
            if bad:
                raise ValueError(f"capabilities.txt is discovery-only; forbidden fields: {sorted(bad)}")
            for v in obj.values():
                scan(v)
        elif isinstance(obj, list):
            for v in obj:
                scan(v)

    scan(doc)
