"""Product manifest — the authoring format for a Materialized Product (harvested from chp-runtime).

A manifest is a plain dict (loaded from JSON/YAML by the caller — core stays dependency-free) that
declares a product: its capability requirements, entitlements, surfaces, and a UI (archetype + routes +
bindings). :func:`parse_manifest` turns it into a :class:`ProductSpecification` (which ``materialize()``
resolves into a signed Lock). :func:`merge_manifests` composes a base with overlays (env layering / a
product family). :func:`manifest_hash` is the content hash for evidence/integrity.

The manifest is the ℋ Header; the Lock is the materialized artifact. One format, dual-impl-ready — the
same dict drives the Python and TS-SDK resolvers to the same Lock digest.
"""

from __future__ import annotations

from .product import (
    ProductSpecification,
    ProductUISchema,
    Region,
    Requirement,
    Route,
    RouteBinding,
    SurfaceBinding,
    product_digest,
)

__all__ = ["parse_manifest", "merge_manifests", "manifest_hash"]


def _binding(b: dict) -> RouteBinding:
    return RouteBinding(card=b["card"], capability=b["capability"],
                        params=b.get("params"), extract=b.get("extract"))


def _parse_ui(ui: dict) -> ProductUISchema:
    routes = [
        Route(
            id=r["id"], path=r.get("path"), label=r.get("label"), icon=r.get("icon"),
            view=r.get("view"), component=r.get("component"),
            bindings=[_binding(b) for b in r.get("bindings", [])],
            regions=[
                Region(id=reg["id"], label=reg.get("label"), component=reg.get("component"),
                       bindings=[_binding(b) for b in reg.get("bindings", [])], span=reg.get("span"))
                for reg in r.get("regions", [])
            ],
            layout=r.get("layout"),
        )
        for r in ui.get("routes", [])
    ]
    return ProductUISchema(archetype=ui.get("archetype"), routes=routes,
                           auth=ui.get("auth"), tenancy=ui.get("tenancy"))


def parse_manifest(data: dict) -> ProductSpecification:
    """Build a :class:`ProductSpecification` from a manifest dict. ``requires`` may be omitted — then
    ``materialize()`` binds every capability the provisioned adapters register (provision-these-adapters
    default)."""
    if "id" not in data or "version" not in data:
        raise ValueError("manifest requires 'id' and 'version'")
    return ProductSpecification(
        id=data["id"],
        version=data["version"],
        requires=[Requirement(capability=r["capability"], range=r.get("range", ">=0.0.0"))
                  for r in data.get("requires", [])],
        entitlements=dict(data.get("entitlements", {})),
        surfaces=[
            SurfaceBinding(slot=s["slot"], capability=s["capability"], surface=s["surface"],
                           authority=s["authority"], component_capability=s.get("component_capability"))
            for s in data.get("surfaces", [])
        ],
        assurance=data.get("assurance", "S1"),
        projection=data.get("projection", "passthrough"),
        ui=_parse_ui(data["ui"]) if data.get("ui") else None,
    )


def _merge_list_by_key(base: list, overlay: list, key: str) -> list:
    """Merge two lists of dicts by *key*: an overlay item replaces a base item with the same key,
    else appends (chp-runtime's mergeArrayByKey)."""
    out = list(base)
    index = {item[key]: i for i, item in enumerate(out) if isinstance(item, dict) and key in item}
    for item in overlay:
        k = item.get(key) if isinstance(item, dict) else None
        if k is not None and k in index:
            out[index[k]] = item
        else:
            out.append(item)
    return out


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursive dict merge — overlay wins on scalars; nested dicts merge; lists REPLACE (not merge),
    matching chp-runtime's deepMergeObjects."""
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def merge_manifests(base: dict, *overlays: dict) -> dict:
    """Compose *base* with *overlays* (left→right). Scalars: overlay wins. ``requires``/``surfaces``
    merge by capability/slot; ``entitlements``/``ui`` deep-merge; ``version`` = overlay's if given.
    Enables env layering and product families (core + intelligence) onto one spec."""
    result = dict(base)
    for overlay in overlays:
        merged = dict(result)
        for k, v in overlay.items():
            if k == "requires" and isinstance(v, list):
                merged[k] = _merge_list_by_key(result.get(k, []), v, "capability")
            elif k == "surfaces" and isinstance(v, list):
                merged[k] = _merge_list_by_key(result.get(k, []), v, "slot")
            elif k in ("entitlements", "ui") and isinstance(v, dict) and isinstance(result.get(k), dict):
                merged[k] = _deep_merge(result[k], v)
            else:
                merged[k] = v
        result = merged
    return result


def manifest_hash(data: dict) -> str:
    """``sha256:``-prefixed content hash over the manifest's canonical bytes — the same canon the Lock
    digest uses, so a manifest and the Lock it produces are provably linked."""
    return product_digest(data)
