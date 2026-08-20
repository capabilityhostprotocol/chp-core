"""Tests for chp_core.manifest — the product manifest authoring format + overlay merge."""

from __future__ import annotations

import pytest

from chp_core.manifest import manifest_hash, merge_manifests, parse_manifest
from chp_core.product import resolve
from chp_core.types import CapabilityDescriptor


def _desc(cid, ver="1.0.0", **kw):
    return CapabilityDescriptor(id=cid, version=ver, description="x", **kw)


BASE = {
    "id": "product:chp-crm", "version": "0.1.0",
    "requires": [{"capability": "crm.deal.list", "range": ">=1.0"}],
    "entitlements": {"crm.": "read-pack"},
    "surfaces": [{"slot": "pipeline", "capability": "crm.deal.list",
                  "surface": "crm.board", "authority": "read_only"}],
    "assurance": "S2", "projection": "passthrough",
    "ui": {"archetype": "data-driven", "routes": [
        {"id": "pipeline", "path": "/pipeline", "component": "chp.widgets.Board",
         "bindings": [{"card": "board", "capability": "crm.deal.list", "extract": "deals"}]}]},
}


def test_parse_manifest_builds_a_resolvable_spec():
    spec = parse_manifest(BASE)
    assert spec.id == "product:chp-crm"
    assert spec.ui.archetype == "data-driven"
    # it materializes: resolve against a matching descriptor
    lock = resolve(spec, [_desc("crm.deal.list", "1.0.0")])
    assert lock.to_dict()["ui"]["routes"][0]["bindings"][0]["capability"] == "crm.deal.list"


def test_parse_requires_id_and_version():
    with pytest.raises(ValueError):
        parse_manifest({"id": "x"})


def test_merge_overlays_surfaces_by_slot_and_entitlements_deep():
    overlay = {
        "version": "0.2.0",
        "entitlements": {"crm.deal.advance": "write-pack"},
        "surfaces": [{"slot": "pipeline", "capability": "crm.deal.list", "surface": "crm.board.v2",
                      "authority": "authoring"}],  # same slot → replaces
    }
    merged = merge_manifests(BASE, overlay)
    assert merged["version"] == "0.2.0"                       # scalar: overlay wins
    assert merged["entitlements"] == {"crm.": "read-pack", "crm.deal.advance": "write-pack"}  # deep
    assert len(merged["surfaces"]) == 1                        # merged by slot, not appended
    assert merged["surfaces"][0]["surface"] == "crm.board.v2"  # replaced


def test_merge_appends_new_surface_slots():
    overlay = {"surfaces": [{"slot": "contacts", "capability": "crm.contact.list",
                             "surface": "crm.people", "authority": "read_only"}]}
    merged = merge_manifests(BASE, overlay)
    assert {s["slot"] for s in merged["surfaces"]} == {"pipeline", "contacts"}


def test_manifest_hash_is_stable_and_order_independent():
    a = manifest_hash(BASE)
    reordered = {k: BASE[k] for k in reversed(list(BASE))}
    assert a.startswith("sha256:")
    assert a == manifest_hash(reordered)  # canonical → key-order independent


def test_parse_manifest_reads_views_and_resolves_a_view_bound_route():
    from chp_core.product import resolve
    from chp_core.types import CapabilityDescriptor
    m = {
        "id": "product:v", "version": "0.1.0",
        "requires": [{"capability": "a.src"}],
        "ui": {"archetype": "data-driven",
               "views": [{"id": "v.stats", "source_capability": "a.src",
                          "output_schema": {"type": "object"}, "audience": "ops"}],
               "routes": [{"id": "r", "path": "/", "component": "chp.widgets.StatGrid",
                           "bindings": [{"card": "stats", "capability": "v.stats", "extract": "stats"}]}]},
    }
    spec = parse_manifest(m)
    assert spec.ui.views[0].source_capability == "a.src"
    assert spec.ui.view_sources() == {"v.stats": "a.src"}
    d = CapabilityDescriptor(id="a.src", version="1.0.0", description="x",
                             input_schema={"type": "object"}, output_schema={"type": "object"},
                             side_effects="read", idempotency="required")
    lock = resolve(spec, [d])          # binds a.src; the View id is a valid binding target
    assert lock.to_dict()["ui"]["views"][0]["audience"] == "ops"


def test_static_props_parse_and_ride_the_lock():
    from chp_core.product import resolve
    from chp_core.types import CapabilityDescriptor
    m = {"id": "product:p", "version": "0.1.0", "requires": [{"capability": "a.src"}],
         "ui": {"routes": [{"id": "t", "path": "/", "component": "chp.widgets.DataTable",
                            "props": {"columns": [{"key": "name"}]},
                            "bindings": [{"card": "items", "capability": "a.src"}]}]}}
    spec = parse_manifest(m)
    assert spec.ui.routes[0].props == {"columns": [{"key": "name"}]}
    d = CapabilityDescriptor(id="a.src", version="1.0.0", description="x",
                             input_schema={"type": "object"}, output_schema={"type": "object"},
                             side_effects="read", idempotency="required")
    assert resolve(spec, [d]).to_dict()["ui"]["routes"][0]["props"] == {"columns": [{"key": "name"}]}


def test_detail_binding_parses_rides_lock_and_validates_bound():
    from chp_core.product import ResolutionError, resolve
    from chp_core.types import CapabilityDescriptor
    def d(cid): return CapabilityDescriptor(id=cid, version="1.0.0", description="x",
                                            input_schema={"type": "object"}, output_schema={"type": "object"},
                                            side_effects="read", idempotency="required")
    m = {"id": "product:md", "version": "0.1.0",
         "requires": [{"capability": "kg.list_nodes"}, {"capability": "kg.get_node"}],
         "ui": {"routes": [{"id": "nodes", "path": "/", "component": "chp.widgets.DataTable",
                            "bindings": [{"card": "items", "capability": "kg.list_nodes", "extract": "nodes",
                                          "detail": {"capability": "kg.get_node", "key": "node_id", "param": "id"}}]}]}}
    spec = parse_manifest(m)
    assert spec.ui.routes[0].bindings[0].detail["capability"] == "kg.get_node"
    lock = resolve(spec, [d("kg.list_nodes"), d("kg.get_node")])
    assert lock.to_dict()["ui"]["routes"][0]["bindings"][0]["detail"]["key"] == "node_id"  # rides the Lock
    # an unbound detail cap → ResolutionError (authority conservation on the drill-down)
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [d("kg.list_nodes")])
    assert "route_detail_unbound:nodes:kg.get_node" in str(exc.value)
