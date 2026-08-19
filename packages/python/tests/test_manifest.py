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
