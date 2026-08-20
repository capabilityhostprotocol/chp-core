"""Tests for chp_core.product — the Materialized Product composition layer (resolver + signed Lock)."""
from __future__ import annotations

import tempfile
from dataclasses import replace

import pytest

from chp_core.product import (
    CONFORMANCE_CHECKS, ComponentRef, ProductSpecification, Requirement, ResolutionError,
    SurfaceBinding, check_conformance, resolve, sign_lock, verify_lock,
)
from chp_core.signing import generate_keypair
from chp_core.types import CapabilityDescriptor


def _desc(cid: str, ver: str, deps: list[str] | None = None) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        id=cid, version=ver, description="x",
        input_schema={"type": "object"}, output_schema={"type": "object"},
        side_effects="write", idempotency="optional", depends_on=deps,
    )


@pytest.fixture
def descriptors() -> list[CapabilityDescriptor]:
    return [
        _desc("a.one", "1.2.0", deps=["a.dep"]),
        _desc("a.one", "1.0.0"),
        _desc("a.dep", "0.3.0"),
        _desc("a.two", "2.0.0"),
    ]


@pytest.fixture
def spec() -> ProductSpecification:
    return ProductSpecification(
        id="product:t", version="0.1.0",
        requires=[Requirement("a.one", ">=1.0 <2"), Requirement("a.two", ">=2.0 <3")],
        entitlements={"a.two": "pack-x"},
    )


def test_resolve_picks_best_version_and_pulls_depends_on(spec, descriptors):
    lock = resolve(spec, descriptors)
    got = {b.capability: b.version for b in lock.bindings}
    assert got == {"a.one": "1.2.0", "a.two": "2.0.0", "a.dep": "0.3.0"}


def test_resolution_is_order_independent(spec, descriptors):
    a = resolve(spec, descriptors)
    b = resolve(spec, list(reversed(descriptors)))
    assert a.digest == b.digest


def test_lock_bindings_project_to_both_tools_and_components():
    # Frontend-as-capability end-to-end: ONE resolved Lock whose bound capability set
    # includes a compute cap AND a render-capability projects to an agent tool-set (all
    # bound caps) AND a component-set (only the render caps) — the same Lock, two consumers.
    from chp_core.agent_interface import (
        capabilities_to_component_list,
        capabilities_to_tool_list,
    )

    compute = _desc("legal.docket.read", "1.0.0")
    render = CapabilityDescriptor(
        id="chp.widgets.DocketView", version="1.0.0", description="docket view",
        category="component", input_schema={"type": "object"},
    )
    spec = ProductSpecification(
        id="product:legal", version="0.1.0",
        requires=[Requirement("legal.docket.read", ">=1.0"),
                  Requirement("chp.widgets.DocketView", ">=1.0")],
    )
    lock = resolve(spec, [compute, render])
    bound = {b.capability for b in lock.bindings}
    assert bound == {"legal.docket.read", "chp.widgets.DocketView"}

    by_id = {compute.id: compute, render.id: render}
    descs = [by_id[b.capability] for b in lock.bindings]
    assert len(capabilities_to_tool_list(descs)) == 2          # both invocable
    components = capabilities_to_component_list(descs)
    assert [c["name"] for c in components] == ["chp.widgets.DocketView"]  # only the render cap


def test_contract_digest_excludes_authority(spec, descriptors):
    # authority (entitlements) lives on the lock, never inside a binding's contractDigest
    lock = resolve(spec, descriptors)
    binding = next(b for b in lock.bindings if b.capability == "a.two")
    assert "pack-x" not in binding.contract_digest
    assert lock.entitlements == {"a.two": "pack-x"}


def test_unsatisfiable_requirement_raises(descriptors):
    bad = ProductSpecification("product:t", "0.1.0", [Requirement("a.one", ">=9.0")])
    with pytest.raises(ResolutionError) as exc:
        resolve(bad, descriptors)
    assert "unresolved:a.one" in str(exc.value)


def test_missing_dependency_raises(spec):
    # a.one 1.2.0 depends_on a.dep, which is absent here
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.one", "1.2.0", deps=["a.dep"]), _desc("a.two", "2.0.0")])
    assert "unresolved_dependency:a.dep" in str(exc.value)


def test_surface_binding_emitted_into_lock(descriptors):
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.one", ">=1.0 <2"), Requirement("a.two", ">=2.0 <3")],
        surfaces=[SurfaceBinding(slot="main", capability="a.two", surface="a.two.console",
                                 authority="governed_mutation")])
    lock = resolve(spec, descriptors)
    surfaces = lock.to_dict()["surfaces"]
    assert len(surfaces) == 1
    s = surfaces[0]
    assert s["slot"] == "main" and s["capability"] == "a.two" and s["authority"] == "governed_mutation"
    assert s["surfaceDigest"].startswith("sha256:")


def test_surface_on_unbound_capability_is_authority_conservation_violation(descriptors):
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        surfaces=[SurfaceBinding("main", "a.NOT_BOUND", "s", "read_only")])
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, descriptors)
    assert "surface_unknown_capability:main:a.NOT_BOUND" in str(exc.value)


def test_surface_invalid_authority_rejected(descriptors):
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        surfaces=[SurfaceBinding("main", "a.two", "s", "root")])   # not an atom
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, descriptors)
    assert "surface_invalid_authority:main:root" in str(exc.value)


def test_conformance_all_seven_pass_for_a_valid_product(spec, descriptors):
    results = check_conformance(spec, resolve(spec, descriptors))
    assert [r.check for r in results] == list(CONFORMANCE_CHECKS)
    assert all(r.passed for r in results), [(r.check, r.detail) for r in results if not r.passed]


def test_conformance_flags_wildcard_capability_selection(descriptors):
    bad = ProductSpecification("product:t", "0.1.0", [Requirement("a.*", ">=0.0.0")])
    # resolve won't find "a.*"; test the static check directly against a hand-built lock
    lock = resolve(spec_ok := ProductSpecification("product:t", "0.1.0",
                   [Requirement("a.two", ">=2.0 <3")]), descriptors)
    res = {r.check: r for r in check_conformance(bad, lock)}
    assert res["explicit_capability_selection"].passed is False


def test_invalid_assurance_tier_rejected_at_resolve(descriptors):
    spec = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")], assurance="S9")
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, descriptors)
    assert "invalid_assurance_tier:S9" in str(exc.value)


def test_assurance_tier_is_in_the_lock(descriptors):
    spec = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")], assurance="S3")
    lock = resolve(spec, descriptors)
    assert lock.to_dict()["assurance"] == "S3"


def test_mesh_resolution_marks_remote_and_cross_host(descriptors):
    remote = [_desc("a.remote", "1.0.0")]
    spec = ProductSpecification("product:t", "0.1.0",
                                [Requirement("a.two", ">=2.0 <3"), Requirement("a.remote", ">=1.0")])
    lock = resolve(spec, descriptors, remote_descriptors=remote)
    locs = {b.capability: b.locality for b in lock.bindings}
    assert locs["a.two"] == "local"
    assert locs["a.remote"] == "remote"
    assert lock.to_dict()["isCrossHost"] is True


def test_local_only_product_is_not_cross_host(spec, descriptors):
    assert resolve(spec, descriptors).to_dict()["isCrossHost"] is False


def test_local_preferred_over_remote(descriptors):
    # a.two exists locally AND remotely → resolves local
    remote = [_desc("a.two", "2.0.0")]
    spec = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")])
    lock = resolve(spec, descriptors, remote_descriptors=remote)
    assert lock.bindings[0].locality == "local"


def test_projection_recorded_in_lock(descriptors):
    spec = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")], projection="merge")
    assert resolve(spec, descriptors).to_dict()["projection"] == "merge"


def test_surface_pins_a_content_addressed_component(descriptors):
    comp = ComponentRef(name="chp.widgets.EvidenceTree", version="1.0.0", content_hash="sha256:abc")
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        surfaces=[SurfaceBinding("audit", "a.two", "a.two.viewer", "read_only", component=comp)])
    surfaces = resolve(spec, descriptors).to_dict()["surfaces"]
    assert surfaces[0]["component"] == {"name": "chp.widgets.EvidenceTree", "version": "1.0.0",
                                        "contentHash": "sha256:abc"}
    # the component is part of the surface's content-addressed identity
    bare = SurfaceBinding("audit", "a.two", "a.two.viewer", "read_only")
    assert bare.digest() != SurfaceBinding("audit", "a.two", "a.two.viewer", "read_only", component=comp).digest()


def test_product_ui_schema_rides_in_the_lock_and_validates_route_bindings():
    from chp_core.product import ProductUISchema, Route, RouteBinding
    spec = ProductSpecification(
        "product:t", "0.1.0",
        [Requirement("a.two", ">=2.0 <3"), Requirement("chp.crm.DealBoard", ">=1.0")],
        ui=ProductUISchema(archetype="data-driven", routes=[
            Route(id="pipeline", path="/pipeline", component="chp.crm.DealBoard",
                  bindings=[RouteBinding(card="board", capability="a.two", extract="deals")])]))
    # a route's federated component must be a BOUND render-capability (route.component is now validated)
    lock = resolve(spec, [_desc("a.two", "2.0.0"), _render_desc("chp.crm.DealBoard")])
    ui = lock.to_dict()["ui"]
    assert ui["archetype"] == "data-driven"
    assert ui["routes"][0]["bindings"][0] == {"card": "board", "capability": "a.two", "extract": "deals"}
    # the ui rides in the digest — changing a route binding changes the lock
    spec2 = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")])
    assert resolve(spec2, [_desc("a.two", "2.0.0")]).digest != lock.digest


def test_route_binding_must_reference_a_bound_capability():
    from chp_core.product import ProductUISchema, Route, RouteBinding
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        ui=ProductUISchema(routes=[Route(id="r", bindings=[
            RouteBinding(card="c", capability="a.NOT_BOUND")])]))
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.two", "2.0.0")])
    assert "route_unknown_capability:a.NOT_BOUND" in str(exc.value)


def test_unknown_archetype_rejected():
    from chp_core.product import ProductUISchema
    spec = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
                                ui=ProductUISchema(archetype="nonsense"))
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.two", "2.0.0")])
    assert "unknown_archetype:nonsense" in str(exc.value)


def test_routes_and_regions_accept_builtin_chp_ui_components():
    # Composable apps: a route OR a composite-page region may mount a built-in @chp/ui component directly —
    # no product render-capability required (built-ins are the always-available floor). Only DATA bindings
    # must resolve to bound capabilities.
    from chp_core.product import ProductUISchema, Region, Route, RouteBinding
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        ui=ProductUISchema(routes=[
            Route(id="table", path="/", component="chp.widgets.DataTable",
                  bindings=[RouteBinding(card="items", capability="a.two", extract="rows")]),
            Route(id="page", path="/p", layout="grid", regions=[
                Region(id="stats", component="chp.molecules.StatCard",
                       bindings=[RouteBinding(card="stats", capability="a.two")])])]))
    assert resolve(spec, [_desc("a.two", "2.0.0")]).digest     # no render-caps registered; built-ins are fine


def test_route_component_is_validated_and_rejects_unknown_component():
    # The gap is closed: a route.component that is neither a bound render-cap nor a built-in dialect fails.
    from chp_core.product import ProductUISchema, Route, RouteBinding
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        ui=ProductUISchema(routes=[Route(id="r", path="/", component="acme.Widget",
            bindings=[RouteBinding(card="c", capability="a.two")])]))
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.two", "2.0.0")])
    assert "route_unknown_component:r:acme.Widget" in str(exc.value)


def _render_desc(cid: str, ver: str = "1.0.0") -> CapabilityDescriptor:
    return CapabilityDescriptor(id=cid, version=ver, description="render",
                                category="component", input_schema={"type": "object"})


def test_region_slots_ride_in_the_lock_and_conserve_authority():
    # A composite page = a route with named regions, each a self-binding render-capability.
    from chp_core.product import ProductUISchema, Region, Route, RouteBinding
    spec = ProductSpecification(
        "product:t", "0.1.0",
        [Requirement("a.two", ">=2.0 <3"), Requirement("chp.crm.Timeline", ">=1.0")],
        ui=ProductUISchema(routes=[Route(
            id="record", path="/record", layout="grid", regions=[
                Region(id="timeline", component="chp.crm.Timeline", span=2,
                       bindings=[RouteBinding(card="items", capability="a.two", extract="deals")])])]))
    lock = resolve(spec, [_desc("a.two", "2.0.0"), _render_desc("chp.crm.Timeline")])
    route = lock.to_dict()["ui"]["routes"][0]
    assert route["layout"] == "grid"
    reg = route["regions"][0]
    assert reg["id"] == "timeline" and reg["component"] == "chp.crm.Timeline" and reg["span"] == 2
    assert reg["bindings"][0] == {"card": "items", "capability": "a.two", "extract": "deals"}
    # regions ride in the signed digest — dropping them changes the lock
    spec2 = ProductSpecification("product:t", "0.1.0",
                                 [Requirement("a.two", ">=2.0 <3"), Requirement("chp.crm.Timeline", ">=1.0")])
    assert resolve(spec2, [_desc("a.two", "2.0.0"), _render_desc("chp.crm.Timeline")]).digest != lock.digest


def test_region_binding_must_reference_a_bound_capability():
    from chp_core.product import ProductUISchema, Region, Route, RouteBinding
    spec = ProductSpecification(
        "product:t", "0.1.0",
        [Requirement("a.two", ">=2.0 <3"), Requirement("chp.crm.Timeline", ">=1.0")],
        ui=ProductUISchema(routes=[Route(id="rec", regions=[
            Region(id="t", component="chp.crm.Timeline",
                   bindings=[RouteBinding(card="c", capability="a.NOT_BOUND")])])]))
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.two", "2.0.0"), _render_desc("chp.crm.Timeline")])
    assert "region_unknown_capability:t:a.NOT_BOUND" in str(exc.value)


def test_region_component_must_be_a_bound_renderable_capability():
    from chp_core.product import ProductUISchema, Region, Route
    # (a) component not bound at all
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        ui=ProductUISchema(routes=[Route(id="rec", regions=[Region(id="t", component="chp.crm.NOPE")])]))
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.two", "2.0.0")])
    assert "region_unknown_component:t:chp.crm.NOPE" in str(exc.value)
    # (b) component bound but NOT a render-capability (a compute cap can't be a region's component)
    spec2 = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        ui=ProductUISchema(routes=[Route(id="rec", regions=[Region(id="t", component="a.two")])]))
    with pytest.raises(ResolutionError) as exc2:
        resolve(spec2, [_desc("a.two", "2.0.0")])
    assert "region_component_not_renderable:t:a.two" in str(exc2.value)


def test_region_slots_manifest_roundtrip():
    from chp_core.manifest import parse_manifest
    m = {"id": "product:t", "version": "0.1.0",
         "requires": [{"capability": "a.two", "range": ">=2.0 <3"},
                      {"capability": "chp.crm.Timeline", "range": ">=1.0"}],
         "ui": {"routes": [{"id": "record", "layout": "stack", "regions": [
             {"id": "timeline", "component": "chp.crm.Timeline", "span": 2,
              "bindings": [{"card": "items", "capability": "a.two", "extract": "deals"}]}]}]}}
    spec = parse_manifest(m)
    r = spec.ui.routes[0]
    assert r.layout == "stack" and r.regions[0].id == "timeline" and r.regions[0].span == 2
    assert r.regions[0].bindings[0].capability == "a.two"
    lock = resolve(spec, [_desc("a.two", "2.0.0"), _render_desc("chp.crm.Timeline")])
    assert lock.to_dict()["ui"]["routes"][0]["regions"][0]["component"] == "chp.crm.Timeline"


def _render_cap(cid: str, ver: str, content_hash: str | None = None) -> CapabilityDescriptor:
    meta = {"content_hash": content_hash} if content_hash else {}
    return CapabilityDescriptor(id=cid, version=ver, description="ui", category="component",
                                input_schema={"type": "object"}, metadata=meta)


def test_surface_names_render_capability_and_derives_component_ref():
    # Frontend-as-capability: the surface names a BOUND render-capability by id; resolve derives the
    # legacy ComponentRef from that capability's binding (pinned by its own contract, not authored).
    view = _render_cap("chp.widgets.DocketView", "2.1.0", content_hash="sha256:bundle")
    spec = ProductSpecification(
        "product:t", "0.1.0",
        [Requirement("a.two", ">=2.0 <3"), Requirement("chp.widgets.DocketView", ">=2.0")],
        surfaces=[SurfaceBinding("main", "a.two", "a.two.console", "authoring",
                                 component_capability="chp.widgets.DocketView")])
    s = resolve(spec, [_desc("a.two", "2.0.0"), view]).to_dict()["surfaces"][0]
    assert s["componentCapability"] == "chp.widgets.DocketView"
    assert s["component"] == {"name": "chp.widgets.DocketView", "version": "2.1.0",
                              "contentHash": "sha256:bundle"}  # derived from the bound render-cap


def test_surface_component_capability_must_be_bound():
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        surfaces=[SurfaceBinding("main", "a.two", "s", "read_only",
                                 component_capability="chp.widgets.NOPE")])
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.two", "2.0.0")])
    assert "surface_unknown_component:main:chp.widgets.NOPE" in str(exc.value)


def test_surface_component_capability_must_be_renderable():
    # a bound but non-render capability cannot be a surface's UI — surface authority conservation
    spec = ProductSpecification(
        "product:t", "0.1.0",
        [Requirement("a.two", ">=2.0 <3"), Requirement("a.compute", ">=1.0")],
        surfaces=[SurfaceBinding("main", "a.two", "s", "read_only",
                                 component_capability="a.compute")])
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.two", "2.0.0"), _desc("a.compute", "1.0.0")])
    assert "surface_component_not_renderable:main:a.compute" in str(exc.value)


def test_sign_and_verify_roundtrip(spec, descriptors):
    lock = resolve(spec, descriptors)
    key = generate_keypair(tempfile.mkdtemp(), overwrite=True)
    sign_lock(lock, key)
    ok, reason = verify_lock(lock, key.public_key_b64)
    assert ok, reason


def test_tamper_fails_closed(spec, descriptors):
    lock = resolve(spec, descriptors)
    key = generate_keypair(tempfile.mkdtemp(), overwrite=True)
    sign_lock(lock, key)
    lock.entitlements["a.two"] = "pack-TAMPERED"
    ok, reason = verify_lock(lock, key.public_key_b64)
    assert not ok and reason == "lock_digest_invalid"


def test_view_is_a_derived_capability_binding_targets_it_and_source_must_be_bound():
    # A first-class View {id, source_capability, output_schema}: a route binds it by id (a view IS a
    # capability), and the View's source_capability must be a BOUND cap (authority conservation).
    from chp_core.product import ProductUISchema, Route, RouteBinding, View
    ui = ProductUISchema(
        archetype="data-driven",
        routes=[Route(id="r", path="/", component="chp.widgets.StatGrid",
                      bindings=[RouteBinding(card="stats", capability="v.stats", extract="stats")])],
        views=[View(id="v.stats", source_capability="a.two",
                    output_schema={"type": "object"})])
    spec = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")], ui=ui)
    lock = resolve(spec, [_desc("a.two", "2.0.0")])       # v.stats need NOT be a registered descriptor
    assert lock.to_dict()["ui"]["views"][0] == {
        "id": "v.stats", "sourceCapability": "a.two", "outputSchema": {"type": "object"}}


def test_view_rides_the_lock_digest_and_is_guarded_for_backcompat():
    from chp_core.product import ProductUISchema, Route, RouteBinding, View
    base = ProductUISchema(routes=[Route(id="r", path="/", component="chp.widgets.StatGrid",
                                         bindings=[RouteBinding(card="stats", capability="a.two")])])
    with_view = replace(base, views=[View(id="v.x", source_capability="a.two")])
    spec_no = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")], ui=base)
    spec_yes = ProductSpecification("product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")], ui=with_view)
    lock_no, lock_yes = resolve(spec_no, [_desc("a.two", "2.0.0")]), resolve(spec_yes, [_desc("a.two", "2.0.0")])
    assert "views" not in lock_no.to_dict()["ui"]          # guarded: a view-less lock keeps its old shape
    assert lock_yes.digest != lock_no.digest               # declaring a View rides the digest


def test_view_with_unbound_source_is_rejected():
    from chp_core.product import ProductUISchema, View
    spec = ProductSpecification(
        "product:t", "0.1.0", [Requirement("a.two", ">=2.0 <3")],
        ui=ProductUISchema(views=[View(id="v.x", source_capability="a.MISSING")]))
    with pytest.raises(ResolutionError) as exc:
        resolve(spec, [_desc("a.two", "2.0.0")])
    assert "view_unbound_source:v.x:a.MISSING" in str(exc.value)
