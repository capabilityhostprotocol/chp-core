"""Tests for chp_core.product — the Materialized Product composition layer (resolver + signed Lock)."""
from __future__ import annotations

import tempfile

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
