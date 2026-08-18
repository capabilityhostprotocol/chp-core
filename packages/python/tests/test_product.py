"""Tests for chp_core.product — the Materialized Product composition layer (resolver + signed Lock)."""
from __future__ import annotations

import tempfile

import pytest

from chp_core.product import (
    ProductSpecification, Requirement, ResolutionError, SurfaceBinding,
    resolve, sign_lock, verify_lock,
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
