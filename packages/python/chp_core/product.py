"""Materialized Product composition — the protocol's build-time artifact.

Where an *evidence bundle* is the signed record of what an invocation *did*, a
**Product Lock** is the signed record of what a product *is made of*: a deterministic,
reproducible resolution of a :class:`ProductSpecification`'s capability requirements
against a set of :class:`~chp_core.types.CapabilityDescriptor` s.

The two separations the composition model rests on:

* **Specification ≠ Lock.** The spec declares requirements as version *ranges*; the lock
  pins each to an exact version + ``contractDigest`` + provider identity. Editing the spec
  never silently rewrites a running lock.
* **Contract ≠ Authority.** ``contractDigest`` covers only the capability's *contract*
  (schema + side-effects + idempotency). *Authority* is external — a CHP capability carries
  no inline ``minimumRole``; it is governed by the entitlement plane at resolution. So the
  lock records an ``entitlements`` binding *alongside* the contract, never folded into it.

Dependency-free. The lock digest reuses :func:`chp_core.signing._canon`, so a lock produced
by the TypeScript SDK (whose canon is wire-identical) hashes to the same value.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .semver import best_satisfying, version_satisfies
from .signing import HostKey, _canon, _sign, _verify_sig
from .types import CapabilityDescriptor

__all__ = [
    "Requirement", "ProductSpecification", "Binding", "ProductLock", "SurfaceBinding",
    "AUTHORITY_CLASSES", "ResolutionError", "resolve", "sign_lock", "verify_lock", "product_digest",
]

# Default resolver policy recorded on every lock so its digest is policy-explicit.
_DEFAULT_POLICY = {"preferLocal": True, "allowRemote": True, "minTrust": "trusted", "maxUnitCost": None}


def product_digest(obj: object) -> str:
    """``sha256:``-prefixed digest over CHP canonical bytes (sorted-key JSON).

    The single hashing primitive under the whole composition model — reused for the
    contract digest, the product semantic digest, and the lock digest, so nested digests
    form a Merkle summary (a lock transitively pins every contract it binds)."""
    return "sha256:" + hashlib.sha256(_canon(obj)).hexdigest()


def contract_digest(d: CapabilityDescriptor) -> str:
    """Pin a capability's CONTRACT — schema + effects + idempotency. Authority is
    deliberately absent (it is external; see the module docstring)."""
    return product_digest({
        "id": d.id,
        "version": d.version,
        "inputSchema": d.input_schema or {"type": "object"},
        "outputSchema": d.output_schema or {"type": "object"},
        "sideEffects": d.side_effects,
        "idempotency": d.idempotency,
    })


class ResolutionError(ValueError):
    """A specification could not be fully resolved (unsatisfiable range or missing dependency)."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = issues
        super().__init__("; ".join(issues))


@dataclass(frozen=True)
class Requirement:
    capability: str
    range: str = ">=0.0.0"          # semver range; default = any


AUTHORITY_CLASSES = ("read_only", "simulation", "authoring", "governed_mutation")


@dataclass(frozen=True)
class SurfaceBinding:
    """A consumer projection of a capability at a declared authority class — the composition half
    of a UI / agent / API surface. ``authority`` is the canonical atom; a surface can never exceed
    it (enforced at the consumer, e.g. ``@chp/ui`` ``<Surface>``). A surface may only project a
    *bound* capability — the authority-conservation invariant, checked in :func:`resolve`."""

    slot: str
    capability: str
    surface: str                     # surface / projection id
    authority: str                   # one of AUTHORITY_CLASSES

    def digest(self) -> str:
        return product_digest({"slot": self.slot, "capability": self.capability,
                               "surface": self.surface, "authority": self.authority})

    def to_dict(self) -> dict:
        return {"slot": self.slot, "capability": self.capability, "surface": self.surface,
                "authority": self.authority, "surfaceDigest": self.digest()}


@dataclass
class ProductSpecification:
    """The declared identity of a product: capability requirements + the authority
    (entitlement) bindings + consumer surfaces. Provider-independent — names no versions/providers."""

    id: str
    version: str
    requires: list[Requirement] = field(default_factory=list)
    entitlements: dict[str, str] = field(default_factory=dict)  # capability-id prefix → entitlement pack
    surfaces: list[SurfaceBinding] = field(default_factory=list)  # UI / agent / API projections

    def semantic_digest(self, bound_capabilities: list[str]) -> str:
        return product_digest({"id": self.id, "version": self.version,
                               "capabilities": sorted(bound_capabilities)})


@dataclass
class Binding:
    capability: str
    version: str
    requested_range: str
    contract_digest: str
    provider: str
    provider_version: str
    package: str
    package_version: str
    locality: str = "local"
    trust: str = "first_party"
    upstream_lock_digest: str | None = None

    def to_dict(self) -> dict:
        # camelCase keys → identical shape (and digest) to the TS-SDK / reference lock.
        return {
            "capability": self.capability, "version": self.version,
            "requestedRange": self.requested_range, "contractDigest": self.contract_digest,
            "providerType": "capability_pack", "provider": self.provider,
            "providerVersion": self.provider_version, "package": self.package,
            "packageVersion": self.package_version, "locality": self.locality,
            "trust": self.trust, "upstreamLockDigest": self.upstream_lock_digest,
        }


@dataclass
class ProductLock:
    product: str
    product_version: str
    product_semantic_digest: str
    bindings: list[Binding]
    entitlements: dict[str, str]
    surfaces: list[SurfaceBinding] = field(default_factory=list)
    resolver_policy: dict = field(default_factory=lambda: dict(_DEFAULT_POLICY))
    digest: str = ""
    signature: dict | None = None

    def _core(self) -> dict:
        """The canonical body the digest is taken over — excludes ``digest``/``signature``,
        bindings sorted by capability so the digest is independent of resolution order."""
        return {
            "product": self.product,
            "productVersion": self.product_version,
            "productSemanticDigest": self.product_semantic_digest,
            "bindings": [b.to_dict() for b in sorted(self.bindings, key=lambda x: x.capability)],
            "resolverPolicy": self.resolver_policy,
            "entitlements": self.entitlements,
            "surfaces": [s.to_dict() for s in sorted(self.surfaces, key=lambda x: x.slot)],
        }

    def compute_digest(self) -> str:
        return product_digest(self._core())

    def to_dict(self) -> dict:
        out = self._core()
        out["digest"] = self.digest or self.compute_digest()
        if self.signature is not None:
            out["signature"] = self.signature
        return out


def _index(descriptors: list[CapabilityDescriptor]) -> dict[str, dict[str, CapabilityDescriptor]]:
    idx: dict[str, dict[str, CapabilityDescriptor]] = {}
    for d in descriptors:
        idx.setdefault(d.id, {})[d.version] = d
    return idx


def _binding_for(d: CapabilityDescriptor, requested_range: str) -> Binding:
    pkg = d.id.rsplit(".", 1)[0] if "." in d.id else d.id
    return Binding(
        capability=d.id, version=d.version, requested_range=requested_range,
        contract_digest=contract_digest(d), provider=d.provider or pkg,
        provider_version=d.version, package=pkg, package_version=d.version,
    )


def resolve(spec: ProductSpecification, descriptors: list[CapabilityDescriptor],
            *, policy: dict | None = None) -> ProductLock:
    """Deterministically resolve *spec* against *descriptors* into an (unsigned) ProductLock.

    For each explicit requirement the highest version satisfying its range is chosen, then
    the transitive ``depends_on`` closure is pulled in (each dependency resolved to its
    highest available version). Raises :class:`ResolutionError` listing every unsatisfiable
    requirement / missing dependency."""
    idx = _index(descriptors)
    chosen: dict[str, CapabilityDescriptor] = {}
    ranges: dict[str, str] = {}
    issues: list[str] = []

    # explicit requirements
    frontier: list[str] = []
    for req in spec.requires:
        versions = list(idx.get(req.capability, {}))
        picked = best_satisfying(versions, req.range) if versions else None
        if picked is None:
            issues.append(f"unresolved:{req.capability} (range {req.range})")
            continue
        chosen[req.capability] = idx[req.capability][picked]
        ranges[req.capability] = req.range
        frontier.append(req.capability)

    # transitive depends_on closure (activating CapabilityDescriptor.depends_on)
    while frontier:
        cap = frontier.pop()
        for dep in (chosen[cap].depends_on or []):
            if dep in chosen:
                continue
            versions = list(idx.get(dep, {}))
            if not versions:
                issues.append(f"unresolved_dependency:{dep} (required by {cap})")
                continue
            picked = best_satisfying(versions, ">=0.0.0")
            chosen[dep] = idx[dep][picked]
            ranges[dep] = f"^{picked}"  # dependency pin: same-major
            frontier.append(dep)

    # surface bindings — authority conservation: a surface may only project a BOUND capability,
    # and its authority must be a valid atom. A surface can never invent authority the product lacks.
    for s in spec.surfaces:
        if s.authority not in AUTHORITY_CLASSES:
            issues.append(f"surface_invalid_authority:{s.slot}:{s.authority}")
        if s.capability not in chosen:
            issues.append(f"surface_unknown_capability:{s.slot}:{s.capability}")

    if issues:
        raise ResolutionError(issues)

    bindings = [_binding_for(d, ranges[cap]) for cap, d in chosen.items()]
    lock = ProductLock(
        product=spec.id, product_version=spec.version,
        product_semantic_digest=spec.semantic_digest([b.capability for b in bindings]),
        bindings=bindings, entitlements=dict(spec.entitlements),
        surfaces=list(spec.surfaces),
        resolver_policy=dict(policy or _DEFAULT_POLICY),
    )
    lock.digest = lock.compute_digest()
    return lock


def sign_lock(lock: ProductLock, host_key: HostKey) -> ProductLock:
    """Sign a lock's digest with an Ed25519 host key, promoting it to a verifiable artifact.
    Mutates and returns *lock*. Requires a key that ``can_sign``."""
    if not host_key.can_sign:
        raise ValueError("host_key cannot sign (no private key loaded)")
    lock.digest = lock.compute_digest()
    lock.signature = {
        "algorithm": "Ed25519", "keyId": host_key.key_id,
        "signedDigest": lock.digest, "signature": _sign(host_key._private, lock.digest.encode()),
    }
    return lock


def verify_lock(lock: ProductLock, public_key_b64: str) -> tuple[bool, str]:
    """Verify a signed lock. Returns ``(ok, reason)`` — fail-closed: the digest must recompute
    to the signed digest AND the Ed25519 signature must verify."""
    sig = lock.signature
    if not sig:
        return False, "lock_signature_missing"
    recomputed = lock.compute_digest()
    if recomputed != sig.get("signedDigest") or recomputed != (lock.digest or recomputed):
        return False, "lock_digest_invalid"
    if not _verify_sig(public_key_b64, sig["signedDigest"].encode(), sig["signature"]):
        return False, "lock_signature_invalid"
    return True, "ok"


def _selfcheck() -> None:
    """Runnable invariant check (no framework): resolve is deterministic + order-independent,
    depends_on is pulled in, and a signed lock round-trips while tamper fails closed."""
    from .signing import generate_keypair
    import tempfile

    def desc(cid, ver, deps=None):
        return CapabilityDescriptor(id=cid, version=ver, description="x",
                                    input_schema={"type": "object"}, output_schema={"type": "object"},
                                    side_effects="write", idempotency="optional", depends_on=deps)

    descriptors = [desc("a.one", "1.2.0", deps=["a.dep"]), desc("a.one", "1.0.0"),
                   desc("a.dep", "0.3.0"), desc("a.two", "2.0.0")]
    spec = ProductSpecification(id="product:t", version="0.1.0",
                                requires=[Requirement("a.one", ">=1.0 <2"), Requirement("a.two", ">=2.0 <3")],
                                entitlements={"a.two": "pack-x"})

    lock = resolve(spec, descriptors)
    caps = {b.capability: b.version for b in lock.bindings}
    assert caps == {"a.one": "1.2.0", "a.two": "2.0.0", "a.dep": "0.3.0"}, caps  # best version + depends_on pulled in

    # order-independence: shuffle descriptors → identical digest
    lock2 = resolve(spec, list(reversed(descriptors)))
    assert lock2.digest == lock.digest, "resolution must be order-independent"

    # unsatisfiable → ResolutionError
    try:
        resolve(ProductSpecification("product:t", "0.1.0", [Requirement("a.one", ">=9.0")]), descriptors)
        raise AssertionError("expected ResolutionError")
    except ResolutionError as e:
        assert "unresolved:a.one" in str(e)

    # sign + verify round-trip, then tamper fails closed
    key = generate_keypair(tempfile.mkdtemp(), overwrite=True)
    sign_lock(lock, key)
    ok, reason = verify_lock(lock, key.public_key_b64)
    assert ok, reason
    lock.entitlements["a.two"] = "pack-TAMPERED"
    ok, reason = verify_lock(lock, key.public_key_b64)
    assert not ok and reason == "lock_digest_invalid", reason
    print("chp_core.product self-check OK")


if __name__ == "__main__":
    _selfcheck()
