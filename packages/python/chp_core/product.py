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
from dataclasses import dataclass, field, replace

from .agent_interface import is_render_capability
from .semver import best_satisfying
from .signing import HostKey, _canon, _sign, _verify_sig
from .types import CapabilityDescriptor

__all__ = [
    "Requirement", "ProductSpecification", "Binding", "ProductLock", "SurfaceBinding", "ComponentRef",
    "Route", "RouteBinding", "View", "ProductUISchema", "ARCHETYPES",
    "AUTHORITY_CLASSES", "ASSURANCE_TIERS", "PROJECTION_MODES", "CONFORMANCE_CHECKS", "ConformanceResult",
    "ResolutionError", "resolve", "sign_lock", "verify_lock", "check_conformance", "product_digest",
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

# Assurance tier — a product's minimum trust/maturity tier (harvested from @auxo/chp-runtime).
ASSURANCE_TIERS = ("S1", "S2", "S3")

# Projection mode — how a multi-capability product's results combine into one output (harvested from
# chp-runtime's built-in ProjectionFunctions): passthrough = a single capability's result;
# merge = combine several. A custom projection reference is allowed; these are the built-ins.
PROJECTION_MODES = ("passthrough", "merge")

# The seven materialized-product conformance checks (harvested from @auxo/chp-runtime's runtime
# model into the Lock artifact — see check_conformance). Three are statically verifiable from the
# spec+lock; the four runtime properties are guaranteed by any CHP host and reported satisfied-by-host.
CONFORMANCE_CHECKS = (
    "explicit_capability_selection", "deterministic_projection", "evidence_backed_output",
    "visibility_of_denied", "assurance_qualified", "replay_identical", "safe_deactivation",
)


@dataclass(frozen=True)
class ConformanceResult:
    check: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ComponentRef:
    """Identity of a federated, content-addressed UI component (mirrors ``@auxo/chp-runtime``'s
    ``ComponentDefinition``). The visual parallel to a capability's ``contractDigest``: name +
    version + ``content_hash`` pin exactly which component bytes render a surface.

    Since the frontend-as-capability evolution, a component IS a render-capability, so a
    ComponentRef is normally **derived** from that capability's binding (see :func:`resolve`) rather
    than authored independently — it is retained as the back-compat projection legacy consumers
    (e.g. ``@chp/ui`` ``BoundSurface``) read. Prefer ``SurfaceBinding.component_capability``."""

    name: str                        # namespaced like a capability, e.g. "chp.widgets.EvidenceTree"
    version: str
    content_hash: str                # sha256 of the component bundle

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "contentHash": self.content_hash}


@dataclass(frozen=True)
class SurfaceBinding:
    """A consumer projection of a capability at a declared authority class — the composition half
    of a UI / agent / API surface. ``authority`` is the canonical atom; a surface can never exceed
    it (enforced at the consumer, e.g. ``@chp/ui`` ``<Surface>``). A surface may only project a
    *bound* capability — the authority-conservation invariant, checked in :func:`resolve`.

    Frontend-as-capability: the UI that renders a surface is itself a **render-capability** named by
    ``component_capability`` (a CapabilityDescriptor with ``category="component"``/a ``render`` mode),
    bound in the Lock like any capability — so its identity and content are pinned by its own binding's
    ``contractDigest``, not a separate struct. :func:`resolve` derives the legacy ``component``
    ComponentRef from that binding for back-compat."""

    slot: str
    capability: str
    surface: str                     # surface / projection id
    authority: str                   # one of AUTHORITY_CLASSES
    component_capability: str | None = None   # id of the render-capability that renders this surface
    component: "ComponentRef | None" = None   # derived (or legacy) content-addressed component ref

    def digest(self) -> str:
        return product_digest({"slot": self.slot, "capability": self.capability,
                               "surface": self.surface, "authority": self.authority,
                               "componentCapability": self.component_capability,
                               "component": self.component.to_dict() if self.component else None})

    def to_dict(self) -> dict:
        out: dict[str, object] = {"slot": self.slot, "capability": self.capability,
                                  "surface": self.surface, "authority": self.authority,
                                  "surfaceDigest": self.digest()}
        if self.component_capability is not None:
            out["componentCapability"] = self.component_capability
        if self.component is not None:
            out["component"] = self.component.to_dict()
        return out


# UI archetype — a page/product behavioral template a runtime expands into routes/surfaces (harvested
# from chp-runtime). data-driven binds live capability data; static has none; dashboard/admin/showcase
# are scaffolding shapes. Open string; these are the built-ins.
ARCHETYPES = ("data-driven", "static", "dashboard", "admin", "showcase")


@dataclass(frozen=True)
class RouteBinding:
    """Bind a card/widget in a route to the capability that supplies its data (chp-runtime's
    ProductUIRouteBinding). The data-binding primitive: a self-binding component fetches ``capability``
    and renders ``extract`` from its result."""

    card: str
    capability: str
    params: dict | None = None
    extract: str | None = None
    detail: dict | None = None       # master-detail drill-down: {capability, key, param} (selecting a row
    #                                  invokes `capability` with {param: row[key]} — must be a BOUND cap)

    def to_dict(self) -> dict:
        out: dict[str, object] = {"card": self.card, "capability": self.capability}
        if self.params is not None:
            out["params"] = self.params
        if self.extract is not None:
            out["extract"] = self.extract
        if self.detail is not None:
            out["detail"] = self.detail
        return out


@dataclass(frozen=True)
class View:
    """A first-class **data-shaping View** — a declared *derived* capability (chp-runtime's View
    concept, ported). A View composes one ``source_capability`` and reshapes its result to
    ``output_schema`` — the canonical shape a component consumes. "A view IS a capability", the peer of
    "a component IS a render-capability": a route/region binding targets a View by putting its ``id`` in
    the binding's ``capability`` (no separate binding field).

    The View makes three things first-class that were previously implicit in a hand-written view-cap:
    * ``output_schema`` is the **contract** the linter checks a binding against (no external catalog to
      drift from — see ``chp_core.app_lint``);
    * ``source_capability`` is the **authority + coverage link** — :func:`resolve` requires it to be a
      BOUND capability (a View can't surface data the product didn't compose), and coverage credits it as
      surfaced when a View over it is bound;
    * ``audience`` / ``decision_grade`` carry the **governance** dimension (who it's for, how load-bearing).

    ``transform`` names the reshape (a pluggable seam — a registered transform, or omitted when the
    ``source_capability`` already emits ``output_schema``). Declaring the View does not itself execute
    the reshape; the view-capability that does is registered on the host (v1) — auto-generating it from
    this declaration is the forward upgrade path."""

    id: str                              # the derived-capability id a binding targets
    source_capability: str               # the raw capability this View composes (must be BOUND)
    output_schema: dict = field(default_factory=dict)   # the shape it emits (the component's contract)
    transform: str | None = None         # named reshape; None ⇒ source already emits output_schema
    audience: str | None = None          # governance: who the View is for
    decision_grade: str | None = None    # governance: how load-bearing (informational / decision / …)

    def to_dict(self) -> dict:
        out: dict[str, object] = {"id": self.id, "sourceCapability": self.source_capability,
                                  "outputSchema": self.output_schema}
        for k, v in (("transform", self.transform), ("audience", self.audience),
                     ("decisionGrade", self.decision_grade)):
            if v is not None:
                out[k] = v
        return out


@dataclass(frozen=True)
class Region:
    """A named region of a composite page: mounts one render-capability (``component``) that
    self-binds its own data (``bindings``), laid out with its siblings by the route's ``layout``.
    The page-level peer of a card's binding — a whole page becomes a layout of self-binding regions
    (data), not a hand-coded organism. ``span`` = grid column span (grid layout only)."""

    id: str
    label: str | None = None
    component: str | None = None
    bindings: list[RouteBinding] = field(default_factory=list)
    span: int | None = None
    props: dict | None = None            # static (non-bound) component props, e.g. DataTable `columns`

    def to_dict(self) -> dict:
        out: dict[str, object] = {"id": self.id}
        for k in ("label", "component"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        if self.bindings:
            out["bindings"] = [b.to_dict() for b in self.bindings]
        if self.span is not None:
            out["span"] = self.span
        if self.props is not None:
            out["props"] = self.props
        return out


@dataclass(frozen=True)
class Route:
    """A route within a product's UI — mounts a built-in ``view``, a federated ``component``
    (render-capability id) with card ``bindings``, OR a composite page of ``regions`` (each a
    self-binding render-capability) arranged by ``layout`` (``stack``|``grid``|``flex``)."""

    id: str
    path: str | None = None
    label: str | None = None
    icon: str | None = None
    view: str | None = None
    component: str | None = None
    bindings: list[RouteBinding] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    layout: str | None = None
    props: dict | None = None            # static (non-bound) component props, e.g. DataTable `columns`

    def to_dict(self) -> dict:
        out: dict[str, object] = {"id": self.id}
        for k in ("path", "label", "icon", "view", "component"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        if self.bindings:
            out["bindings"] = [b.to_dict() for b in self.bindings]
        if self.regions:
            out["regions"] = [r.to_dict() for r in self.regions]
        if self.layout is not None:
            out["layout"] = self.layout
        if self.props is not None:
            out["props"] = self.props
        return out


@dataclass(frozen=True)
class ProductUISchema:
    """A product's declarative UI (chp-runtime's ProductUISchema, decoupled): an archetype + routes.
    ``auth``/``tenancy`` are *declarative requirements* — an injected provider enforces them; no auth
    vendor is named here. Carried in the Lock so a Python- or TS-produced Lock drives the same console."""

    archetype: str | None = None
    routes: list[Route] = field(default_factory=list)
    auth: dict | None = None            # {"required": bool}
    tenancy: dict | None = None         # {"requireOrg": bool, "rolesAllowed": [...]}
    views: list[View] = field(default_factory=list)   # first-class data-shaping Views (derived caps)

    def to_dict(self) -> dict:
        out: dict[str, object] = {}
        if self.archetype is not None:
            out["archetype"] = self.archetype
        if self.routes:
            out["routes"] = [r.to_dict() for r in self.routes]
        if self.auth is not None:
            out["auth"] = self.auth
        if self.tenancy is not None:
            out["tenancy"] = self.tenancy
        if self.views:                                # guarded ⇒ view-less locks keep their old digest
            out["views"] = [v.to_dict() for v in self.views]
        return out

    def bound_capabilities(self) -> list[str]:
        """Every capability the UI's route AND region bindings reference — checked against the Lock in
        resolve() (authority conservation: the UI can't surface data the product didn't compose). Includes
        master-detail drill-down capabilities (a binding's ``detail.capability``)."""
        all_bindings = [b for r in self.routes for b in r.bindings]
        all_bindings += [b for r in self.routes for reg in r.regions for b in reg.bindings]
        caps = [b.capability for b in all_bindings]
        caps += [b.detail["capability"] for b in all_bindings if b.detail and b.detail.get("capability")]
        return caps

    def view_sources(self) -> dict[str, str]:
        """Map ``view id → source_capability`` for every declared View. Used to credit a source
        capability as surfaced when a bound View derives from it (coverage) and to enforce the
        View's authority-conservation link in resolve()."""
        return {v.id: v.source_capability for v in self.views}


@dataclass
class ProductSpecification:
    """The declared identity of a product: capability requirements + the authority
    (entitlement) bindings + consumer surfaces + an optional declarative UI. Provider-independent."""

    id: str
    version: str
    requires: list[Requirement] = field(default_factory=list)
    entitlements: dict[str, str] = field(default_factory=dict)  # capability-id prefix → entitlement pack
    surfaces: list[SurfaceBinding] = field(default_factory=list)  # UI / agent / API projections
    assurance: str = "S1"                                        # minimum assurance tier (S1/S2/S3)
    projection: str = "passthrough"                              # how capability results combine
    ui: ProductUISchema | None = None                            # declarative product UI (routes/archetype)

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
    assurance: str = "S1"
    projection: str = "passthrough"
    is_cross_host: bool = False          # any binding resolved to a remote (mesh) capability
    ui: ProductUISchema | None = None    # declarative product UI carried in the Lock (routes/archetype)
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
            "assurance": self.assurance,
            "projection": self.projection,
            "isCrossHost": self.is_cross_host,
            "ui": self.ui.to_dict() if self.ui else None,
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


def _binding_for(d: CapabilityDescriptor, requested_range: str, locality: str = "local") -> Binding:
    pkg = d.id.rsplit(".", 1)[0] if "." in d.id else d.id
    return Binding(
        capability=d.id, version=d.version, requested_range=requested_range,
        contract_digest=contract_digest(d), provider=d.provider or pkg,
        provider_version=d.version, package=pkg, package_version=d.version, locality=locality,
    )


def _derive_component_ref(s: SurfaceBinding, chosen: dict[str, CapabilityDescriptor]) -> SurfaceBinding:
    """Project the bound render-capability into the surface's legacy ``component`` ComponentRef, so
    consumers reading ``surface.component`` keep working after the id-based evolution. An explicitly
    authored ``component`` is left untouched. The derived content hash is the render-capability's own
    ``metadata.content_hash`` (the bundle digest) or, absent that, its contract digest — either way a
    value pinned by the capability's own binding, not invented here."""
    if s.component_capability is None or s.component is not None:
        return s
    d = chosen.get(s.component_capability)
    if d is None:                       # unresolved — resolve() already recorded the issue
        return s
    content_hash = (d.metadata or {}).get("content_hash") or contract_digest(d)
    ref = ComponentRef(name=d.id, version=d.version, content_hash=content_hash)
    return replace(s, component=ref)


# Built-in @chp/ui render dialects — the always-available component floor (BASE_CATALOG). A route or region
# may mount one of these directly; it need not be a product-composed render-capability. Data bindings still
# must resolve to BOUND capabilities — authority conservation is on the DATA (the binding), not the widget.
_BUILTIN_RENDER_DIALECTS = frozenset({
    "chp.widgets", "chp.ui", "chp.molecules", "chp.surfaces", "chp.ai",
    "chp.governed", "chp.shell", "chp.workflow", "chp.explainability",
})


def _component_issue(component: str, chosen: dict[str, CapabilityDescriptor], where: str,
                     ident: str) -> str | None:
    """Validate a route/region ``component``: valid iff a BOUND render-capability (a product-composed
    component) OR a built-in @chp/ui component (a known render dialect). Returns an issue string, or None."""
    d = chosen.get(component)
    if d is not None:
        return None if is_render_capability(d) else f"{where}_component_not_renderable:{ident}:{component}"
    if ".".join(component.split(".")[:2]) in _BUILTIN_RENDER_DIALECTS:
        return None
    return f"{where}_unknown_component:{ident}:{component}"


def resolve(spec: ProductSpecification, descriptors: list[CapabilityDescriptor],
            *, remote_descriptors: list[CapabilityDescriptor] | None = None,
            policy: dict | None = None) -> ProductLock:
    """Deterministically resolve *spec* into an (unsigned) ProductLock.

    Each explicit requirement is resolved to the highest satisfying version, then the transitive
    ``depends_on`` closure is pulled in. Resolution prefers LOCAL *descriptors*; a capability found
    only in *remote_descriptors* (a mesh catalog) is bound with ``locality="remote"`` — a cross-host
    assemblage (``lock.is_cross_host``). Raises :class:`ResolutionError` on any unsatisfiable
    requirement / missing dependency / invalid projection or assurance."""
    idx = _index(descriptors)
    ridx = _index(remote_descriptors or [])
    chosen: dict[str, CapabilityDescriptor] = {}
    ranges: dict[str, str] = {}
    localities: dict[str, str] = {}
    issues: list[str] = []

    def _pick(cap: str, rng: str) -> tuple[CapabilityDescriptor | None, str | None]:
        for index, loc in ((idx, "local"), (ridx, "remote")):  # local first (preferLocal), then mesh
            versions = list(index.get(cap, {}))
            picked = best_satisfying(versions, rng) if versions else None
            if picked is not None:
                return index[cap][picked], loc
        return None, None

    # explicit requirements
    frontier: list[str] = []
    for req in spec.requires:
        d, loc = _pick(req.capability, req.range)
        if d is None or loc is None:
            issues.append(f"unresolved:{req.capability} (range {req.range})")
            continue
        chosen[req.capability], ranges[req.capability], localities[req.capability] = d, req.range, loc
        frontier.append(req.capability)

    # transitive depends_on closure (activating CapabilityDescriptor.depends_on)
    while frontier:
        cap = frontier.pop()
        for dep in (chosen[cap].depends_on or []):
            if dep in chosen:
                continue
            d, loc = _pick(dep, ">=0.0.0")
            if d is None or loc is None:
                issues.append(f"unresolved_dependency:{dep} (required by {cap})")
                continue
            chosen[dep], ranges[dep], localities[dep] = d, f"^{d.version}", loc  # same-major pin
            frontier.append(dep)

    # surface bindings — authority conservation: a surface may only project a BOUND capability,
    # and its authority must be a valid atom. A surface can never invent authority the product lacks.
    # Its UI (component_capability), if named, must likewise be a BOUND render-capability — the
    # surface can't render a component the product didn't compose.
    for s in spec.surfaces:
        if s.authority not in AUTHORITY_CLASSES:
            issues.append(f"surface_invalid_authority:{s.slot}:{s.authority}")
        if s.capability not in chosen:
            issues.append(f"surface_unknown_capability:{s.slot}:{s.capability}")
        if s.component_capability is not None:
            comp = chosen.get(s.component_capability)
            if comp is None:
                issues.append(f"surface_unknown_component:{s.slot}:{s.component_capability}")
            elif not is_render_capability(comp):
                issues.append(f"surface_component_not_renderable:{s.slot}:{s.component_capability}")

    if spec.assurance not in ASSURANCE_TIERS:
        issues.append(f"invalid_assurance_tier:{spec.assurance}")
    if not spec.projection:
        issues.append("empty_projection")

    # UI route/region bindings — same authority-conservation law one level up: a route card OR a
    # composite-page region may only bind a BOUND capability (the console can't surface data the product
    # didn't compose), a region's render-capability ``component`` must be a BOUND renderable one (like a
    # surface), and the archetype (if named) must be a known template.
    if spec.ui is not None:
        if spec.ui.archetype is not None and spec.ui.archetype not in ARCHETYPES:
            issues.append(f"unknown_archetype:{spec.ui.archetype}")
        # Declared Views are derived capabilities: a binding may target a View by id, and each View's
        # source_capability must be BOUND (a View can't surface data the product didn't compose).
        view_ids = {v.id for v in spec.ui.views}
        for v in spec.ui.views:
            if v.source_capability not in chosen:
                issues.append(f"view_unbound_source:{v.id}:{v.source_capability}")

        def _binding_target_ok(cap: str) -> bool:
            return cap in chosen or cap in view_ids   # a raw bound cap OR a declared View id

        def _check_detail(b: RouteBinding, where: str, ident: str) -> None:
            # master-detail drill-down: the detail capability must be BOUND too (authority conservation)
            if b.detail and not _binding_target_ok(b.detail.get("capability", "")):
                issues.append(f"{where}_detail_unbound:{ident}:{b.detail.get('capability')}")
        for r in spec.ui.routes:
            for b in r.bindings:
                if not _binding_target_ok(b.capability):
                    issues.append(f"route_unknown_capability:{b.capability}")
                _check_detail(b, "route", r.id)
            if r.component is not None:                      # routes were never validated before (a gap):
                issue = _component_issue(r.component, chosen, "route", r.id)
                if issue:
                    issues.append(issue)
            for reg in r.regions:
                for b in reg.bindings:
                    if not _binding_target_ok(b.capability):
                        issues.append(f"region_unknown_capability:{reg.id}:{b.capability}")
                    _check_detail(b, "region", reg.id)
                if reg.component is not None:                # now also accepts built-in @chp/ui components,
                    issue = _component_issue(reg.component, chosen, "region", reg.id)  # not only bound caps
                    if issue:
                        issues.append(issue)

    if issues:
        raise ResolutionError(issues)

    bindings = [_binding_for(d, ranges[cap], localities[cap]) for cap, d in chosen.items()]
    surfaces = [_derive_component_ref(s, chosen) for s in spec.surfaces]
    lock = ProductLock(
        product=spec.id, product_version=spec.version,
        product_semantic_digest=spec.semantic_digest([b.capability for b in bindings]),
        bindings=bindings, entitlements=dict(spec.entitlements),
        surfaces=surfaces, assurance=spec.assurance, projection=spec.projection,
        is_cross_host=any(loc == "remote" for loc in localities.values()),
        ui=spec.ui,
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


def check_conformance(spec: ProductSpecification, lock: ProductLock) -> list[ConformanceResult]:
    """Evaluate the seven materialized-product conformance checks against a spec + resolved lock.

    Harvested from ``@auxo/chp-runtime``'s runtime conformance model into the Lock artifact. The
    three *static* checks (capability selection, projection, assurance) are verified here; the four
    *runtime* properties (evidence, denial visibility, replay, deactivation) are guaranteed by any
    CHP host — a materialized product on a ``LocalCapabilityHost`` inherits them — and are reported
    satisfied-by-host with the reason, so the report is honest about what is checked vs. inherited."""
    R = ConformanceResult
    wildcards = [r.capability for r in spec.requires if (not r.capability) or "*" in r.capability]
    bad_authority = [s.slot for s in spec.surfaces if s.authority not in AUTHORITY_CLASSES]
    projection_ok = bool(spec.projection) and not bad_authority
    return [
        R("explicit_capability_selection", not wildcards,
          "requirements are explicit capability ids (no wildcards)" if not wildcards else f"wildcards: {wildcards}"),
        R("deterministic_projection", projection_ok,
          f"projection {spec.projection!r}; surfaces project at a defined authority; digest is order-independent"
          if projection_ok else f"empty projection / undefined surface authority: {bad_authority}"),
        R("evidence_backed_output", True,
          "satisfied by host: LocalCapabilityHost records signed evidence for every invocation"),
        R("visibility_of_denied", True,
          "satisfied by host: denials emit evidence (CHP is a denial-aware protocol)"),
        R("assurance_qualified", spec.assurance in ASSURANCE_TIERS,
          f"assurance tier {spec.assurance!r}" if spec.assurance in ASSURANCE_TIERS
          else f"missing/invalid assurance tier {spec.assurance!r} (expected {ASSURANCE_TIERS})"),
        R("replay_identical", bool(lock.digest),
          "lock digest is reproducible; host replays deterministically by correlation id"),
        R("safe_deactivation", True,
          "satisfied by host: the lock is a declarative artifact and evidence is append-only — "
          "teardown preserves the chain"),
    ]


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

    # Views: a declared View is a derived cap — a binding may target its id; its source must be BOUND,
    # and declaring a View changes the lock digest (it rides ProductUISchema → _core["ui"]).
    view_ui = ProductUISchema(
        archetype="data-driven",
        routes=[Route(id="r", path="/", component="chp.widgets.StatGrid",
                      bindings=[RouteBinding(card="stats", capability="v.a_stats", extract="stats")])],
        views=[View(id="v.a_stats", source_capability="a.one", output_schema={"type": "object"})],
    )
    spec_v = ProductSpecification(id="product:v", version="0.1.0",
                                  requires=[Requirement("a.one", ">=1.0 <2")], ui=view_ui)
    lock_v = resolve(spec_v, descriptors)
    assert lock_v.digest and lock_v.digest != resolve(
        replace(spec_v, ui=None), descriptors).digest, "a declared View must ride the lock digest"
    # a View whose source_capability isn't bound → ResolutionError (authority conservation on the View)
    bad_ui = replace(view_ui, views=[View(id="v.a_stats", source_capability="a.missing")])
    try:
        resolve(replace(spec_v, ui=bad_ui), descriptors)
        raise AssertionError("expected ResolutionError for unbound View source")
    except ResolutionError as e:
        assert "view_unbound_source:v.a_stats:a.missing" in str(e), str(e)

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
