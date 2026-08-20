"""Author-time binding linter for Materialized Products.

Catches component↔capability mismatches BEFORE render — the shape gaps that only surface at runtime today
(a route/region binds a built-in component under the wrong prop name, forgets a required static prop like
`DataTable.columns`, or binds a card that isn't a prop at all).

Generic + UI-agnostic: it takes a **component-contract catalog** as input (``{component_id: {"data_prop":
str, "also_needs"?: [str], "kind"?: str}}``), sourced from ``@chp/ui`` — so ``chp_core`` never depends on
specific UI components. It is deliberately NOT part of ``resolve()``: it is an advisory DX check (a linter),
release-decoupled from the protocol. A component absent from the catalog (a federated render-capability, or
an uncatalogued built-in) is skipped, not failed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .product import ProductSpecification


@dataclass(frozen=True)
class BindingIssue:
    """One binding mismatch. ``kind`` ∈ {missing_data_prop, missing_static_prop, unknown_card, shape_kind}."""
    location: str        # "route:<id>" | "region:<id>"
    component: str
    kind: str
    detail: str


def check_bindings(spec: ProductSpecification, contracts: dict[str, dict],
                   descriptors: list | None = None) -> list[BindingIssue]:
    """Validate a product's UI route/region bindings against the component-contract catalog.

    Returns the list of mismatches (empty = clean). Only components present in ``contracts`` are checked.
    When ``descriptors`` (the resolved capability descriptors) are supplied, also checks the shape **kind**:
    a bound cap that declares an ``output_schema`` must yield the component's expected ``kind`` (array/object)
    at the binding's ``extract`` path — else a ``shape_kind`` issue. Best-effort (a cap with no output_schema
    is skipped).

    A binding that targets a first-class :class:`~chp_core.product.View` needs no external descriptor: the
    View carries its own ``output_schema`` (it *is* the contract), so a view-bound route is shape-checked
    from the spec alone — the drift-free path the whole View primitive is for."""
    issues: list[BindingIssue] = []
    if spec.ui is None:
        return issues
    idx = {d.id: d for d in (descriptors or [])}
    idx.update({v.id: v for v in spec.ui.views})   # a View carries output_schema → its own contract
    for r in spec.ui.routes:
        _check(r.component, r.bindings, f"route:{r.id}", contracts, idx, issues, r.props)
        for reg in r.regions:
            _check(reg.component, reg.bindings, f"region:{reg.id}", contracts, idx, issues, reg.props)
    return issues


def _schema_at(schema, path: str | None):
    """Walk a JSON Schema down an ``extract`` dot-path (through ``properties``). None if it doesn't resolve."""
    cur = schema
    for seg in (path.split(".") if path else []):
        if not isinstance(cur, dict):
            return None
        cur = (cur.get("properties") or {}).get(seg)
        if cur is None:
            return None
    return cur


def _kind_of(schema) -> str | None:
    t = schema.get("type") if isinstance(schema, dict) else None
    return t if t in ("array", "object") else None


def _check(component: str | None, bindings, location: str, contracts: dict[str, dict],
           idx: dict, out: list[BindingIssue], static_props: dict | None = None) -> None:
    if not component:
        return
    contract = contracts.get(component)
    if contract is None:          # federated render-cap or uncatalogued built-in — nothing to validate here
        return
    if contract.get("kind") == "action":   # an action component INVOKES a cap; its binding is not a data shape
        return
    data_prop = contract["data_prop"]
    props = {data_prop, *contract.get("also_needs", [])}
    cards = {b.card for b in bindings}
    static = set(static_props or {})   # static (non-bound) props supplied on the route/region

    if data_prop not in cards and data_prop not in static:   # the main data prop is neither bound nor static
        out.append(BindingIssue(location, component, "missing_data_prop",
                                f"expects data prop '{data_prop}' — bound cards are {sorted(cards) or '[]'}"))
    for need in contract.get("also_needs", []):   # e.g. DataTable.columns — bind it OR supply it in `props`
        if need not in cards and need not in static:
            out.append(BindingIssue(location, component, "missing_static_prop",
                                    f"needs prop '{need}' — bind it, or supply it statically in the route/region "
                                    f"`props`"))
    for b in bindings:
        if b.card not in props:   # a bound card that is not a prop of the component
            out.append(BindingIssue(location, component, "unknown_card",
                                    f"card '{b.card}' (→ {b.capability}) is not a prop of {component}; "
                                    f"props are {sorted(props)}"))
        # shape KIND (best-effort): the main data prop's bound cap must yield the expected array/object
        if b.card == data_prop and contract.get("kind"):
            d = idx.get(b.capability)
            schema = getattr(d, "output_schema", None) if d is not None else None
            got = _kind_of(_schema_at(schema, b.extract)) if schema else None
            if got is not None and got != contract["kind"]:
                out.append(BindingIssue(location, component, "shape_kind",
                                        f"card '{b.card}' expects {contract['kind']}, but {b.capability} "
                                        f"(extract={b.extract or '·'}) yields {got}"))


def lint_report(issues: list[BindingIssue]) -> str:
    """Human-readable report — a clean line, or one ``✗`` line per mismatch."""
    if not issues:
        return "✓ bindings OK"
    return "\n".join(f"  ✗ [{i.location}] {i.component}: {i.detail}" for i in issues)


@dataclass(frozen=True)
class CoverageReport:
    """UI coverage of a product's capabilities. ``silent`` = capabilities referenced by no route/region."""
    total: int
    surfaced: int
    silent: list

    @property
    def score(self) -> float:
        return self.surfaced / self.total if self.total else 1.0


def check_coverage(spec: ProductSpecification, capabilities) -> CoverageReport:
    """Report which of ``capabilities`` (the product's capability ids — from the Lock bindings or a host
    descriptor) are SURFACED in the UI (bound to a route/region card, or mounted as a component) vs SILENT
    (referenced nowhere). The authoring-intelligence counterpart to the binding linter — mirrors
    chp-runtime's vocabulary / silent-capability analysis: 'which verbs have no UI?'"""
    referenced: set = set()
    if spec.ui is not None:
        referenced |= set(spec.ui.bound_capabilities())
        for r in spec.ui.routes:
            if r.component:
                referenced.add(r.component)
            for reg in r.regions:
                if reg.component:
                    referenced.add(reg.component)
    caps = set(capabilities)
    surfaced = caps & referenced
    return CoverageReport(total=len(caps), surfaced=len(surfaced), silent=sorted(caps - referenced))


def coverage_report(report: CoverageReport) -> str:
    """Human-readable coverage — the score, then the silent capabilities."""
    head = (f"UI coverage: {report.surfaced}/{report.total} capabilities surfaced "
            f"({round(report.score * 100)}%)")
    if not report.silent:
        return head + " — ✓ all surfaced"
    body = "\n".join(f"    · {c}" for c in report.silent)
    return f"{head}\n  silent (no UI):\n{body}"


# ── governance-completeness: the check no UI framework but CHP can offer ───────────────────────────
def _is_mutation(side_effects) -> bool:
    """A capability mutates state unless its side-effects are empty / read-only."""
    if not side_effects:
        return False
    if isinstance(side_effects, str):
        return side_effects.lower() not in ("read", "none", "read_only")
    return any(_is_mutation(s) for s in side_effects)


# Verb prefixes that mark a capability as MUTATING by NAME — a backstop for adapters that under-declare
# side_effects (github's create_issue/update_issue declare none). Shared with the introspect CLI.
MUTATING_VERBS = (
    "create", "update", "delete", "remove", "add", "set", "put", "post", "patch", "merge", "close",
    "open", "stop", "start", "restart", "deploy", "install", "provision", "push", "write", "send",
    "run", "execute", "cancel", "approve", "reject", "revoke", "grant", "sync", "bump", "publish",
)


def mutating_name(cap_id: str) -> bool:
    method = cap_id.rsplit(".", 1)[-1]
    return any(method == v or method.startswith(v + "_") for v in MUTATING_VERBS)


@dataclass(frozen=True)
class GovernanceReport:
    """How governed a product's SURFACED capabilities are. ``ungoverned_mutations`` = surfaced
    capabilities that mutate state but carry no entitlement (authority) binding — the load-bearing
    gap: a write surface with no governing authority. ``score`` = governed fraction of surfaced caps."""
    surfaced: int
    governed: int                 # surfaced caps covered by an entitlement (authority) binding
    mutations: int                # surfaced caps that mutate state
    ungoverned_mutations: list    # surfaced mutating caps with NO entitlement — the flags
    declared: int = 0             # surfaced caps carrying a declared View (audience/decision-grade intent)

    @property
    def score(self) -> float:
        return self.governed / self.surfaced if self.surfaced else 1.0


def check_governance(spec: ProductSpecification, descriptors) -> GovernanceReport:
    """Score the GOVERNANCE of a product's UI, not just its shape (chp-runtime's vocabulary governance
    dimension). A capability is *governed* when an entitlement in ``spec.entitlements`` covers its id
    (prefix match — authority is external in CHP, bound by the entitlement plane). This flags the
    load-bearing gap the shape linter can't see: a **mutating** capability surfaced with no governing
    authority — exactly what ``suggest`` will draft if it binds a write cap to a display widget.

    A View surfaces its ``source_capability``; the source's side-effects/entitlement are what count
    (the View is a read projection, but the authority rides the underlying cap)."""
    idx = {_get(d, "id"): d for d in descriptors}
    referenced: set = set()
    view_sources: dict = {}
    if spec.ui is not None:
        referenced |= set(spec.ui.bound_capabilities())
        view_sources = spec.ui.view_sources()
    # resolve each surfaced cap to the underlying data cap (a View → its source_capability)
    surfaced = {view_sources.get(c, c) for c in referenced if idx.get(view_sources.get(c, c)) is not None}
    prefixes = tuple(spec.entitlements)

    def _governed(cap: str) -> bool:
        return any(cap == p or cap.startswith(p) for p in prefixes)
    governed = {c for c in surfaced if _governed(c)}
    # a mutation by declared side_effects OR by name (backstop for under-declared adapters like github)
    mutations = {c for c in surfaced if _is_mutation(_get(idx.get(c), "side_effects")) or mutating_name(c)}
    ungoverned_mutations = sorted(mutations - governed)
    declared_sources = set(view_sources.values())     # caps carrying a declared View (governance intent)
    declared = len(surfaced & declared_sources)
    return GovernanceReport(surfaced=len(surfaced), governed=len(governed),
                            mutations=len(mutations), ungoverned_mutations=ungoverned_mutations,
                            declared=declared)


def governance_report(report: GovernanceReport) -> str:
    intent = f"; {report.declared}/{report.surfaced} carry a declared View (audience/grade)" if report.declared else ""
    head = (f"Governance: {report.governed}/{report.surfaced} surfaced capabilities governed "
            f"({round(report.score * 100)}%); {report.mutations} mutate state{intent}")
    if not report.ungoverned_mutations:
        return head + " — ✓ no ungoverned mutation surfaces"
    body = "\n".join(f"    ⚠ {c} — mutates state, no entitlement (authority) binding"
                     for c in report.ungoverned_mutations)
    return f"{head}\n  ungoverned mutation surfaces:\n{body}"


# ── shape inference: learn a capability's output_schema from a live sample result ─────────────────
def _infer(sample, depth: int) -> dict:
    if isinstance(sample, bool):
        return {"type": "boolean"}
    if isinstance(sample, (int, float)):
        return {"type": "number"}
    if isinstance(sample, str):
        return {"type": "string"}
    if isinstance(sample, list):
        out: dict = {"type": "array"}
        if sample and depth < 3:                      # capture the item shape from the first element
            out["items"] = _infer(sample[0], depth + 1)
        return out
    if isinstance(sample, dict):
        if depth >= 3:
            return {"type": "object"}
        return {"type": "object", "properties": {k: _infer(v, depth + 1) for k, v in sample.items()}}
    return {"type": "object"}


def infer_output_schema(sample) -> dict:
    """Synthesize a JSON-Schema-ish ``output_schema`` from a SAMPLE capability result (one live
    invocation). Adapter descriptors rarely declare ``output_schema.properties``, so ``suggest`` can't
    shape-match and defaults everything to an array/MeshTopology. One real result fixes that: invoke a
    read-only cap once, infer its shape, and every downstream matcher (component pick, extract path,
    linter kind, and auto-columns) becomes accurate — the bridge that makes the whole adapter library
    assemblable without hand-authoring schemas. Captures object properties AND the item shape of an
    array (one element deep, so a list-of-objects yields ``items.properties`` for column generation)."""
    return _infer(sample, 0)


def _columns_from_schema(output_schema: dict, extract: str | None):
    """Derive ``DataTable``-style columns from an inferred/declared schema: the array at ``extract``
    ('' = top level) whose ``items`` is an object → one column per item property. None if not a
    list-of-objects. The static ``columns`` an author would otherwise hand-write."""
    node = output_schema if isinstance(output_schema, dict) else {}
    if extract:                                       # walk to the array under the extract key
        node = ((node.get("properties") or {}).get(extract)) or {}
    if node.get("type") != "array":
        return None
    item_props = ((node.get("items") or {}).get("properties")) or {}
    if not item_props:
        return None
    return [{"key": k, "label": k.replace("_", " ").title()} for k in item_props]


def _fields_from_schema(output_schema: dict, extract: str | None):
    """Derive ``DetailCard``-style fields from an inferred/declared schema: the OBJECT at ``extract``
    (None = the top-level object) → one field per property. The single-record counterpart of
    :func:`_columns_from_schema`. None if not an object with properties."""
    node = output_schema if isinstance(output_schema, dict) else {}
    if extract:
        node = ((node.get("properties") or {}).get(extract)) or {}
    if node.get("type") != "object":
        return None
    props = node.get("properties") or {}
    if not props:
        return None
    return [{"key": k, "label": k.replace("_", " ").title()} for k in props]


def descriptors_with_inferred_schemas(descriptors, samples: dict) -> list:
    """Return *descriptors* with ``output_schema`` filled from ``samples`` (``{cap_id: sample_result}``)
    wherever a descriptor lacks a real one — so ``suggest`` shape-matches from live data. Non-destructive:
    a descriptor that already declares ``output_schema.properties`` is left untouched."""
    out: list = []
    for d in descriptors:
        cid = _get(d, "id")
        existing = _get(d, "output_schema") or {}
        has_real = isinstance(existing, dict) and existing.get("properties")
        if cid in samples and not has_real:
            merged = dict(d) if isinstance(d, dict) else {"id": cid, "category": _get(d, "category")}
            merged["output_schema"] = infer_output_schema(samples[cid])
            out.append(merged)
        else:
            out.append(d)
    return out


# ── authoring inversion: draft a manifest by matching capabilities to components ──────────────────
_LIST_KEYS = ("records", "items", "results", "rows", "data", "hosts", "invocations", "mappings", "events")
_NAME_HINT_ARRAY = ("list", "query", "search", "timeline", "activity", "audit", "stats", "report",
                    "topology", "inventory", "dashboard", "funnel", "aggregate")
# cap-id keyword → preferred component (used when component-name affinity doesn't fire)
_HINT_COMPONENT = (
    ("invocation", "chp.widgets.Timeline"), ("activity", "chp.widgets.Timeline"),
    ("audit", "chp.widgets.Timeline"), ("timeline", "chp.widgets.Timeline"), ("event", "chp.widgets.Timeline"),
    ("stat", "chp.widgets.StatGrid"), ("report", "chp.widgets.StatGrid"),
    ("metric", "chp.widgets.StatGrid"), ("token", "chp.widgets.StatGrid"),
    ("topology", "chp.widgets.MeshTopology"), ("host", "chp.widgets.MeshTopology"), ("mesh", "chp.widgets.MeshTopology"),
    ("decision", "chp.widgets.GovernanceSurface"), ("governance", "chp.widgets.GovernanceSurface"),
    ("list", "chp.widgets.DataTable"), ("record", "chp.widgets.DataTable"),
    ("query", "chp.widgets.DataTable"), ("search", "chp.widgets.DataTable"),
)


@dataclass(frozen=True)
class Suggestion:
    """A drafted binding — the built-in component a capability maps to (``component=''`` if unmatched)."""
    capability: str
    component: str
    card: str
    extract: str | None
    reason: str


def _get(d, key):
    return d.get(key) if isinstance(d, dict) else getattr(d, key, None)


def _array_extract(output_schema) -> str | None:
    """If the cap output is an array — top-level, under a common list key, or (from a real/inferred schema)
    under ANY array-typed property — return the extract path ('' = top-level, or the key). None if not
    array-shaped. Prefers a well-known list key, then falls back to the first array property by name — so a
    schema inferred from a live sample (e.g. ``check_all`` → ``adapters``) resolves without a hardcoded name."""
    if not isinstance(output_schema, dict):
        return None
    if output_schema.get("type") == "array":
        return ""
    props = output_schema.get("properties") or {}
    for k in _LIST_KEYS:                                   # 1. a conventional list key
        v = props.get(k)
        if isinstance(v, dict) and v.get("type") == "array":
            return k
    for k in sorted(props):                                # 2. any array property (real/inferred schema)
        v = props.get(k)
        if isinstance(v, dict) and v.get("type") == "array":
            return k
    return None


def _pick_component(cap_id: str, candidates: list, prefer: set | None = None) -> tuple:
    """Pick the component for a cap. A requested VARIANT (``prefer``) that fits this shape wins outright —
    the composability knob: swap the whole app to cards/table/… without touching bindings. Otherwise:
    name affinity, then a semantic keyword hint, then the generic component, then the first candidate."""
    if prefer:                                          # 0. an explicit variant for this shape family
        for comp_id, c in candidates:
            if comp_id in prefer:
                return comp_id, c
    low = cap_id.lower()
    for comp_id, c in candidates:                       # 1. name affinity
        for word in re.findall(r"[A-Z][a-z]+", comp_id.split(".")[-1]):
            if word.lower() in low:
                return comp_id, c
    by_id = {cid: c for cid, c in candidates}
    for hint, comp_id in _HINT_COMPONENT:               # 2. semantic keyword hint
        if hint in low and comp_id in by_id:
            return comp_id, by_id[comp_id]
    for comp_id, c in candidates:                       # 3. the GENERIC component for this kind (DataTable/
        if c.get("generic"):                            #    DetailCard) — never a specialized viz by default
            return comp_id, c
    return candidates[0]                                # 4. last resort: first candidate


def component_variants(contracts: dict) -> dict:
    """``family → [component_ids]`` — the interchangeable presentation variants of each shape. Members of
    a family share a data shape (a records list, a single record, metrics), so a route swaps between them
    with no other change. The discovery surface behind ``chp app variants`` and ``--variant``."""
    fams: dict = {}
    for cid, c in contracts.items():
        fam = c.get("family")
        if fam:
            fams.setdefault(fam, []).append(cid)
    return {f: sorted(v) for f, v in sorted(fams.items())}


def suggest_bindings(descriptors, contracts: dict, prefer: set | None = None) -> list:
    """Draft, for each DATA capability, the built-in component that best fits its shape: match a cap whose
    output is array-shaped (via ``output_schema``, top-level or under a list key) — or, absent a schema, whose
    id carries a list-ish hint — to a component of that kind, with a name-affinity tie-break. Render-caps
    (category=component) are skipped; unmatched caps get ``component=''``. The inversion of the linter."""
    by_kind: dict = {}
    for cid, c in contracts.items():
        by_kind.setdefault(c.get("kind", "object"), []).append((cid, c))
    out: list = []
    for d in descriptors:
        if _get(d, "category") == "component":
            continue
        cap_id = _get(d, "id")
        if not cap_id:
            continue
        os_ = _get(d, "output_schema")
        ext = _array_extract(os_)
        if ext is not None:                                       # array shape → array component
            kind, reason = "array", "shape"
        elif isinstance(os_, dict) and os_.get("properties"):     # a real object shape → detail/object component
            kind, reason = "object", "shape"
        elif any(h in cap_id for h in _NAME_HINT_ARRAY):          # no schema → name hint (assume list)
            kind, reason = "array", "name-hint"
        else:
            kind, reason = None, "name-hint"
        candidates = by_kind.get(kind or "array", [])
        if not candidates:
            out.append(Suggestion(cap_id, "", "", None, f"no component for kind={kind or '?'}"))
            continue
        comp_id, comp = _pick_component(cap_id, candidates, prefer)
        out.append(Suggestion(cap_id, comp_id, comp["data_prop"], ext or None, reason))
    return out


def _component_for_view(view: dict, contracts: dict):
    """Pick the component a reused View feeds from the VIEW's own output_schema (it declares the shape),
    not from the source cap's name. Returns ``(component_id, contract)`` or None. Prefers a component whose
    ``data_prop`` is an ARRAY prop of the View's output_schema (the primary data), then any matching prop."""
    props = (view.get("output_schema") or {}).get("properties") or {}
    if not props:
        return None
    arrays = {k for k, v in props.items() if isinstance(v, dict) and v.get("type") == "array"}
    for prefer_arrays in (True, False):                 # array props first, then any prop
        for comp_id, c in contracts.items():
            dp = c.get("data_prop")
            if dp in props and (dp in arrays if prefer_arrays else True):
                return comp_id, c
    return None


def suggest_manifest(product_id: str, descriptors, contracts: dict, reuse_views=None, prefer=None) -> dict:
    """Draft a Materialized Product manifest from a host's capabilities — one route per matched capability.
    A starting point to refine (then ``chp app check`` it), not a finished app.

    ``reuse_views`` is a library of already-declared Views (dicts ``{id, source_capability, output_schema?}``,
    e.g. harvested from existing manifests' ``ui.views``). When a capability is the ``source_capability`` of a
    known View, the drafted route binds **that View** (by id) instead of the raw cap, and the View is carried
    into the draft's ``ui.views`` — so a new app COMPOSES from the shared View library rather than
    re-authoring the shape. This is "a View built once is consumed everywhere", as a command."""
    by_source: dict = {}
    view_ids: set = set()
    for v in (reuse_views or []):
        view_ids.add(v.get("id"))
        src = v.get("source_capability")
        if src:
            by_source.setdefault(src, v)
    schema_by_id = {_get(d, "id"): (_get(d, "output_schema") or {}) for d in descriptors}
    routes: list = []
    used_views: dict = {}
    prefer_set = set(prefer) if prefer else None
    for i, s in enumerate(suggest_bindings(descriptors, contracts, prefer_set)):
        if s.capability in view_ids:               # a reuse View's OWN id in the descriptor set — it's already
            continue                               # covered through its source_capability; don't draft it raw
        view = by_source.get(s.capability)
        if view is not None:                       # REUSE: bind the existing View, shaped by ITS output_schema
            picked = _component_for_view(view, contracts)
            schema = view.get("output_schema") or {}
            if picked is None:                     # View shape matches no component — fall back to raw suggestion
                if not s.component:
                    continue
                component = s.component
                primary_extract = _array_extract(schema) or s.card
                bindings = [{"card": s.card, "capability": view["id"], "extract": primary_extract}]
            else:
                component, contract = picked        # component/card/extract from the View, not the cap name
                vprops = (schema.get("properties")) or {}
                # bind the primary data prop AND any also_needs the View actually emits (e.g. summary)
                cards = [contract["data_prop"]] + [n for n in contract.get("also_needs", []) if n in vprops]
                bindings = [{"card": c, "capability": view["id"], "extract": c} for c in cards]
                primary_extract = contract["data_prop"]
            used_views[view["id"]] = view
        else:
            if not s.component:
                continue
            component = s.component
            schema = schema_by_id.get(s.capability) or {}
            primary_extract = s.extract
            b = {"card": s.card, "capability": s.capability}
            if s.extract:
                b["extract"] = s.extract
            bindings = [b]
        slug = s.capability.rsplit(".", 1)[-1]
        route: dict = {"id": slug, "path": "/" if i == 0 else f"/{slug}",
                       "label": slug.replace("_", " ").title(), "component": component,
                       "bindings": bindings}
        # auto-fill a field/column list from the inferred shape so the route is check-clean without the
        # author hand-writing it: `columns` from a list-of-objects (DataTable), `fields` from an object
        # (DetailCard). Both come straight from the sampled shape.
        also_needs = contracts.get(component, {}).get("also_needs", [])
        bound_cards = {b["card"] for b in bindings}
        derived = {}
        if "columns" in also_needs and "columns" not in bound_cards:
            cols = _columns_from_schema(schema, primary_extract)
            if cols:
                derived["columns"] = cols
        if "fields" in also_needs and "fields" not in bound_cards:
            flds = _fields_from_schema(schema, primary_extract)
            if flds:
                derived["fields"] = flds
        if derived:
            route["props"] = derived
        routes.append(route)
    ui: dict = {"archetype": "data-driven", "routes": routes}
    if used_views:
        ui["views"] = list(used_views.values())
    return {"id": product_id, "version": "0.1.0", "entitlements": {}, "assurance": "S1",
            "projection": "merge", "ui": ui}
