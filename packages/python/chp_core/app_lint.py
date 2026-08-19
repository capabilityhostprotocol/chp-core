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
    is skipped)."""
    issues: list[BindingIssue] = []
    if spec.ui is None:
        return issues
    idx = {d.id: d for d in (descriptors or [])}
    for r in spec.ui.routes:
        _check(r.component, r.bindings, f"route:{r.id}", contracts, idx, issues)
        for reg in r.regions:
            _check(reg.component, reg.bindings, f"region:{reg.id}", contracts, idx, issues)
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
           idx: dict, out: list[BindingIssue]) -> None:
    if not component:
        return
    contract = contracts.get(component)
    if contract is None:          # federated render-cap or uncatalogued built-in — nothing to validate here
        return
    data_prop = contract["data_prop"]
    props = {data_prop, *contract.get("also_needs", [])}
    cards = {b.card for b in bindings}

    if data_prop not in cards:    # the component's main data prop isn't bound (the #1 mismatch)
        out.append(BindingIssue(location, component, "missing_data_prop",
                                f"expects data prop '{data_prop}' — bound cards are {sorted(cards) or '[]'}"))
    for need in contract.get("also_needs", []):   # e.g. DataTable.columns — static, not bindable from a cap
        if need not in cards:
            out.append(BindingIssue(location, component, "missing_static_prop",
                                    f"needs prop '{need}' (static config — not bindable from a capability)"))
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
    """If the cap output is an array — top-level, or under a common list key — return the extract path
    ('' = top-level, or the key). None if not array-shaped."""
    if not isinstance(output_schema, dict):
        return None
    if output_schema.get("type") == "array":
        return ""
    props = output_schema.get("properties") or {}
    for k in _LIST_KEYS:
        v = props.get(k)
        if isinstance(v, dict) and v.get("type") == "array":
            return k
    return None


def _pick_component(cap_id: str, candidates: list) -> tuple:
    """Prefer name affinity (a component name-word appears in the cap id); else a semantic keyword hint
    (audit→Timeline, stats→StatGrid, …) if that component is a candidate; else the first candidate."""
    low = cap_id.lower()
    for comp_id, c in candidates:                       # 1. name affinity
        for word in re.findall(r"[A-Z][a-z]+", comp_id.split(".")[-1]):
            if word.lower() in low:
                return comp_id, c
    by_id = {cid: c for cid, c in candidates}
    for hint, comp_id in _HINT_COMPONENT:               # 2. semantic keyword hint
        if hint in low and comp_id in by_id:
            return comp_id, by_id[comp_id]
    return candidates[0]                                # 3. fallback


def suggest_bindings(descriptors, contracts: dict) -> list:
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
        ext = _array_extract(_get(d, "output_schema"))
        kind = "array" if ext is not None else ("array" if any(h in cap_id for h in _NAME_HINT_ARRAY) else None)
        candidates = by_kind.get(kind or "array", [])
        if not candidates:
            out.append(Suggestion(cap_id, "", "", None, f"no component for kind={kind or '?'}"))
            continue
        comp_id, comp = _pick_component(cap_id, candidates)
        out.append(Suggestion(cap_id, comp_id, comp["data_prop"], ext or None,
                              "shape" if ext is not None else "name-hint"))
    return out


def suggest_manifest(product_id: str, descriptors, contracts: dict) -> dict:
    """Draft a Materialized Product manifest from a host's capabilities — one route per matched capability.
    A starting point to refine (then ``chp app check`` it), not a finished app."""
    routes: list = []
    for i, s in enumerate(suggest_bindings(descriptors, contracts)):
        if not s.component:
            continue
        binding = {"card": s.card, "capability": s.capability}
        if s.extract:
            binding["extract"] = s.extract
        slug = s.capability.rsplit(".", 1)[-1]
        routes.append({"id": slug, "path": "/" if i == 0 else f"/{slug}",
                       "label": slug.replace("_", " ").title(), "component": s.component,
                       "bindings": [binding]})
    return {"id": product_id, "version": "0.1.0", "entitlements": {}, "assurance": "S1",
            "projection": "merge", "ui": {"archetype": "data-driven", "routes": routes}}
