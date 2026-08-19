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
