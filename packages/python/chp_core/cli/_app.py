"""``chp app`` — DX helpers for building composable Materialized-Product apps.

``check``          lints a manifest's route/region bindings against a component-contract catalog and prints
                   the author-time mismatch report (exits non-zero on issues — CI-friendly).
``scaffold-view``  generates a view-capability adapter stub that composes a source capability and reshapes
                   it into a component's expected shape (the matched-pair / view-cap fix, scaffolded).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..app_lint import (
    _is_mutation,
    mutating_name,
    check_bindings,
    check_coverage,
    check_governance,
    coverage_report,
    descriptors_with_inferred_schemas,
    governance_report,
    lint_report,
    suggest_bindings,
    suggest_manifest,
)
from ..manifest import parse_manifest


def _load_manifest(path: str) -> dict:
    return json.loads(Path(path).read_text())   # JSON manifest (keeps chp_core dependency-free)


# Bundled default component-contract catalog — mirrors @chp/ui's component-contracts.json for the built-in
# chp.widgets.* floor, so `--contracts` is optional (the most frequent papercut). Pass --contracts to
# override with a project's own @chp/ui catalog.
_BUILTIN_CONTRACTS = {
    "chp.widgets.MeshTopology": {"data_prop": "hosts", "kind": "array", "family": "records"},
    "chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "also_needs": ["columns"],
                              "generic": True, "family": "records"},
    "chp.widgets.CardGrid": {"data_prop": "items", "kind": "array", "also_needs": ["columns"], "family": "records"},
    "chp.widgets.StatGrid": {"data_prop": "stats", "kind": "array", "family": "metrics"},
    "chp.widgets.DetailCard": {"data_prop": "record", "kind": "object", "also_needs": ["fields"],
                               "generic": True, "family": "record"},
    "chp.widgets.GovernanceSurface": {"data_prop": "decisions", "kind": "array", "also_needs": ["summary"],
                                      "family": "records"},
    "chp.widgets.Timeline": {"data_prop": "entries", "kind": "array", "family": "records"},
    "chp.widgets.ActionButton": {"data_prop": "actions", "kind": "action", "family": "action"},
}


def _load_contracts(path: str | None) -> dict:
    """Load the component-contract catalog. With no path, fall back to the bundled built-in catalog so
    `--contracts` is optional; pass a path to use a project's own @chp/ui catalog."""
    return json.loads(Path(path).read_text()) if path else dict(_BUILTIN_CONTRACTS)


def cmd_app_check(args: argparse.Namespace) -> int:
    spec = parse_manifest(_load_manifest(args.manifest))
    contracts = _load_contracts(args.contracts)
    if not contracts:
        print("note: no --contracts catalog given — component shapes are NOT checked (structure only).")
    issues = check_bindings(spec, contracts)
    print(f"{spec.id}:")
    print(lint_report(issues))
    return 1 if issues else 0


def cmd_app_coverage(args: argparse.Namespace) -> int:
    spec = parse_manifest(_load_manifest(args.manifest))
    if args.caps:
        caps = json.loads(Path(args.caps).read_text())
    else:
        caps = [req.capability for req in spec.requires]
    if not caps:
        print("no capabilities to score — the manifest declares no `requires` (auto-derived at "
              "materialize). Pass --caps <ids.json> (e.g. the ids from a materialized host descriptor).")
        return 0
    print(f"{spec.id}:")
    print(coverage_report(check_coverage(spec, caps)))
    return 0


def cmd_app_governance(args: argparse.Namespace) -> int:
    spec = parse_manifest(_load_manifest(args.manifest))
    descriptors = json.loads(Path(args.descriptors).read_text())
    report = check_governance(spec, descriptors)
    print(f"{spec.id}:")
    print(governance_report(report))
    return 1 if report.ungoverned_mutations else 0   # CI-friendly: fail on an ungoverned mutation surface


def cmd_app_components(args: argparse.Namespace) -> int:
    contracts = _load_contracts(args.contracts)
    if not contracts:
        print("no --contracts catalog given (pass @chp/ui component-contracts.json).")
        return 0
    print(f"{len(contracts)} bindable components:")
    for cid, c in sorted(contracts.items()):
        needs = f" + static {c['also_needs']}" if c.get("also_needs") else ""
        fam = f"  [{c['family']}]" if c.get("family") else ""
        print(f"  {cid:38} card '{c['data_prop']}' ({c.get('kind', '?')}){needs}{fam}")
    return 0


def cmd_app_variants(args: argparse.Namespace) -> int:
    from ..app_lint import component_variants
    contracts = _load_contracts(args.contracts)
    if not contracts:
        print("no --contracts catalog given (pass @chp/ui component-contracts.json).")
        return 0
    fams = component_variants(contracts)
    print("component variants (a route swaps between members of a family with no other change):")
    for fam, members in fams.items():
        print(f"  {fam:10} {', '.join(m.split('.')[-1] for m in members)}")
    print("\nuse --variant <component-id> on suggest/introspect/dev to pick one for its shape.")
    return 0


def _harvest_views(paths: str | None) -> list:
    """Collect declared Views from existing manifests (comma-separated paths) — the reuse library."""
    views: list = []
    for p in (paths.split(",") if paths else []):
        p = p.strip()
        if not p:
            continue
        ui = _load_manifest(p).get("ui") or {}
        views.extend(ui.get("views", []))
    return views


def _http_json(url: str, body: dict | None = None, timeout: float = 15.0) -> dict:
    """Minimal JSON GET/POST over stdlib urllib (keeps chp_core dependency-free)."""
    import json as _json
    import urllib.request
    data = _json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if body is not None else "GET",
                                 headers={"Content-Type": "application/json"} if body is not None else {})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (operator-supplied host URL)
        return _json.loads(r.read())


def _parse_params(param_args) -> dict:
    params: dict = {}
    for kv in (param_args or []):                     # --param owner=X --param repo=Y → shared sample inputs
        k, _, v = kv.partition("=")
        params[k.strip()] = v
    return params


def _action_route(cid: str, ischema: dict, params: dict, index: int) -> dict:
    """Draft an ActionButton route surfacing a WRITE capability as a governed action (invoked through the
    gate on click, never sampled). Fills the action's declared inputs from --param where present."""
    method = cid.rsplit(".", 1)[-1]
    allowed = set((ischema.get("properties") or {}).keys())
    inp = {k: v for k, v in params.items() if k in allowed}
    label = method.replace("_", " ").title()
    binding: dict = {"card": label, "capability": cid}
    if inp:
        binding["params"] = inp
    return {"id": method, "path": "/" if index == 0 else f"/{method}", "label": label,
            "component": "chp.widgets.ActionButton", "bindings": [binding]}


def _wire_master_detail(manifest: dict, caps: list, samples: dict, params: dict) -> None:
    """Auto-pair a ``list_*``/``search_*`` route with the matching ``get_*`` cap of the same noun and wire a
    master-detail drill-down: selecting a row invokes the detail cap with the row's KEY plus the shared
    CONTEXT params. The per-row param is the detail cap's required param that matches a list-item field
    (github's get_issue needs owner+repo+number — owner/repo are context, number is per-row); the rest are
    filled from --param. Mutates the manifest in place."""
    by_id = {c.get("id"): c for c in caps}
    for route in manifest["ui"]["routes"]:
        binds = route.get("bindings") or []
        if not binds:
            continue
        b = binds[0]
        cap = b.get("capability")
        extract = b.get("extract")
        if not cap or "detail" in b:
            continue
        prefix, _, method = cap.rpartition(".")
        if not any(method.startswith(p + "_") for p in ("list", "search", "query")):
            continue
        noun = method.split("_", 1)[1]
        singular = noun[:-1] if noun.endswith("s") else noun
        get_cap = next((g for g in (f"{prefix}.get_{noun}", f"{prefix}.get_{singular}") if g in by_id), None)
        if not get_cap:
            continue
        required = ((by_id[get_cap].get("input_schema") or {}).get("required")) or []
        if not required:
            continue
        sample = samples.get(cap) or {}
        arr = (sample.get(extract) if extract else sample) if isinstance(sample, dict) else sample
        item_keys = list(arr[0].keys()) if isinstance(arr, list) and arr and isinstance(arr[0], dict) else []
        # the per-row param matches a list-item field; the other required params are context (from --param)
        row_params = [r for r in required if r in item_keys]
        key = row_params[0] if row_params else next(
            (k for k in (f"{singular}_id", "id", "number", "node_id", "name") if k in item_keys), None)
        if not key:
            continue
        param = row_params[0] if row_params else next((r for r in required if r not in params), key)
        context = {r: params[r] for r in required if r != param and r in params}
        detail: dict = {"capability": get_cap, "key": key, "param": param}
        if context:
            detail["params"] = context
        b["detail"] = detail


def _synthesize_dashboard(manifest: dict) -> None:
    """Group the display routes into a single Overview page of grid regions (reusing the composite-page
    primitive), so an introspected app opens on a dashboard combining a domain's views instead of one flat
    route per cap. The per-cap routes stay (moved off ``/``). Action routes are left as their own routes.
    Mutates the manifest in place; a no-op if there's nothing to combine."""
    routes = manifest["ui"]["routes"]
    display = [r for r in routes
               if r.get("component") and r["component"] != "chp.widgets.ActionButton" and not r.get("regions")]
    if len(display) < 2:
        return
    regions = []
    for r in display[:8]:                          # cap the tiles; the per-cap routes still hold the rest
        reg: dict = {"id": r["id"], "label": r.get("label"), "component": r["component"],
                     "span": 6, "bindings": r["bindings"]}
        if r.get("props"):
            reg["props"] = r["props"]
        regions.append(reg)
    for r in routes:                               # free up "/" for the dashboard
        if r.get("path") == "/":
            r["path"] = "/" + r["id"]
    routes.insert(0, {"id": "overview", "path": "/", "label": "Overview", "layout": "grid", "regions": regions})


def _introspect_host(base: str, params: dict, *, only: str | None, contracts: dict,
                     reuse: list, include_writes: bool, product_id: str, prefer=None,
                     actions: bool = False, dashboard: bool = False) -> tuple:
    """Discover a running host, SAMPLE each safe read cap once, infer shapes, and draft a manifest.
    Returns ``(manifest, samples, cap_inputs, skipped, ncaps)`` — ``cap_inputs`` is the exact input used
    per sampled cap, so a live preview can re-invoke identically. Never fires a write (side_effects OR a
    mutating verb in the name); with ``actions=True`` a write is instead drafted as a governed ActionButton
    route (surfaced, not invoked)."""
    caps = _http_json(f"{base}/capabilities").get("capabilities", [])
    if only:
        caps = [c for c in caps if c.get("id", "").startswith(only)]
    samples: dict = {}
    cap_inputs: dict = {}
    skipped: list = []
    action_caps: list = []
    for c in caps:
        cid = c.get("id")
        if not cid:
            continue
        if (_is_mutation(c.get("side_effects")) or mutating_name(cid)) and not include_writes:
            if actions:
                action_caps.append(c)     # surface it as a governed action instead of sampling it
            else:
                skipped.append((cid, "mutation (skipped — introspect never fires writes)"))
            continue
        ischema = c.get("input_schema") or {}
        allowed = set((ischema.get("properties") or {}).keys())
        inp = {k: v for k, v in params.items() if k in allowed} if allowed else dict(params)
        missing = [r for r in (ischema.get("required") or []) if r not in inp]
        if missing:
            skipped.append((cid, f"needs input {missing} (supply with --param)"))
            continue
        try:
            r = _http_json(f"{base}/invoke", {"capability_id": cid, "payload": inp})   # envelope arg key
            if r.get("outcome") == "success":
                samples[cid] = r.get("data")
                cap_inputs[cid] = inp
            else:
                skipped.append((cid, r.get("outcome") or "not_success"))
        except Exception as e:                       # network / denial / handler error — skip, keep going
            skipped.append((cid, f"error: {type(e).__name__}"))

    # Draft ONLY from caps we actually sampled — a skipped mutation/input cap has no known shape and must
    # not become a display route (that's the governance smell the linter flags anyway).
    sampled_descs = descriptors_with_inferred_schemas([c for c in caps if c.get("id") in samples], samples)
    manifest = suggest_manifest(product_id, sampled_descs, contracts, reuse_views=reuse, prefer=prefer)
    # Persist the sampling inputs (owner/repo/…) into each binding so the SAVED manifest is self-contained —
    # it fetches the same data standalone (smoke, round-trip, a served console), not just during introspect.
    for _route in manifest["ui"]["routes"]:
        for _b in _route.get("bindings", []):
            _inp = cap_inputs.get(_b.get("capability"))
            if _inp:
                _b["params"] = _inp
    # Governance ledger: declare a View per sampled read cap (source + inferred shape + audience/grade) so the
    # signed Lock records who each surface is for and how load-bearing it is. Declarations, not rewired
    # bindings — the app still targets the live host's raw caps.
    view_decls = [{"id": "view:" + d["id"].rsplit(".", 1)[-1], "source_capability": d["id"],
                   "output_schema": d.get("output_schema") or {}, "audience": "operator",
                   "decision_grade": "informational"} for d in sampled_descs]
    if view_decls:
        manifest["ui"].setdefault("views", []).extend(view_decls)
    _wire_master_detail(manifest, caps, samples, params)   # auto drill-down: list_* row → get_* detail
    if action_caps:                       # append governed-action routes for the write caps
        base_n = len(manifest["ui"]["routes"])
        manifest["ui"]["routes"] += [
            _action_route(c["id"], c.get("input_schema") or {}, params, base_n + i)
            for i, c in enumerate(action_caps)]
    if dashboard:
        _synthesize_dashboard(manifest)
    return manifest, samples, cap_inputs, skipped, len(caps)


def cmd_app_introspect(args: argparse.Namespace) -> int:
    """Point at a RUNNING CHP host and draft a shape-accurate app in one command: discover its
    capabilities, SAMPLE each safe read cap once (never a mutation, never a cap needing input), infer each
    output_schema from the live result, and draft a manifest. Turns any provisioned host — any of the
    adapters — into an app draft with no hand-authored schemas."""
    base = args.host.rstrip("/")
    manifest, samples, _inputs, skipped, ncaps = _introspect_host(
        base, _parse_params(args.param), only=args.only, contracts=_load_contracts(args.contracts),
        reuse=_harvest_views(getattr(args, "reuse", None)),
        include_writes=args.include_writes, product_id=args.product_id, prefer=getattr(args, "variant", None),
        actions=getattr(args, "actions", False), dashboard=getattr(args, "dashboard", False))

    if args.samples_out:
        Path(args.samples_out).write_text(json.dumps(samples, indent=2) + "\n")
    text = json.dumps(manifest, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n")
    else:
        print(text)
    routes = manifest["ui"]["routes"]
    print(f"\n# introspected {base}: {ncaps} caps · sampled {len(samples)} · "
          f"drafted {len(routes)} routes"
          + (f" · wrote {args.out}" if args.out else ""), flush=True)
    if skipped:
        print(f"# skipped {len(skipped)}: "
              + ", ".join(f"{cid.split('.')[-1]} ({why})" for cid, why in skipped[:10])
              + (" …" if len(skipped) > 10 else ""))
    return 0


def cmd_app_smoke(args: argparse.Namespace) -> int:
    """Render every route against a live host and report which routes' data actually loads — the runtime
    companion to the static ``check``. Invokes each display binding (never an action/write); a binding that
    denies or errors is a failing route. Exits non-zero on any failure (CI-friendly)."""
    manifest = _load_manifest(args.manifest)
    base = args.host.rstrip("/")
    contracts = _load_contracts(args.contracts)
    action_ids = {cid for cid, c in contracts.items() if c.get("kind") == "action"}
    ok, fails = 0, []

    def _smoke(node: dict, where: str) -> None:
        nonlocal ok
        if node.get("component") in action_ids:      # never fire a write in a smoke test
            return
        for b in node.get("bindings", []):
            try:
                r = _http_json(f"{base}/invoke", {"capability_id": b["capability"], "payload": b.get("params") or {}})
                outcome = r.get("outcome")
            except Exception as e:
                outcome = f"error:{type(e).__name__}"
            if outcome == "success":
                ok += 1
            else:
                fails.append((where, b["capability"], outcome))

    for r in manifest["ui"]["routes"]:
        _smoke(r, f"route:{r['id']}")
        for reg in r.get("regions", []):
            _smoke(reg, f"region:{reg['id']}")
    print(f"{manifest.get('id', 'app')}: {ok} binding(s) OK, {len(fails)} failed", flush=True)
    for where, cap, why in fails:
        print(f"  ✗ [{where}] {cap.split('.')[-1]} → {why}", flush=True)
    return 1 if fails else 0


def cmd_app_suggest(args: argparse.Namespace) -> int:
    descriptors = json.loads(Path(args.descriptors).read_text())
    if getattr(args, "samples", None):        # learn real shapes from one live result per cap
        samples = json.loads(Path(args.samples).read_text())
        descriptors = descriptors_with_inferred_schemas(descriptors, samples)
    contracts = _load_contracts(args.contracts)
    reuse = _harvest_views(getattr(args, "reuse", None))
    manifest = suggest_manifest(args.product_id, descriptors, contracts, reuse_views=reuse,
                                prefer=getattr(args, "variant", None))
    text = json.dumps(manifest, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n")
        print(f"wrote {args.out} — {len(manifest['ui']['routes'])} routes drafted; refine, then `chp app check`")
    else:
        print(text)
    reused = manifest["ui"].get("views", [])
    if reused:
        print(f"\n# reused {len(reused)} existing View(s): " + ", ".join(v["id"] for v in reused))
    unmatched = [s.capability for s in suggest_bindings(descriptors, contracts) if not s.component]
    if unmatched:
        print(f"\n# {len(unmatched)} unmatched (no fitting component): "
              + ", ".join(unmatched[:8]) + (" …" if len(unmatched) > 8 else ""))
    return 0


def _manifest_schema(contracts: dict) -> dict:
    """A JSON Schema for the Materialized Product manifest, with enums pulled live from chp_core and the
    component ids surfaced as examples from the contract catalog (editor autocomplete)."""
    from ..product import ARCHETYPES, ASSURANCE_TIERS, AUTHORITY_CLASSES

    component: dict = {"type": "string",
                       "description": "A render component — a built-in @chp/ui component or product render-cap."}
    if contracts:
        component["examples"] = sorted(contracts)
    binding = {"type": "object", "required": ["card", "capability"], "additionalProperties": False,
               "properties": {
                   "card": {"type": "string", "description": "The component prop this data fills."},
                   "capability": {"type": "string", "description": "The data capability to invoke."},
                   "params": {"type": "object"},
                   "extract": {"type": "string", "description": "Dot-path plucked from the result."}}}
    static_props = {"type": "object",
                    "description": "Static (non-bound) component props, e.g. DataTable `columns`."}
    region = {"type": "object", "required": ["id"], "additionalProperties": False,
              "properties": {"id": {"type": "string"}, "label": {"type": "string"}, "component": component,
                             "span": {"type": "integer", "minimum": 1, "maximum": 12},
                             "bindings": {"type": "array", "items": binding}, "props": static_props}}
    route = {"type": "object", "required": ["id"], "additionalProperties": False,
             "properties": {"id": {"type": "string"}, "path": {"type": "string"}, "label": {"type": "string"},
                            "icon": {"type": "string"}, "view": {"type": "string"}, "component": component,
                            "layout": {"enum": ["stack", "grid", "flex"]},
                            "bindings": {"type": "array", "items": binding},
                            "regions": {"type": "array", "items": region}, "props": static_props}}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CHP Materialized Product manifest",
        "type": "object", "required": ["id", "version"], "additionalProperties": False,
        "properties": {
            "id": {"type": "string", "pattern": "^product:"},
            "version": {"type": "string"},
            "requires": {"type": "array", "items": {"type": "object", "required": ["capability"],
                         "properties": {"capability": {"type": "string"}, "range": {"type": "string"}}}},
            "entitlements": {"type": "object", "additionalProperties": {"type": "string"}},
            "assurance": {"enum": sorted(ASSURANCE_TIERS)},
            "projection": {"type": "string"},
            "surfaces": {"type": "array", "items": {"type": "object",
                         "required": ["slot", "capability", "authority"],
                         "properties": {"slot": {"type": "string"}, "capability": {"type": "string"},
                                        "surface": {"type": "string"},
                                        "authority": {"enum": sorted(AUTHORITY_CLASSES)},
                                        "component_capability": {"type": "string"}}}},
            "ui": {"type": "object", "additionalProperties": False, "properties": {
                "archetype": {"enum": sorted(ARCHETYPES)},
                "routes": {"type": "array", "items": route},
                "views": {"type": "array", "items": {
                    "type": "object", "required": ["id", "source_capability"], "additionalProperties": False,
                    "properties": {
                        "id": {"type": "string", "description": "Derived-cap id a binding targets."},
                        "source_capability": {"type": "string", "description": "The raw cap this View composes (must be bound)."},
                        "output_schema": {"type": "object", "description": "The shape it emits — the component's contract."},
                        "transform": {"type": "string"}, "audience": {"type": "string"},
                        "decision_grade": {"type": "string"}}}},
                "auth": {"type": "object"}, "tenancy": {"type": "object"}}},
        },
    }


def cmd_app_schema(args: argparse.Namespace) -> int:
    schema = _manifest_schema(_load_contracts(args.contracts))
    text = json.dumps(schema, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n")
        print(f"wrote {args.out}  — reference it from your manifests for editor validation + autocomplete")
    else:
        print(text)
    return 0


def _view_id(source_cap: str, view_id: str | None) -> str:
    return view_id or f"chp.view.{source_cap.rsplit('.', 1)[-1]}"


def _scaffold_view(component: str, source_cap: str, data_prop: str, kind: str | None,
                   view_id: str | None) -> str:
    kind_note = f" ({'an' if kind and kind[:1] in 'aeiou' else 'a'} {kind})" if kind else ""
    is_array = kind == "array"
    stub_value = ('[\n            {"label": "TODO", "value": data.get("TODO")},\n        ]'
                  if is_array else "data")
    count_expr = f"len({data_prop})" if is_array else "1"
    short = source_cap.rsplit(".", 1)[-1]
    cls = "".join(p.capitalize() for p in short.split("_")) + "View"
    aid = f"{short}_view".replace("-", "_")
    vid = _view_id(source_cap, view_id)
    return f'''\
"""Generated view capability — bridges {source_cap} to {component}'s expected shape.

{component} wants prop `{data_prop}`{kind_note}. Fill in the reshape below (the mapping is all that's left);
the composition + evidence wiring is done. Bind it in a manifest with card `{data_prop}`.
"""
from __future__ import annotations

from typing import Any

from chp_core import BaseAdapter, capability


class {cls}(BaseAdapter):
    adapter_id = "chp.adapters.{aid}"
    adapter_name = "{cls}"
    adapter_description = "View cap: {source_cap} -> {component} ({data_prop})."
    adapter_category = "integration"

    @capability(id="{vid}", version="1.0.0",
                description="Reshape {source_cap} into {component}'s `{data_prop}`.",
                category="integration", side_effects=[], emits=["view_rendered"])
    async def {short}(self, ctx: Any, payload: dict) -> dict:
        r = await ctx.ainvoke("{source_cap}", {{}})
        if not r.success:
            raise RuntimeError("{source_cap} unavailable or denied")
        data = r.data or {{}}
        # TODO: map `data` -> {component}'s `{data_prop}`{kind_note}
        {data_prop} = {stub_value}
        ctx.emit("view_rendered", {{"view": "{short}", "n": {count_expr}}}, redacted=False)
        return {{"{data_prop}": {data_prop}}}
'''


def cmd_app_scaffold_view(args: argparse.Namespace) -> int:
    contract = _load_contracts(args.contracts).get(args.component, {})
    data_prop = contract.get("data_prop") or "data"
    code = _scaffold_view(args.component, args.source_cap, data_prop, contract.get("kind"), args.view_id)
    if args.out:
        Path(args.out).write_text(code)
        print(f"wrote {args.out}  — bind {args.component} with card '{data_prop}'")
    else:
        print(code)
    # The first-class View DECLARATION to paste into the manifest's `ui.views` (the linter reads its
    # output_schema as the contract; a route binds it by this id with card '{data_prop}').
    vid = _view_id(args.source_cap, args.view_id)
    out_schema: dict = {"type": "object", "properties": {data_prop: {"type": contract.get("kind", "array")}}}
    declaration = {"id": vid, "source_capability": args.source_cap, "output_schema": out_schema}
    print("\n# add to ui.views:")
    print(json.dumps(declaration, indent=2))
    return 0


def _pluck(data, extract: str | None):
    if not extract:
        return data
    cur = data
    for seg in extract.split("."):
        cur = cur.get(seg) if isinstance(cur, dict) else None
    return cur


def _esc(v) -> str:
    import html as _html
    return _html.escape(v if isinstance(v, str) else json.dumps(v) if isinstance(v, (dict, list)) else str(v))


def _render_block(node: dict, base: str, cap_inputs: dict, contracts: dict) -> str:
    """Render one component block (a route or a region) as HTML by invoking its bound caps on the TARGET
    host LIVE. Array components → a table (columns from props/first row); object → a key/value list; an
    action component → its buttons (non-interactive in the static preview). The server mirror of ProductRenderer."""
    comp = node.get("component") or ""
    contract = contracts.get(comp, {})
    data_prop = contract.get("data_prop")
    props = node.get("props") or {}
    head = f'<h2>{_esc(node.get("label") or node.get("id"))} <small>{_esc(comp.split(".")[-1])}</small></h2>'
    if contract.get("kind") == "action":
        btns = "".join(f'<button disabled>{_esc(b.get("card"))}</button>' for b in node.get("bindings", []))
        return f'{head}<div class="actions">{btns}</div>'
    cards: dict = {}
    for b in node.get("bindings", []):
        try:
            payload = b.get("params") or cap_inputs.get(b["capability"], {})   # binding's own input, else sampled
            r = _http_json(f"{base}/invoke", {"capability_id": b["capability"], "payload": payload})
            cards[b["card"]] = _pluck(r.get("data"), b.get("extract")) if r.get("outcome") == "success" else None
        except Exception:
            cards[b["card"]] = None
    primary = cards.get(data_prop)
    if contract.get("kind") == "array" and isinstance(primary, list):
        keys = ([c["key"] for c in props["columns"]] if props.get("columns")
                else list(primary[0].keys()) if primary and isinstance(primary[0], dict) else ["value"])
        th = "".join(f"<th>{_esc(k)}</th>" for k in keys)
        rows = ""
        for row in primary[:100]:
            tds = "".join(f"<td>{_esc(row.get(k) if isinstance(row, dict) else row)}</td>" for k in keys)
            rows += f"<tr>{tds}</tr>"
        return f'{head}<table><thead><tr>{th}</tr></thead><tbody>{rows}</tbody></table>'
    if isinstance(primary, dict):
        fields = ([f["key"] for f in props["fields"]] if props.get("fields") else list(primary.keys()))
        rows = "".join(f'<div class="kv"><dt>{_esc(k)}</dt><dd>{_esc(primary.get(k))}</dd></div>' for k in fields)
        return f'{head}<dl>{rows}</dl>'
    return f'{head}<pre>{_esc(primary)}</pre>'


def _render_route_html(route: dict, base: str, cap_inputs: dict, contracts: dict) -> str:
    """Render a route: a composite page of regions (grid) or a single component block."""
    if route.get("regions"):
        head = f'<h2>{_esc(route.get("label") or route["id"])}</h2>'
        cells = "".join(f'<div class="region">{_render_block(reg, base, cap_inputs, contracts)}</div>'
                        for reg in route["regions"])
        return f'{head}<div class="grid">{cells}</div>'
    return _render_block(route, base, cap_inputs, contracts)


_PREVIEW_CSS = (
    "body{font:14px system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}"
    "header{padding:12px 20px;border-bottom:1px solid #222;background:#161922}"
    "main{padding:20px;max-width:1100px;margin:0 auto}h2{font-size:15px;margin:24px 0 8px}"
    "h2 small{color:#888;font-weight:400;margin-left:8px}nav a{color:#7aa2f7;margin-right:14px;text-decoration:none}"
    "table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #222;padding:4px 8px;text-align:left}"
    "th{background:#161922;color:#9aa}dl{border:1px solid #222;border-radius:6px;overflow:hidden}"
    ".kv{display:grid;grid-template-columns:180px 1fr;border-top:1px solid #222}.kv:first-child{border-top:0}"
    "dt{padding:6px 10px;color:#9aa;background:#12141a}dd{padding:6px 10px;margin:0}pre{background:#12141a;padding:10px;overflow:auto}"
    ".grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.region{min-width:0;overflow:auto}"
    ".actions button{border:1px solid #333;background:#161922;color:#e6e6e6;border-radius:6px;padding:5px 10px;margin-right:8px}"
)


def _render_preview(manifest: dict, base: str, cap_inputs: dict, contracts: dict) -> str:
    ui = manifest.get("ui") or {}
    routes = ui.get("routes") or []
    nav = " ".join(f'<a href="#{_esc(r["id"])}">{_esc(r.get("label") or r["id"])}</a>' for r in routes)
    body = "".join(f'<section id="{_esc(r["id"])}">{_render_route_html(r, base, cap_inputs, contracts)}</section>'
                   for r in routes)
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{_esc(manifest.get("id", "app"))}</title>'
            f'<style>{_PREVIEW_CSS}</style></head><body><header><strong>{_esc(manifest.get("id", "app"))}</strong>'
            f' &middot; live preview of {_esc(base)}<nav style="margin-top:8px">{nav}</nav></header>'
            f'<main>{body}</main></body></html>')


def _serve_preview(get_manifest, base: str, cap_inputs: dict, contracts: dict, port: int) -> None:
    """Serve a live server-side preview: every request re-reads the manifest (``get_manifest()``) AND
    re-invokes the target host, so both a manifest edit and fresh host data show on refresh — the round-trip
    authoring loop. No React build — the CLI renders the components as HTML."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            html = _render_preview(get_manifest(), base, cap_inputs, contracts).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        def log_message(self, *a) -> None:      # quiet
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"live preview → http://127.0.0.1:{port}  (renders {base} on every request; Ctrl-C to stop)",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
        print("\nstopped.", flush=True)


def _dev_report(manifest_path: str, contracts_path: str | None,
                descriptors_path: str | None) -> tuple[str, bool]:
    """Lint a manifest once and format the live report. Pure (no watching / no I/O loop) so it is
    unit-testable. Runs the binding linter always; adds resolve (structural) + coverage + governance
    when ``descriptors`` are supplied. Returns ``(report_text, clean)``."""
    from ..product import ResolutionError, resolve

    lines: list = []
    clean = True
    spec = parse_manifest(_load_manifest(manifest_path))
    lines.append(f"{spec.id}:")

    issues = check_bindings(spec, _load_contracts(contracts_path))
    lines.append(lint_report(issues))
    clean = clean and not issues

    if descriptors_path:
        from ..types import CapabilityDescriptor
        raw = json.loads(Path(descriptors_path).read_text())
        descs = [d if isinstance(d, CapabilityDescriptor)
                 else CapabilityDescriptor(id=d["id"], version=d.get("version", "0.0.0"),
                                           description=d.get("description", ""),
                                           input_schema=d.get("input_schema") or {"type": "object"},
                                           output_schema=d.get("output_schema") or {"type": "object"},
                                           side_effects=d.get("side_effects", []),
                                           idempotency=d.get("idempotency", "optional"),
                                           category=d.get("category"))
                 for d in raw]
        from dataclasses import replace as _replace

        from ..product import Requirement
        eff = spec if spec.requires else _replace(
            spec, requires=[Requirement(d.id, f">={d.version}") for d in descs])  # materialize's default
        try:
            resolve(eff, descs)
            lines.append("✓ resolves")
        except ResolutionError as e:
            lines.append("✗ resolve: " + "; ".join(e.issues))
            clean = False
        cap_ids = [d.id for d in descs]
        lines.append(coverage_report(check_coverage(spec, cap_ids)))
        gov = check_governance(spec, raw)
        lines.append(governance_report(gov))
        clean = clean and not gov.ungoverned_mutations
    return "\n".join(lines), clean


def cmd_app_dev(args: argparse.Namespace) -> int:
    """Watch a manifest and re-lint on every save — the tight authoring loop. With ``--module`` +
    ``--port`` it also live-serves the app's host and restarts it on change (a @chp/ui console then
    re-renders). Stdlib only (mtime poll); Ctrl-C to stop."""
    import importlib
    import importlib.util
    import os
    import sys
    import threading
    import time

    if getattr(args, "host", None):
        base = args.host.rstrip("/")
        contracts = _load_contracts(args.contracts)
        if args.manifest:
            # ROUND-TRIP: watch a saved manifest FILE and serve its live preview (data from the host), so an
            # edit → refresh loop authors against real data. Re-lints on each save.
            holder = {"m": _load_manifest(args.manifest)}
            threading.Thread(target=_serve_preview, args=(lambda: holder["m"], base, {}, contracts, args.port),
                             daemon=True).start()
            print(f"round-trip: {args.manifest} ↔ live {base}", flush=True)
            report, _ = _dev_report(args.manifest, args.contracts, args.descriptors)
            print(report + "\n", flush=True)
            last_mt = os.path.getmtime(args.manifest)
            try:
                while True:
                    time.sleep(args.interval)
                    now_mt = os.path.getmtime(args.manifest) if os.path.exists(args.manifest) else last_mt
                    if now_mt != last_mt:
                        last_mt = now_mt
                        holder["m"] = _load_manifest(args.manifest)
                        rep, clean = _dev_report(args.manifest, args.contracts, args.descriptors)
                        print(("✓ " if clean else "✗ ") + "reloaded @ save\n" + rep + "\n", flush=True)
            except KeyboardInterrupt:
                print("\nstopped.", flush=True)
            return 0
        # one command: introspect a running host → serve a LIVE preview app
        manifest, _samples, cap_inputs, skipped, ncaps = _introspect_host(
            base, _parse_params(getattr(args, "param", None)), only=args.only, contracts=contracts,
            reuse=_harvest_views(getattr(args, "reuse", None)), include_writes=False,
            product_id="product:introspected", prefer=getattr(args, "variant", None),
            actions=getattr(args, "actions", False), dashboard=getattr(args, "dashboard", False))
        routes = manifest["ui"]["routes"]
        print(f"introspected {base}: {ncaps} caps · drafted {len(routes)} routes "
              f"({', '.join(r['id'] for r in routes) or 'none'})", flush=True)
        if not routes:
            print("no routes drafted — nothing to preview (supply --param for input-taking caps?)", flush=True)
            return 1
        _serve_preview(lambda: manifest, base, cap_inputs, contracts, args.port)
        return 0

    if not args.manifest:
        raise SystemExit("chp app dev: provide a manifest to watch, or --host to introspect + preview.")

    if args.module and os.getcwd() not in sys.path:   # a --module is usually a cwd-local app module
        sys.path.insert(0, os.getcwd())

    def _emit() -> None:
        report, clean = _dev_report(args.manifest, args.contracts, args.descriptors)
        print(("✓ " if clean else "✗ ") + "lint @ save\n" + report + "\n", flush=True)

    server = None
    thread = None

    def _serve() -> None:
        nonlocal server, thread
        if not args.module:
            return
        from ..http import create_http_server
        mod_name, _, factory = args.module.partition(":")
        mod = importlib.import_module(mod_name)
        importlib.reload(mod)                      # pick up edits to the app module
        built = getattr(mod, factory)(args.app) if args.app else getattr(mod, factory)()
        host = getattr(built, "host", built)       # a MaterializedProduct (.host) or a bare host
        if server is not None:
            server.shutdown()
            server.server_close()
        server = create_http_server(host, bind="127.0.0.1", port=args.port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f"serving http://127.0.0.1:{args.port}  (POST /invoke)", flush=True)

    paths = [args.manifest]                        # watch the manifest always; + the module file below
    if args.module:
        mod_name = args.module.split(":")[0]
        spec = importlib.util.find_spec(mod_name)
        if spec and spec.origin:
            paths.append(spec.origin)
    _emit()
    _serve()
    last = {p: (os.path.getmtime(p) if os.path.exists(p) else 0.0) for p in paths}
    print(f"watching {', '.join(paths)} … (Ctrl-C to stop)", flush=True)
    try:
        while True:
            time.sleep(args.interval)             # ponytail: mtime poll — no watchdog dep for a dev loop
            now = {p: (os.path.getmtime(p) if os.path.exists(p) else 0.0) for p in paths}
            if now != last:
                last = now
                _emit()
                _serve()
    except KeyboardInterrupt:
        if server is not None:
            server.shutdown()
            server.server_close()
        print("\nstopped.", flush=True)
    return 0


def register(subcommands) -> None:
    app = subcommands.add_parser("app", help="Build composable Materialized-Product apps (check, scaffold).")
    app_sub = app.add_subparsers(dest="app_command", required=True)

    check = app_sub.add_parser("check", help="Lint a manifest's bindings against a component-contract catalog.")
    check.add_argument("manifest", help="Path to the product manifest (JSON).")
    check.add_argument("--contracts", default=None, help="Path to component-contracts.json (from @chp/ui).")
    check.set_defaults(func=cmd_app_check)

    cov = app_sub.add_parser("coverage", help="UI coverage — which capabilities are surfaced vs SILENT.")
    cov.add_argument("manifest", help="Path to the product manifest (JSON).")
    cov.add_argument("--caps", default=None,
                     help="PATH to a JSON file: list of the product's capability ids (else the manifest's `requires`).")
    cov.set_defaults(func=cmd_app_coverage)

    smoke = app_sub.add_parser("smoke", help="Render every route against a live host; report failing routes.")
    smoke.add_argument("manifest", help="Path to the product manifest (JSON).")
    smoke.add_argument("--host", required=True, help="Base URL of a running CHP host.")
    smoke.add_argument("--contracts", default=None, help="component-contracts.json (else the bundled catalog).")
    smoke.set_defaults(func=cmd_app_smoke)

    gov = app_sub.add_parser("governance",
                             help="Governance-completeness — governed fraction + ungoverned mutation surfaces.")
    gov.add_argument("manifest", help="Path to the product manifest (JSON).")
    gov.add_argument("--descriptors", required=True,
                     help="PATH to a JSON file: host capability descriptors ({id, side_effects?}).")
    gov.set_defaults(func=cmd_app_governance)

    comp = app_sub.add_parser("components", help="Discovery — list bindable components + the prop each expects.")
    comp.add_argument("--contracts", default=None, help="Path to component-contracts.json (from @chp/ui).")
    comp.set_defaults(func=cmd_app_components)

    var = app_sub.add_parser("variants", help="List component variants by shape family (swap presentations).")
    var.add_argument("--contracts", default=None, help="Path to component-contracts.json (from @chp/ui).")
    var.set_defaults(func=cmd_app_variants)

    schema = app_sub.add_parser("schema", help="Generate the manifest JSON Schema (editor validation + autocomplete).")
    schema.add_argument("--contracts", default=None,
                        help="component-contracts.json — surfaces component ids as autocomplete examples.")
    schema.add_argument("--out", default=None, help="Write the schema to this file (else print to stdout).")
    schema.set_defaults(func=cmd_app_schema)

    intr = app_sub.add_parser("introspect",
                              help="Point at a running host: sample its read caps, infer shapes, draft an app.")
    intr.add_argument("--host", required=True, help="Base URL of a running CHP host, e.g. http://127.0.0.1:8770")
    intr.add_argument("--contracts", default=None, help="component-contracts.json (from @chp/ui).")
    intr.add_argument("--only", default=None, help="Only introspect caps whose id starts with this prefix.")
    intr.add_argument("--param", action="append", default=None, metavar="KEY=VALUE",
                      help="Shared sample input applied to any read cap that declares it (repeatable), "
                           "e.g. --param owner=octocat --param repo=Hello-World.")
    intr.add_argument("--reuse", default=None, help="Comma-separated manifest paths whose ui.views seed reuse.")
    intr.add_argument("--variant", action="append", default=None, metavar="COMPONENT_ID",
                      help="Prefer this component for its shape family (repeatable), e.g. chp.widgets.CardGrid.")
    intr.add_argument("--actions", action="store_true",
                      help="Surface write caps as governed ActionButton routes (invoked through the gate on "
                           "click, never sampled) instead of skipping them.")
    intr.add_argument("--dashboard", action="store_true",
                      help="Open on an Overview page combining the display routes as grid regions.")
    intr.add_argument("--include-writes", action="store_true",
                      help="Also sample mutating caps (DANGER: fires side effects). Off by default.")
    intr.add_argument("--product-id", default="product:introspected")
    intr.add_argument("--out", default=None, help="Write the drafted manifest here (else print to stdout).")
    intr.add_argument("--samples-out", default=None, help="Also write the raw {cap: sample} results here.")
    intr.set_defaults(func=cmd_app_introspect)

    sg = app_sub.add_parser("suggest", help="Draft a manifest by matching a host's capabilities to components.")
    sg.add_argument("--descriptors", required=True,
                    help="PATH to a JSON file: list of host capability descriptors ({id, category?, output_schema?}).")
    sg.add_argument("--contracts", default=None, help="component-contracts.json (from @chp/ui).")
    sg.add_argument("--samples", default=None,
                    help="PATH to a JSON file {cap_id: sample_result} — infer each cap's output_schema from "
                         "one live result so drafting shape-matches (any adapter, no declared schema needed).")
    sg.add_argument("--reuse", default=None,
                    help="Comma-separated manifest paths whose ui.views seed a reuse library — a cap that "
                         "is a known View's source binds THAT View (compose from shared Views).")
    sg.add_argument("--variant", action="append", default=None, metavar="COMPONENT_ID",
                    help="Prefer this component for its shape family (repeatable), e.g. --variant chp.widgets.CardGrid.")
    sg.add_argument("--product-id", default="product:suggested")
    sg.add_argument("--out", default=None, help="Write the drafted manifest here (else print to stdout).")
    sg.set_defaults(func=cmd_app_suggest)

    dev = app_sub.add_parser("dev",
                             help="Watch a manifest and re-lint (+ live serve), OR --host to introspect+preview.")
    dev.add_argument("manifest", nargs="?", default=None, help="Path to the product manifest (JSON) to watch.")
    dev.add_argument("--host", default=None,
                     help="Introspect a running host and serve a LIVE preview app of it — one command, no file.")
    dev.add_argument("--param", action="append", default=None, metavar="KEY=VALUE",
                     help="Shared sample input for --host introspection (repeatable), e.g. --param owner=octocat.")
    dev.add_argument("--only", default=None, help="With --host: only caps whose id starts with this prefix.")
    dev.add_argument("--reuse", default=None, help="With --host: manifest paths whose ui.views seed reuse.")
    dev.add_argument("--variant", action="append", default=None, metavar="COMPONENT_ID",
                     help="With --host: prefer this component for its shape family (e.g. chp.widgets.CardGrid).")
    dev.add_argument("--actions", action="store_true", help="With --host: surface writes as ActionButton routes.")
    dev.add_argument("--dashboard", action="store_true", help="With --host: open on a combined Overview page.")
    dev.add_argument("--contracts", default=None, help="component-contracts.json (from @chp/ui).")
    dev.add_argument("--descriptors", default=None,
                     help="PATH to a JSON file of host descriptors — enables resolve + coverage + governance.")
    dev.add_argument("--module", default=None,
                     help="mod:factory that builds the app's host (a MaterializedProduct or host) — live-serve it.")
    dev.add_argument("--app", default=None, help="Optional arg passed to the factory (e.g. an app name).")
    dev.add_argument("--port", type=int, default=8770, help="Serve/preview port.")
    dev.add_argument("--interval", type=float, default=1.0, help="mtime poll interval (seconds).")
    dev.set_defaults(func=cmd_app_dev)

    sv = app_sub.add_parser("scaffold-view",
                            help="Generate a view-cap stub bridging a source capability to a component.")
    sv.add_argument("--component", required=True, help="Target component id, e.g. chp.widgets.StatGrid.")
    sv.add_argument("--source-cap", required=True, help="Source data capability id to compose.")
    sv.add_argument("--contracts", default=None, help="component-contracts.json (for the target shape).")
    sv.add_argument("--view-id", default=None, help="Override the generated view capability id.")
    sv.add_argument("--out", default=None, help="Write the stub to this file (else print to stdout).")
    sv.set_defaults(func=cmd_app_scaffold_view)
