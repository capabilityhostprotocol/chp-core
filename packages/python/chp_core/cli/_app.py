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
    check_bindings,
    check_coverage,
    coverage_report,
    lint_report,
    suggest_bindings,
    suggest_manifest,
)
from ..manifest import parse_manifest


def _load_manifest(path: str) -> dict:
    return json.loads(Path(path).read_text())   # JSON manifest (keeps chp_core dependency-free)


def _load_contracts(path: str | None) -> dict:
    return json.loads(Path(path).read_text()) if path else {}


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


def cmd_app_components(args: argparse.Namespace) -> int:
    contracts = _load_contracts(args.contracts)
    if not contracts:
        print("no --contracts catalog given (pass @chp/ui component-contracts.json).")
        return 0
    print(f"{len(contracts)} bindable components:")
    for cid, c in sorted(contracts.items()):
        needs = f" + static {c['also_needs']}" if c.get("also_needs") else ""
        print(f"  {cid:38} card '{c['data_prop']}' ({c.get('kind', '?')}){needs}")
    return 0


def cmd_app_suggest(args: argparse.Namespace) -> int:
    descriptors = json.loads(Path(args.descriptors).read_text())
    contracts = _load_contracts(args.contracts)
    manifest = suggest_manifest(args.product_id, descriptors, contracts)
    text = json.dumps(manifest, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n")
        print(f"wrote {args.out} — {len(manifest['ui']['routes'])} routes drafted; refine, then `chp app check`")
    else:
        print(text)
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
    region = {"type": "object", "required": ["id"], "additionalProperties": False,
              "properties": {"id": {"type": "string"}, "label": {"type": "string"}, "component": component,
                             "span": {"type": "integer", "minimum": 1, "maximum": 12},
                             "bindings": {"type": "array", "items": binding}}}
    route = {"type": "object", "required": ["id"], "additionalProperties": False,
             "properties": {"id": {"type": "string"}, "path": {"type": "string"}, "label": {"type": "string"},
                            "icon": {"type": "string"}, "view": {"type": "string"}, "component": component,
                            "layout": {"enum": ["stack", "grid", "flex"]},
                            "bindings": {"type": "array", "items": binding},
                            "regions": {"type": "array", "items": region}}}
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
    vid = view_id or f"chp.view.{short}"
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
                     help="JSON list of the product's capability ids (else the manifest's `requires`).")
    cov.set_defaults(func=cmd_app_coverage)

    comp = app_sub.add_parser("components", help="Discovery — list bindable components + the prop each expects.")
    comp.add_argument("--contracts", default=None, help="Path to component-contracts.json (from @chp/ui).")
    comp.set_defaults(func=cmd_app_components)

    schema = app_sub.add_parser("schema", help="Generate the manifest JSON Schema (editor validation + autocomplete).")
    schema.add_argument("--contracts", default=None,
                        help="component-contracts.json — surfaces component ids as autocomplete examples.")
    schema.add_argument("--out", default=None, help="Write the schema to this file (else print to stdout).")
    schema.set_defaults(func=cmd_app_schema)

    sg = app_sub.add_parser("suggest", help="Draft a manifest by matching a host's capabilities to components.")
    sg.add_argument("--descriptors", required=True,
                    help="JSON list of host capability descriptors ({id, category?, output_schema?}).")
    sg.add_argument("--contracts", default=None, help="component-contracts.json (from @chp/ui).")
    sg.add_argument("--product-id", default="product:suggested")
    sg.add_argument("--out", default=None, help="Write the drafted manifest here (else print to stdout).")
    sg.set_defaults(func=cmd_app_suggest)

    sv = app_sub.add_parser("scaffold-view",
                            help="Generate a view-cap stub bridging a source capability to a component.")
    sv.add_argument("--component", required=True, help="Target component id, e.g. chp.widgets.StatGrid.")
    sv.add_argument("--source-cap", required=True, help="Source data capability id to compose.")
    sv.add_argument("--contracts", default=None, help="component-contracts.json (for the target shape).")
    sv.add_argument("--view-id", default=None, help="Override the generated view capability id.")
    sv.add_argument("--out", default=None, help="Write the stub to this file (else print to stdout).")
    sv.set_defaults(func=cmd_app_scaffold_view)
