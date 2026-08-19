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

from ..app_lint import check_bindings, lint_report
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

    sv = app_sub.add_parser("scaffold-view",
                            help="Generate a view-cap stub bridging a source capability to a component.")
    sv.add_argument("--component", required=True, help="Target component id, e.g. chp.widgets.StatGrid.")
    sv.add_argument("--source-cap", required=True, help="Source data capability id to compose.")
    sv.add_argument("--contracts", default=None, help="component-contracts.json (for the target shape).")
    sv.add_argument("--view-id", default=None, help="Override the generated view capability id.")
    sv.add_argument("--out", default=None, help="Write the stub to this file (else print to stdout).")
    sv.set_defaults(func=cmd_app_scaffold_view)
