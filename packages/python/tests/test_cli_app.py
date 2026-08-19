"""chp app check + scaffold-view (composable-apps DX CLI)."""

from __future__ import annotations

import argparse
import json

from chp_core.cli import build_parser
from chp_core.cli._app import _scaffold_view, cmd_app_check

_CONTRACTS = {"chp.widgets.StatGrid": {"data_prop": "stats", "kind": "array"},
              "chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "also_needs": ["columns"]}}
_BAD = {"id": "product:x", "version": "0.1.0", "assurance": "S1", "projection": "merge",
        "ui": {"routes": [{"id": "t", "path": "/", "component": "chp.widgets.DataTable",
                           "bindings": [{"card": "rows", "capability": "a.read"}]}]}}
_OK = {"id": "product:y", "version": "0.1.0", "assurance": "S1", "projection": "merge",
       "ui": {"routes": [{"id": "t", "path": "/", "component": "chp.widgets.StatGrid",
                          "bindings": [{"card": "stats", "capability": "a.read"}]}]}}


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return str(p)


def test_app_subcommand_is_registered():
    build_parser().parse_args(["app", "check", "m.json"])   # parses without error → wired up


def test_check_exits_nonzero_on_mismatch(tmp_path, capsys):
    args = argparse.Namespace(manifest=_write(tmp_path, "bad.json", _BAD),
                              contracts=_write(tmp_path, "c.json", _CONTRACTS))
    assert cmd_app_check(args) == 1
    assert "DataTable" in capsys.readouterr().out


def test_check_exits_zero_when_clean(tmp_path):
    args = argparse.Namespace(manifest=_write(tmp_path, "ok.json", _OK),
                              contracts=_write(tmp_path, "c.json", _CONTRACTS))
    assert cmd_app_check(args) == 0


def test_scaffold_view_emits_a_compilable_stub_with_the_right_shape():
    code = _scaffold_view("chp.widgets.StatGrid", "chp.adapters.host.stats", "stats", "array", None)
    compile(code, "<scaffold>", "exec")                     # generated stub is valid Python
    assert 'ctx.ainvoke("chp.adapters.host.stats"' in code
    assert 'return {"stats": stats}' in code
    assert 'id="chp.view.stats"' in code
