"""chp app check + scaffold-view (composable-apps DX CLI)."""

from __future__ import annotations

import argparse
import json

import pytest

from chp_core.cli import build_parser
from chp_core.cli._app import (
    _scaffold_view,
    cmd_app_check,
    cmd_app_components,
    cmd_app_coverage,
    cmd_app_suggest,
)

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


def test_coverage_prints_silent_caps(tmp_path, capsys):
    m = {"id": "p", "version": "0.1.0", "assurance": "S1", "projection": "merge",
         "requires": [{"capability": "a.read", "range": ">=1.0"},
                      {"capability": "a.silent", "range": ">=1.0"}],
         "ui": {"routes": [{"id": "t", "path": "/", "component": "chp.widgets.StatGrid",
                            "bindings": [{"card": "stats", "capability": "a.read"}]}]}}
    assert cmd_app_coverage(argparse.Namespace(manifest=_write(tmp_path, "m.json", m), caps=None)) == 0
    out = capsys.readouterr().out
    assert "a.silent" in out and "surfaced" in out


def test_components_lists_the_catalog(tmp_path, capsys):
    assert cmd_app_components(argparse.Namespace(contracts=_write(tmp_path, "c.json", _CONTRACTS))) == 0
    assert "chp.widgets.StatGrid" in capsys.readouterr().out


def test_suggest_drafts_a_manifest(tmp_path, capsys):
    descs = [{"id": "host.topology",
              "output_schema": {"type": "object", "properties": {"hosts": {"type": "array"}}}}]
    args = argparse.Namespace(descriptors=_write(tmp_path, "d.json", descs),
                              contracts=_write(tmp_path, "c.json", _CONTRACTS),
                              product_id="product:x", out=None)
    assert cmd_app_suggest(args) == 0
    out = capsys.readouterr().out
    assert "product:x" in out
    assert '"component"' in out and '"host.topology"' in out   # a route was drafted binding the cap


def test_generated_schema_validates_a_real_manifest_and_surfaces_components():
    import jsonschema

    from chp_core.cli._app import _manifest_schema
    schema = _manifest_schema(_CONTRACTS)
    jsonschema.validate(_OK, schema)                       # a valid manifest passes
    comp = schema["properties"]["ui"]["properties"]["routes"]["items"]["properties"]["component"]
    assert "chp.widgets.StatGrid" in comp["examples"]      # component ids surfaced for autocomplete
    assert "data-driven" in schema["properties"]["ui"]["properties"]["archetype"]["enum"]  # enum from chp_core


def test_generated_schema_rejects_a_bad_manifest():
    import jsonschema

    from chp_core.cli._app import _manifest_schema
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"id": "NOT-a-product", "version": "0.1.0"}, _manifest_schema({}))


def test_scaffold_view_emits_a_compilable_stub_with_the_right_shape():
    code = _scaffold_view("chp.widgets.StatGrid", "chp.adapters.host.stats", "stats", "array", None)
    compile(code, "<scaffold>", "exec")                     # generated stub is valid Python
    assert 'ctx.ainvoke("chp.adapters.host.stats"' in code
    assert 'return {"stats": stats}' in code
    assert 'id="chp.view.stats"' in code
