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


def test_dev_report_lints_resolves_and_governs(tmp_path):
    import json as _json

    from chp_core.cli._app import _dev_report
    manifest = {"id": "product:d", "version": "0.1.0",
                "ui": {"archetype": "data-driven", "routes": [
                    {"id": "s", "path": "/", "component": "chp.widgets.StatGrid",
                     "bindings": [{"card": "stats", "capability": "host.stats"}]},
                    {"id": "d", "path": "/d", "component": "chp.widgets.StatGrid",
                     "bindings": [{"card": "stats", "capability": "host.restart"}]}]}}
    descs = [{"id": "host.stats", "output_schema": {"type": "object", "properties": {"stats": {"type": "array"}}}},
             {"id": "host.restart", "side_effects": "write"}]
    mp = tmp_path / "m.json"
    dp = tmp_path / "d.json"
    mp.write_text(_json.dumps(manifest))
    dp.write_text(_json.dumps(descs))
    report, clean = _dev_report(str(mp), None, str(dp))
    assert "✓ resolves" in report                       # requires auto-derived from descriptors
    assert "UI coverage: 2/2" in report
    assert "host.restart — mutates state" in report      # ungoverned mutation surfaced
    assert clean is False                                # a governance flag makes the report not-clean


def test_introspect_samples_read_caps_skips_mutations_and_input_caps(monkeypatch):
    import argparse

    from chp_core.cli import _app
    caps = {"capabilities": [
        {"id": "svc.list", "side_effects": []},                                    # read, no input → sampled
        {"id": "svc.create", "side_effects": "write"},                             # mutation → skipped
        {"id": "svc.get", "side_effects": [], "input_schema": {"required": ["id"]}},  # needs input → skipped
    ]}

    def fake_http(url, body=None, timeout=15.0):
        if url.endswith("/capabilities"):
            return caps
        assert body["capability_id"] == "svc.list"          # ONLY the safe read cap is ever invoked
        assert "payload" in body
        return {"outcome": "success", "data": {"records": [{"id": 1}]}}
    monkeypatch.setattr(_app, "_http_json", fake_http)
    monkeypatch.setattr(_app, "_load_contracts",
                        lambda _p: {"chp.widgets.DataTable": {"data_prop": "items", "kind": "array"}})

    captured = {}
    monkeypatch.setattr(_app.Path, "write_text", lambda self, txt: captured.update(out=txt))
    args = argparse.Namespace(host="http://h", contracts=None, only=None, param=None, reuse=None,
                              include_writes=False, product_id="product:i",
                              out="/x/m.json", samples_out=None)
    assert _app.cmd_app_introspect(args) == 0
    import json as _json
    manifest = _json.loads(captured["out"])
    caps_bound = {r["bindings"][0]["capability"] for r in manifest["ui"]["routes"]}
    assert caps_bound == {"svc.list"}                        # only the sampled read cap drafted a route


def test_introspect_name_backstop_and_param_inputs(monkeypatch):
    import argparse

    from chp_core.cli import _app
    caps = {"capabilities": [
        {"id": "gh.get_repo", "side_effects": [],
         "input_schema": {"required": ["owner", "repo"], "properties": {"owner": {}, "repo": {}}}},
        {"id": "gh.create_issue", "side_effects": [],   # under-declared mutation → name backstop skips it
         "input_schema": {"required": ["owner", "repo", "title"], "properties": {"owner": {}, "repo": {}, "title": {}}}},
        {"id": "gh.get_issue", "side_effects": [],       # read but needs `number` we don't supply → skipped
         "input_schema": {"required": ["owner", "repo", "number"], "properties": {"owner": {}, "repo": {}, "number": {}}}},
    ]}
    invoked = []

    def fake_http(url, body=None, timeout=15.0):
        if url.endswith("/capabilities"):
            return caps
        invoked.append((body["capability_id"], body["payload"]))
        return {"outcome": "success", "data": {"stargazers": 1, "name": body["input"]["repo"]}}
    monkeypatch.setattr(_app, "_http_json", fake_http)
    monkeypatch.setattr(_app, "_load_contracts", lambda _p: {})
    captured = {}
    monkeypatch.setattr(_app.Path, "write_text", lambda self, txt: captured.update(out=txt))
    args = argparse.Namespace(host="http://h", contracts=None, only=None,
                              param=["owner=octocat", "repo=Hello-World"], reuse=None,
                              include_writes=False, product_id="product:gh", out="/x/m.json", samples_out=None)
    assert _app.cmd_app_introspect(args) == 0
    assert invoked == [("gh.get_repo", {"owner": "octocat", "repo": "Hello-World"})]  # ONLY the safe, satisfiable read


def test_preview_renders_array_and_object_routes_from_live_invokes(monkeypatch):
    from chp_core.cli import _app
    contracts = {"chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "also_needs": ["columns"]},
                 "chp.widgets.DetailCard": {"data_prop": "record", "kind": "object", "also_needs": ["fields"]}}
    manifest = {"id": "product:p", "ui": {"routes": [
        {"id": "list", "label": "Nodes", "component": "chp.widgets.DataTable",
         "props": {"columns": [{"key": "node_id"}, {"key": "node_type"}]},
         "bindings": [{"card": "items", "capability": "kg.list_nodes", "extract": "nodes"}]},
        {"id": "detail", "label": "Node", "component": "chp.widgets.DetailCard",
         "props": {"fields": [{"key": "node_id"}, {"key": "node_type"}]},
         "bindings": [{"card": "record", "capability": "kg.get_node"}]}]}}

    def fake_http(url, body=None, timeout=15.0):
        cap = body["capability_id"]
        if cap == "kg.list_nodes":
            return {"outcome": "success", "data": {"nodes": [{"node_id": "chp", "node_type": "project"}]}}
        return {"outcome": "success", "data": {"node_id": "chp", "node_type": "project"}}
    monkeypatch.setattr(_app, "_http_json", fake_http)
    html = _app._render_preview(manifest, "http://h", {}, contracts)
    assert "<th>node_id</th>" in html and "<th>node_type</th>" in html   # DataTable headers from columns
    assert "<td>chp</td>" in html and "<td>project</td>" in html          # live rows
    assert "<dt>node_id</dt>" in html and "<dd>chp</dd>" in html          # DetailCard key/value
    assert 'id="list"' in html and 'id="detail"' in html                 # both routes as sections


def test_introspect_actions_surfaces_writes_as_governed_action_routes(monkeypatch):
    import argparse

    from chp_core.cli import _app
    caps = {"capabilities": [
        {"id": "svc.list", "side_effects": []},
        {"id": "svc.create", "side_effects": [],
         "input_schema": {"required": ["name"], "properties": {"name": {}}}},   # write (name backstop)
    ]}

    def fake_http(url, body=None, timeout=15.0):
        if url.endswith("/capabilities"):
            return caps
        assert body["capability_id"] == "svc.list"      # only the read is invoked; the write is NOT
        return {"outcome": "success", "data": {"items": [{"a": 1}]}}
    monkeypatch.setattr(_app, "_http_json", fake_http)
    monkeypatch.setattr(_app, "_load_contracts",
                        lambda _p: {"chp.widgets.DataTable": {"data_prop": "items", "kind": "array"}})
    captured = {}
    monkeypatch.setattr(_app.Path, "write_text", lambda self, txt: captured.update(out=txt))
    args = argparse.Namespace(host="http://h", contracts=None, only=None, param=["name=x"], reuse=None,
                              variant=None, include_writes=False, actions=True, product_id="product:i",
                              out="/x/m.json", samples_out=None)
    assert _app.cmd_app_introspect(args) == 0
    import json as _json
    m = _json.loads(captured["out"])
    byid = {r["id"]: r["component"] for r in m["ui"]["routes"]}
    assert byid["create"] == "chp.widgets.ActionButton"      # write surfaced as a governed action
    assert byid["list"] == "chp.widgets.DataTable"           # read still a display


def test_wire_master_detail_pairs_list_with_get_and_splits_row_vs_context():
    from chp_core.cli._app import _wire_master_detail
    caps = [
        {"id": "gh.list_issues"},
        {"id": "gh.get_issue", "input_schema": {"required": ["owner", "repo", "number"]}},
    ]
    samples = {"gh.list_issues": {"issues": [{"number": 7, "title": "x"}]}}
    manifest = {"ui": {"routes": [
        {"id": "list_issues", "bindings": [{"card": "items", "capability": "gh.list_issues", "extract": "issues"}]}]}}
    _wire_master_detail(manifest, caps, samples, {"owner": "octocat", "repo": "Hello-World"})
    d = manifest["ui"]["routes"][0]["bindings"][0]["detail"]
    assert d == {"capability": "gh.get_issue", "key": "number", "param": "number",
                 "params": {"owner": "octocat", "repo": "Hello-World"}}   # number per-row; owner/repo context


def test_synthesize_dashboard_groups_display_routes_into_regions():
    from chp_core.cli._app import _synthesize_dashboard
    m = {"ui": {"routes": [
        {"id": "a", "path": "/", "component": "chp.widgets.DataTable",
         "props": {"columns": [{"key": "x"}]}, "bindings": [{"card": "items", "capability": "c.a"}]},
        {"id": "b", "path": "/b", "component": "chp.widgets.DetailCard",
         "bindings": [{"card": "record", "capability": "c.b"}]},
        {"id": "act", "path": "/act", "component": "chp.widgets.ActionButton",
         "bindings": [{"card": "Do", "capability": "c.write"}]}]}}
    _synthesize_dashboard(m)
    routes = m["ui"]["routes"]
    assert routes[0]["id"] == "overview" and routes[0]["path"] == "/"
    ids = {reg["id"] for reg in routes[0]["regions"]}
    assert ids == {"a", "b"}                                  # display routes tiled; the action route excluded
    assert routes[0]["regions"][0]["props"] == {"columns": [{"key": "x"}]}   # props carried into the region
    assert all(r["path"] != "/" for r in routes[1:])          # per-cap routes moved off "/"


def test_introspect_emits_governed_view_declarations(monkeypatch):
    import argparse

    from chp_core.cli import _app
    caps = {"capabilities": [{"id": "svc.list", "side_effects": []}]}

    def fake_http(url, body=None, timeout=15.0):
        if url.endswith("/capabilities"):
            return caps
        return {"outcome": "success", "data": {"items": [{"a": 1}]}}
    monkeypatch.setattr(_app, "_http_json", fake_http)
    monkeypatch.setattr(_app, "_load_contracts", lambda _p: {"chp.widgets.DataTable": {"data_prop": "items", "kind": "array"}})
    captured = {}
    monkeypatch.setattr(_app.Path, "write_text", lambda self, txt: captured.update(out=txt))
    args = argparse.Namespace(host="http://h", contracts=None, only=None, param=None, reuse=None, variant=None,
                              include_writes=False, actions=False, dashboard=False, product_id="product:i",
                              out="/x/m.json", samples_out=None)
    assert _app.cmd_app_introspect(args) == 0
    import json as _json
    views = _json.loads(captured["out"])["ui"]["views"]
    assert views[0]["source_capability"] == "svc.list"
    assert views[0]["audience"] == "operator" and views[0]["decision_grade"] == "informational"


def test_bundled_contracts_default_when_no_path():
    from chp_core.cli._app import _load_contracts
    c = _load_contracts(None)
    assert "chp.widgets.DataTable" in c and "chp.widgets.ActionButton" in c   # bundled catalog, no --contracts
    assert c["chp.widgets.DataTable"]["family"] == "records"


def test_introspect_persists_sampling_params_into_bindings(monkeypatch):
    import argparse

    from chp_core.cli import _app
    caps = {"capabilities": [
        {"id": "gh.list_issues", "input_schema": {"required": ["owner"], "properties": {"owner": {}}}}]}

    def fake_http(url, body=None, timeout=15.0):
        if url.endswith("/capabilities"):
            return caps
        return {"outcome": "success", "data": {"issues": [{"number": 1}]}}
    monkeypatch.setattr(_app, "_http_json", fake_http)
    captured = {}
    monkeypatch.setattr(_app.Path, "write_text", lambda self, txt: captured.update(out=txt))
    args = argparse.Namespace(host="http://h", contracts=None, only=None, param=["owner=octocat"], reuse=None,
                              variant=None, include_writes=False, actions=False, dashboard=False,
                              product_id="product:i", out="/x/m.json", samples_out=None)
    assert _app.cmd_app_introspect(args) == 0
    import json as _json
    b = _json.loads(captured["out"])["ui"]["routes"][0]["bindings"][0]
    assert b["params"] == {"owner": "octocat"}      # saved manifest is self-contained


def test_smoke_reports_failing_routes(monkeypatch, tmp_path):
    import argparse
    import json as _json

    from chp_core.cli import _app
    m = {"id": "product:s", "ui": {"routes": [
        {"id": "ok", "component": "chp.widgets.DataTable", "bindings": [{"card": "items", "capability": "c.ok"}]},
        {"id": "bad", "component": "chp.widgets.DataTable", "bindings": [{"card": "items", "capability": "c.bad"}]},
        {"id": "act", "component": "chp.widgets.ActionButton", "bindings": [{"card": "Do", "capability": "c.write"}]}]}}
    mp = tmp_path / "m.json"
    mp.write_text(_json.dumps(m))
    fired = []

    def fake_http(url, body=None, timeout=15.0):
        fired.append(body["capability_id"])
        return {"outcome": "success" if body["capability_id"] == "c.ok" else "denied"}
    monkeypatch.setattr(_app, "_http_json", fake_http)
    rc = _app.cmd_app_smoke(argparse.Namespace(manifest=str(mp), host="http://h", contracts=None))
    assert rc == 1                                  # a failing route → non-zero
    assert "c.write" not in fired                   # the action route is never fired
