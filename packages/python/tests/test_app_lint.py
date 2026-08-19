"""chp_core.app_lint — author-time binding linter (composable-apps DX)."""

from __future__ import annotations

from chp_core.app_lint import check_bindings, lint_report
from chp_core.product import ProductSpecification, ProductUISchema, Region, Route, RouteBinding

_CONTRACTS = {
    "chp.widgets.StatGrid": {"data_prop": "stats", "kind": "array"},
    "chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "also_needs": ["columns"]},
    "chp.widgets.MeshTopology": {"data_prop": "hosts", "kind": "array"},
}


def _spec(routes):
    return ProductSpecification("p", "0.1.0", [], ui=ProductUISchema(routes=routes))


def test_clean_binding_reports_no_issues():
    spec = _spec([Route(id="ok", component="chp.widgets.StatGrid",
                        bindings=[RouteBinding(card="stats", capability="x")])])
    assert check_bindings(spec, _CONTRACTS) == []
    assert lint_report([]) == "✓ bindings OK"


def test_catches_prop_name_and_static_prop_and_unknown_card():
    # DataTable wants `items` + a static `columns`; binding `rows` fails all three ways.
    spec = _spec([Route(id="bad", component="chp.widgets.DataTable",
                        bindings=[RouteBinding(card="rows", capability="host.facts", extract="hosts")])])
    kinds = {i.kind for i in check_bindings(spec, _CONTRACTS)}
    assert kinds == {"missing_data_prop", "missing_static_prop", "unknown_card"}


def test_regions_are_linted_too():
    spec = _spec([Route(id="page", layout="grid", regions=[
        Region(id="t", component="chp.widgets.MeshTopology",
               bindings=[RouteBinding(card="topology", capability="host.topology")])])])   # topology != hosts
    issues = check_bindings(spec, _CONTRACTS)
    assert any(i.location == "region:t" and i.kind == "missing_data_prop" for i in issues)


def test_uncatalogued_component_is_skipped():
    spec = _spec([Route(id="fed", component="chp.crm.Pipeline",
                        bindings=[RouteBinding(card="anything", capability="x")])])
    assert check_bindings(spec, _CONTRACTS) == []   # federated render-cap — not in the catalog, not linted here


def test_shape_kind_flags_object_where_component_wants_array():
    from chp_core.types import CapabilityDescriptor
    # host.stats declares an OBJECT output; StatGrid wants an array → shape_kind mismatch (only with descriptors).
    desc = CapabilityDescriptor(id="host.stats", version="1.0.0", description="x",
                                output_schema={"type": "object", "properties": {"cpu_count": {"type": "integer"}}})
    spec = _spec([Route(id="s", component="chp.widgets.StatGrid",
                        bindings=[RouteBinding(card="stats", capability="host.stats")])])
    assert any(i.kind == "shape_kind" for i in check_bindings(spec, _CONTRACTS, [desc]))
    assert check_bindings(spec, _CONTRACTS) == []   # no descriptors → shape not checked (card matches → clean)


def test_shape_kind_clean_when_array_matches_at_extract_path():
    from chp_core.types import CapabilityDescriptor
    # cap returns {records: array}; extract 'records' → array; DataTable wants items: array → kind OK.
    desc = CapabilityDescriptor(id="a.list", version="1.0.0", description="x",
                                output_schema={"type": "object", "properties": {"records": {"type": "array"}}})
    spec = _spec([Route(id="d", component="chp.widgets.DataTable",
                        bindings=[RouteBinding(card="items", capability="a.list", extract="records"),
                                  RouteBinding(card="columns", capability="a.list")])])
    assert not any(i.kind == "shape_kind" for i in check_bindings(spec, _CONTRACTS, [desc]))


def test_coverage_reports_silent_capabilities():
    from chp_core.app_lint import check_coverage
    spec = _spec([Route(id="a", component="chp.widgets.StatGrid",
                        bindings=[RouteBinding(card="stats", capability="cap.surfaced")])])
    rep = check_coverage(spec, ["cap.surfaced", "cap.silent1", "cap.silent2"])
    assert rep.total == 3 and rep.surfaced == 1
    assert rep.silent == ["cap.silent1", "cap.silent2"]
    assert round(rep.score, 2) == 0.33


def test_coverage_all_surfaced():
    from chp_core.app_lint import check_coverage
    spec = _spec([Route(id="a", component="chp.widgets.StatGrid",
                        bindings=[RouteBinding(card="stats", capability="c1")])])
    rep = check_coverage(spec, ["c1"])
    assert rep.silent == [] and rep.score == 1.0


def test_suggest_matches_by_shape_and_affinity():
    from chp_core.app_lint import suggest_bindings
    descs = [
        {"id": "a.list", "output_schema": {"type": "object", "properties": {"records": {"type": "array"}}}},
        {"id": "host.topology", "output_schema": {"type": "object", "properties": {"hosts": {"type": "array"}}}},
        {"id": "crm.Board", "category": "component"},
    ]
    s = {x.capability: x for x in suggest_bindings(descs, _CONTRACTS)}
    assert "crm.Board" not in s                                        # render-cap skipped
    assert s["a.list"].extract == "records"                            # array under 'records' → matched
    assert s["host.topology"].component == "chp.widgets.MeshTopology"  # affinity: 'topology' in the cap id
    assert s["host.topology"].card == "hosts" and s["host.topology"].extract == "hosts"


def test_suggest_manifest_is_wellformed():
    from chp_core.app_lint import suggest_manifest
    descs = [{"id": "host.topology",
              "output_schema": {"type": "object", "properties": {"hosts": {"type": "array"}}}}]
    r = suggest_manifest("product:x", descs, _CONTRACTS)["ui"]["routes"][0]
    assert r["component"] == "chp.widgets.MeshTopology"
    assert r["bindings"][0] == {"card": "hosts", "capability": "host.topology", "extract": "hosts"}
