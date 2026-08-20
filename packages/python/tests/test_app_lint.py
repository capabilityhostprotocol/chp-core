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


def test_view_output_schema_is_the_contract_for_shape_kind_without_descriptors():
    # A view-bound route is shape-checked from the View's own output_schema — no external descriptors.
    from chp_core.product import View
    ui = ProductUISchema(
        routes=[Route(id="r", component="chp.widgets.StatGrid",
                      bindings=[RouteBinding(card="stats", capability="v.stats", extract="stats")])],
        views=[View(id="v.stats", source_capability="host.stats",
                    output_schema={"type": "object", "properties": {"stats": {"type": "array"}}})])
    assert check_bindings(ProductSpecification("p", "0.1.0", [], ui=ui), _CONTRACTS) == []
    # a View whose emitted shape is the WRONG kind (object where StatGrid wants array) → shape_kind issue
    ui_bad = ProductUISchema(
        routes=[Route(id="r", component="chp.widgets.StatGrid",
                      bindings=[RouteBinding(card="stats", capability="v.bad", extract="stats")])],
        views=[View(id="v.bad", source_capability="host.stats",
                    output_schema={"type": "object", "properties": {"stats": {"type": "object"}}})])
    kinds = {i.kind for i in check_bindings(ProductSpecification("p", "0.1.0", [], ui=ui_bad), _CONTRACTS)}
    assert "shape_kind" in kinds


def test_suggest_manifest_reuses_a_view_when_a_cap_is_its_source():
    from chp_core.app_lint import suggest_manifest
    descs = [{"id": "host.stats",
              "output_schema": {"type": "object", "properties": {"stats": {"type": "array"}}}}]
    reuse = [{"id": "chp.view.host_stats", "source_capability": "host.stats",
              "output_schema": {"type": "object", "properties": {"stats": {"type": "array"}}}}]
    m = suggest_manifest("product:x", descs, _CONTRACTS, reuse_views=reuse)
    binding = m["ui"]["routes"][0]["bindings"][0]
    assert binding["capability"] == "chp.view.host_stats"      # bound the View, not the raw cap
    assert binding["extract"] == "stats"
    assert m["ui"]["views"] == reuse                           # the reused View rides into the draft


def test_governance_scores_governed_fraction_and_flags_ungoverned_mutations():
    from chp_core.app_lint import check_governance
    # host.restart mutates + has NO entitlement → flagged; billing.charge mutates but IS entitled → governed.
    descs = [
        {"id": "host.stats", "side_effects": []},
        {"id": "host.restart", "side_effects": "write"},
        {"id": "billing.charge", "side_effects": ["write"]},
    ]
    ui = ProductUISchema(routes=[Route(id="r", component="chp.widgets.StatGrid", bindings=[
        RouteBinding(card="stats", capability="host.stats"),
        RouteBinding(card="x", capability="host.restart"),
        RouteBinding(card="y", capability="billing.charge")])])
    spec = ProductSpecification("p", "0.1.0", [], entitlements={"billing.": "pack-billing"}, ui=ui)
    rep = check_governance(spec, descs)
    assert rep.surfaced == 3 and rep.mutations == 2
    assert rep.ungoverned_mutations == ["host.restart"]     # write + no entitlement
    assert rep.governed == 1                                 # billing.charge covered by 'billing.' prefix


def test_governance_credits_the_view_source_capability():
    # A View is a read projection; the underlying source_capability's side-effects/entitlement are what count.
    from chp_core.app_lint import check_governance
    from chp_core.product import View
    descs = [{"id": "host.restart", "side_effects": "write"}]
    ui = ProductUISchema(
        routes=[Route(id="r", component="chp.widgets.StatGrid",
                      bindings=[RouteBinding(card="stats", capability="v.danger")])],
        views=[View(id="v.danger", source_capability="host.restart")])
    rep = check_governance(ProductSpecification("p", "0.1.0", [], ui=ui), descs)
    assert rep.ungoverned_mutations == ["host.restart"]     # the View surfaces a mutating source


def test_reuse_picks_component_from_view_schema_not_cap_name():
    # A View's output_schema — not the source cap's name — chooses the component. host.stats emits `stats`,
    # so the reused View must bind StatGrid, NOT MeshTopology (which the cap-name 'host' would suggest).
    from chp_core.app_lint import suggest_manifest
    descs = [{"id": "host.stats"}]                       # no output_schema on the cap → name would win
    reuse = [{"id": "chp.mesh.view.host_stats", "source_capability": "host.stats",
              "output_schema": {"type": "object", "properties": {"stats": {"type": "array"}}}}]
    r = suggest_manifest("product:x", descs, _CONTRACTS, reuse_views=reuse)["ui"]["routes"][0]
    assert r["component"] == "chp.widgets.StatGrid"      # from the View shape, not 'host'→MeshTopology
    assert r["bindings"][0] == {"card": "stats", "capability": "chp.mesh.view.host_stats", "extract": "stats"}


def test_reuse_binds_also_needs_the_view_emits():
    from chp_core.app_lint import suggest_manifest
    contracts = {"chp.widgets.GovernanceSurface": {"data_prop": "decisions", "kind": "array",
                                                   "also_needs": ["summary"]}}
    descs = [{"id": "conf.check"}]
    reuse = [{"id": "v.gov", "source_capability": "conf.check",
              "output_schema": {"type": "object", "properties": {"decisions": {"type": "array"},
                                                                 "summary": {"type": "object"}}}}]
    r = suggest_manifest("product:x", descs, contracts, reuse_views=reuse)["ui"]["routes"][0]
    cards = {b["card"] for b in r["bindings"]}
    assert cards == {"decisions", "summary"}             # both the data prop AND the also_needs the View emits


def test_reuse_skips_a_descriptor_that_is_itself_a_view():
    # The view-cap ids are in the host descriptor set too; they must not be drafted raw (double coverage).
    from chp_core.app_lint import suggest_manifest
    descs = [{"id": "host.stats"}, {"id": "chp.mesh.view.host_stats"}]
    reuse = [{"id": "chp.mesh.view.host_stats", "source_capability": "host.stats",
              "output_schema": {"type": "object", "properties": {"stats": {"type": "array"}}}}]
    caps = {r["bindings"][0]["capability"]
            for r in suggest_manifest("product:x", descs, _CONTRACTS, reuse_views=reuse)["ui"]["routes"]}
    assert caps == {"chp.mesh.view.host_stats"}          # one route, via the View; the raw view-cap is skipped


def test_static_props_satisfy_also_needs_and_data_prop():
    # DataTable needs `items` (data) + `columns` (static). Bind items, supply columns in `props` → clean.
    contracts = {"chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "also_needs": ["columns"]}}
    ok = _spec([Route(id="t", component="chp.widgets.DataTable",
                      bindings=[RouteBinding(card="items", capability="x")],
                      props={"columns": [{"key": "name"}]})])
    assert check_bindings(ok, contracts) == []
    # without the static prop, columns is still flagged (bind it OR supply it)
    missing = _spec([Route(id="t", component="chp.widgets.DataTable",
                           bindings=[RouteBinding(card="items", capability="x")])])
    kinds = {i.kind for i in check_bindings(missing, contracts)}
    assert kinds == {"missing_static_prop"}


def test_infer_output_schema_from_a_sample_result():
    from chp_core.app_lint import infer_output_schema
    assert infer_output_schema([1, 2])["type"] == "array"
    assert infer_output_schema([]) == {"type": "array"}          # empty list → no item shape
    got = infer_output_schema({"adapters": [{"id": "x"}], "count": 3, "name": "s", "ok": True})
    assert got["properties"]["count"] == {"type": "number"}
    assert got["properties"]["name"] == {"type": "string"}
    assert got["properties"]["ok"] == {"type": "boolean"}
    assert got["properties"]["adapters"]["type"] == "array"                    # item shape captured too
    assert got["properties"]["adapters"]["items"]["properties"] == {"id": {"type": "string"}}


def test_inference_makes_suggest_shape_match_any_array_key():
    # A cap whose real array key isn't a conventional list name (`adapters`) — inference + any-array extract
    # resolve it, where the name-hint path could not.
    from chp_core.app_lint import descriptors_with_inferred_schemas, suggest_bindings
    descs = [{"id": "conformance.check_all"}]                       # no declared output_schema
    samples = {"conformance.check_all": {"adapters": [{"id": "a"}], "total": 0}}
    enriched = descriptors_with_inferred_schemas(descs, samples)
    s = suggest_bindings(enriched, _CONTRACTS)[0]
    assert s.extract == "adapters" and s.reason == "shape"         # learned the real array key from the sample


def test_inference_does_not_clobber_a_declared_schema():
    from chp_core.app_lint import descriptors_with_inferred_schemas
    descs = [{"id": "a", "output_schema": {"type": "object", "properties": {"rows": {"type": "array"}}}}]
    out = descriptors_with_inferred_schemas(descs, {"a": {"other": [1]}})
    assert out[0]["output_schema"]["properties"] == {"rows": {"type": "array"}}   # untouched


def test_inference_captures_array_item_shape():
    from chp_core.app_lint import infer_output_schema
    got = infer_output_schema({"issues": [{"number": 1, "title": "x", "open": True}]})
    items = got["properties"]["issues"]["items"]
    assert items["type"] == "object"
    assert set(items["properties"]) == {"number", "title", "open"}          # item keys captured


def test_columns_from_schema_derives_datatable_columns():
    from chp_core.app_lint import _columns_from_schema, infer_output_schema
    schema = infer_output_schema({"issues": [{"number": 1, "title": "x"}]})
    cols = _columns_from_schema(schema, "issues")
    assert cols == [{"key": "number", "label": "Number"}, {"key": "title", "label": "Title"}]
    assert _columns_from_schema(infer_output_schema({"n": 3}), None) is None   # not a list-of-objects


def test_suggest_auto_fills_datatable_columns_from_item_shape():
    from chp_core.app_lint import descriptors_with_inferred_schemas, suggest_manifest
    contracts = {"chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "also_needs": ["columns"]}}
    descs = descriptors_with_inferred_schemas(
        [{"id": "gh.list_issues"}], {"gh.list_issues": {"issues": [{"number": 1, "title": "x"}]}})
    m = suggest_manifest("product:x", descs, contracts)
    route = m["ui"]["routes"][0]
    assert [c["key"] for c in route["props"]["columns"]] == ["number", "title"]   # auto-filled, no hand-writing
    # and the drafted route is clean against the same catalog (data prop bound + columns supplied)
    from chp_core.app_lint import check_bindings
    from chp_core.manifest import parse_manifest
    assert check_bindings(parse_manifest(m), contracts) == []


def test_object_shaped_cap_maps_to_a_detail_component_with_auto_fields():
    from chp_core.app_lint import descriptors_with_inferred_schemas, suggest_manifest
    contracts = {"chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "also_needs": ["columns"]},
                 "chp.widgets.DetailCard": {"data_prop": "record", "kind": "object", "also_needs": ["fields"]}}
    # get_repo returns ONE object (no array) → DetailCard, with fields auto-filled from the object keys.
    descs = descriptors_with_inferred_schemas(
        [{"id": "gh.get_repo"}], {"gh.get_repo": {"full_name": "o/h", "stargazers_count": 42}})
    m = suggest_manifest("product:x", descs, contracts)
    route = m["ui"]["routes"][0]
    assert route["component"] == "chp.widgets.DetailCard"
    assert route["bindings"][0] == {"card": "record", "capability": "gh.get_repo"}   # whole object, no extract
    assert [f["key"] for f in route["props"]["fields"]] == ["full_name", "stargazers_count"]
    from chp_core.app_lint import check_bindings
    from chp_core.manifest import parse_manifest
    assert check_bindings(parse_manifest(m), contracts) == []                         # check-clean, no editing


def test_fields_from_schema_only_for_objects():
    from chp_core.app_lint import _fields_from_schema, infer_output_schema
    assert [f["key"] for f in _fields_from_schema(infer_output_schema({"a": 1, "b": 2}), None)] == ["a", "b"]
    assert _fields_from_schema(infer_output_schema([{"a": 1}]), None) is None          # a list is not a record


def test_generic_component_is_the_default_but_affinity_still_wins():
    # A list-of-objects with no name affinity → the GENERIC array component (DataTable), never a specialized
    # viz. But a cap whose name matches a specialized component (topology→MeshTopology) still picks it.
    from chp_core.app_lint import suggest_bindings
    contracts = {
        "chp.widgets.MeshTopology": {"data_prop": "hosts", "kind": "array"},          # specialized, listed first
        "chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "generic": True},
    }
    descs = [
        {"id": "kg.get_edges", "output_schema": {"type": "object", "properties": {"edges": {"type": "array"}}}},
        {"id": "host.topology", "output_schema": {"type": "object", "properties": {"hosts": {"type": "array"}}}},
    ]
    s = {x.capability: x.component for x in suggest_bindings(descs, contracts)}
    assert s["kg.get_edges"] == "chp.widgets.DataTable"       # generic default, not the first (MeshTopology)
    assert s["host.topology"] == "chp.widgets.MeshTopology"   # affinity beats the generic default


def test_variant_override_swaps_the_component_within_the_shape_family():
    from chp_core.app_lint import component_variants, suggest_manifest
    contracts = {
        "chp.widgets.DataTable": {"data_prop": "items", "kind": "array", "also_needs": ["columns"],
                                  "generic": True, "family": "records"},
        "chp.widgets.CardGrid": {"data_prop": "items", "kind": "array", "also_needs": ["columns"],
                                 "family": "records"},
    }
    assert component_variants(contracts) == {"records": ["chp.widgets.CardGrid", "chp.widgets.DataTable"]}
    descs = [{"id": "kg.list", "output_schema": {"type": "object", "properties": {"items": {"type": "array"}}}}]
    default = suggest_manifest("p", descs, contracts)["ui"]["routes"][0]["component"]
    carded = suggest_manifest("p", descs, contracts, prefer=["chp.widgets.CardGrid"])["ui"]["routes"][0]["component"]
    assert default == "chp.widgets.DataTable"        # generic default
    assert carded == "chp.widgets.CardGrid"          # variant override — same binding, different presentation


def test_action_component_is_not_shape_linted():
    # An ActionButton INVOKES a cap; its binding is a label+cap, not a data shape — the linter skips it.
    contracts = {"chp.widgets.ActionButton": {"data_prop": "actions", "kind": "action", "family": "action"}}
    spec = _spec([Route(id="a", component="chp.widgets.ActionButton",
                        bindings=[RouteBinding(card="Restart", capability="host.restart")])])
    assert check_bindings(spec, contracts) == []


def test_governance_name_backstop_flags_writes_with_lying_side_effects():
    # github declares side_effects=[] even on create_issue; the name backstop catches it anyway.
    from chp_core.app_lint import check_governance
    descs = [{"id": "gh.create_issue", "side_effects": []}, {"id": "gh.get_repo", "side_effects": []}]
    ui = ProductUISchema(routes=[
        Route(id="a", component="chp.widgets.ActionButton",
              bindings=[RouteBinding(card="Create issue", capability="gh.create_issue")]),
        Route(id="r", component="chp.widgets.DetailCard",
              bindings=[RouteBinding(card="record", capability="gh.get_repo")])])
    rep = check_governance(ProductSpecification("p", "0.1.0", [], ui=ui), descs)
    assert rep.ungoverned_mutations == ["gh.create_issue"]     # write flagged despite empty side_effects


def test_governance_reports_declared_view_coverage():
    from chp_core.app_lint import check_governance, governance_report
    from chp_core.product import View
    ui = ProductUISchema(
        routes=[Route(id="r", component="chp.widgets.DataTable",
                      bindings=[RouteBinding(card="items", capability="c.list")])],
        views=[View(id="view:list", source_capability="c.list", audience="operator",
                    decision_grade="informational")])
    rep = check_governance(ProductSpecification("p", "0.1.0", [], ui=ui), [{"id": "c.list", "side_effects": []}])
    assert rep.declared == 1                              # the surfaced cap carries a declared View
    assert "carry a declared View" in governance_report(rep)
