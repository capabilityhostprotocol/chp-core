"""Typed composition DAG (composition wave arc 2; CHP-COMP-003/006/007/008/009/010/011/013).

Proves the typed-DAG semantics that the linear composition adapter could not express: typed edges,
data-edge artifact continuity, an evidence edge that schedules but never admits, indeterminate
blocking a safety-critical node, explicit join conditions, the full partial-completion state
taxonomy, and compensation as a new governed node.
"""

import pytest

from chp_core import (
    Composition,
    CompositionEdge,
    CompositionNode,
    classify,
    compensation_node,
    ready_nodes,
)


def _n(nid, **kw):
    return CompositionNode(id=nid, capability={"id": f"cap.{nid}"}, **kw)


# ---- COMP-003: typed edges + structural validation ----

def test_edge_type_and_graph_validation():
    with pytest.raises(ValueError):
        CompositionEdge(src="a", dst="b", type="magic")           # bad edge type
    with pytest.raises(ValueError):
        Composition(nodes=[_n("a")], edges=[CompositionEdge("a", "z", "control")])  # dangling
    with pytest.raises(ValueError):
        Composition(nodes=[_n("a"), _n("b")],
                    edges=[CompositionEdge("a", "b", "control"), CompositionEdge("b", "a", "control")])  # cycle


# ---- control / data / evidence edge semantics ----

def test_control_edge_needs_upstream_completed():
    c = Composition(nodes=[_n("a"), _n("b")], edges=[CompositionEdge("a", "b", "control")])
    assert ready_nodes(c, {"a": "pending"}) == ["a"]              # root ready, b waits
    assert ready_nodes(c, {"a": "running"}) == []
    assert ready_nodes(c, {"a": "completed"}) == ["b"]


def test_data_edge_requires_the_upstream_artifact():  # COMP-007
    c = Composition(nodes=[_n("a"), _n("b")], edges=[CompositionEdge("a", "b", "data")])
    assert ready_nodes(c, {"a": "completed"}) == []              # completed but no artifact carried
    assert ready_nodes(c, {"a": "completed"}, artifacts={"a"}) == ["b"]


def test_evidence_edge_schedules_but_is_not_admission():  # COMP-006
    c = Composition(nodes=[_n("a"), _n("b")], edges=[CompositionEdge("a", "b", "evidence")])
    st = classify(c, {"a": "completed"})
    assert st["b"] == "ready"          # evidence available → schedulable...
    assert st["b"] != "completed"      # ...but readiness is NOT admission; b still runs governed


# ---- COMP-010 / COMP-008: indeterminate handling ----

def test_indeterminate_blocks_a_safety_critical_node():  # COMP-010
    c = Composition(nodes=[_n("a"), _n("b", safety_critical=True)],
                    edges=[CompositionEdge("a", "b", "control")])
    assert classify(c, {"a": "indeterminate"})["b"] == "blocked"   # never proceeds on 'don't know'
    assert "b" not in ready_nodes(c, {"a": "indeterminate"})


def test_indeterminate_makes_a_normal_node_wait_never_ready():  # COMP-008 (explicit, not silently done)
    c = Composition(nodes=[_n("a"), _n("b")], edges=[CompositionEdge("a", "b", "control")])
    st = classify(c, {"a": "indeterminate"})
    assert st["b"] == "pending"        # waits; indeterminate is never read as completed


# ---- COMP-013: explicit join semantics ----

def test_join_all_vs_any():
    nodes = [_n("a"), _n("b"), _n("j_all", join="all"), _n("j_any", join="any")]
    edges = [CompositionEdge("a", "j_all", "control"), CompositionEdge("b", "j_all", "control"),
             CompositionEdge("a", "j_any", "control"), CompositionEdge("b", "j_any", "control")]
    c = Composition(nodes=nodes, edges=edges)
    st = classify(c, {"a": "completed", "b": "pending"})
    assert st["j_any"] == "ready"      # any: one upstream done is enough
    assert st["j_all"] == "pending"    # all: still waiting on b
    assert classify(c, {"a": "completed", "b": "completed"})["j_all"] == "ready"


# ---- COMP-009: partial-completion taxonomy preserved ----

def test_classify_preserves_terminal_states():
    c = Composition(nodes=[_n("a"), _n("b"), _n("d")],
                    edges=[CompositionEdge("a", "b", "control")])
    st = classify(c, {"a": "completed", "b": "failed", "d": "pending"})
    assert st["a"] == "completed" and st["b"] == "failed" and st["d"] == "ready"


# ---- COMP-011: compensation is a new governed node ----

def test_compensation_is_a_new_node_not_a_rollback():
    a = _n("a")
    comp = compensation_node(a, capability={"id": "cap.undo_a"})
    assert comp.id != a.id and comp.id.startswith("cnode_")
    assert comp.capability == {"id": "cap.undo_a"}   # a fresh invocation, not an undo of a
