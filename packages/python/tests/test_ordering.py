"""Tests for chp-causal-order-v1 (chp_core/ordering.py)."""

from __future__ import annotations

import json
from pathlib import Path

from chp_core.ordering import order_events

VEC = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "ordering.json"


def test_reproduces_the_published_vector_exactly():
    v = json.loads(VEC.read_text())
    assert [e["event_id"] for e in order_events(v["events"])] == v["expected_order"]


def test_input_order_is_irrelevant():
    v = json.loads(VEC.read_text())
    reversed_input = list(reversed(v["events"]))
    assert [e["event_id"] for e in order_events(reversed_input)] == v["expected_order"]


def test_causal_edge_overrides_wall_clock():
    v = json.loads(VEC.read_text())
    order = [e["event_id"] for e in order_events(v["events"])]
    # host-B's events are wall-clock EARLIER than evt_a1 but causally after it.
    assert order.index("evt_a1") < order.index("evt_b1") < order.index("evt_b2")


def test_total_on_cyclic_input():
    # Tampered data: two events causing each other. Must not raise; emits all.
    a = {"event_id": "x", "invocation_id": "ix", "host_id": "h1", "sequence": 1,
         "timestamp": "t1", "correlation": {"causation_id": "iy"}}
    b = {"event_id": "y", "invocation_id": "iy", "host_id": "h2", "sequence": 1,
         "timestamp": "t2", "correlation": {"causation_id": "ix"}}
    out = order_events([a, b])
    assert {e["event_id"] for e in out} == {"x", "y"}


def test_empty_and_single():
    assert order_events([]) == []
    one = [{"event_id": "e", "invocation_id": "i", "host_id": "h", "sequence": 1,
            "timestamp": "t", "correlation": {}}]
    assert order_events(one) == one
