"""Parity + regression tests for chp_core.agent.

The fixture ``agent_golden_master.json`` was frozen from LIVE chp-home (assistant._select,
rank_by_cosine, skills.Skill). chp_core.agent must reproduce it EXACTLY — this is the gate that keeps
the shared substrate and chp-home's reference behavior in lockstep so the (later) port of chp-home onto
this module can never silently swap a model or break a signed skill. The test deliberately does NOT
import chp_home (chp_core must not depend on a product); it asserts against the static baseline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chp_core.agent import ModelCard, ModelCatalog, Skill, rank_by_cosine, resolve_model

_GOLDEN = json.loads((Path(__file__).parent / "agent_golden_master.json").read_text())


def _catalog() -> ModelCatalog:
    cards = [
        ModelCard(name=name, params_b=c["params_b"], backend=c.get("backend", ""),
                  coder=c.get("coder", False), tools=c.get("tools", False),
                  embedding=c.get("embedding", False))
        for name, c in _GOLDEN["routing_catalog"].items()
    ]
    return ModelCatalog(cards)


@pytest.mark.parametrize("role,expected", list(_GOLDEN["home_routing_by_role"].items()))
def test_routing_matches_home_golden_master(role: str, expected: list | None) -> None:
    # expected is [backend, model_id] frozen from chp-home; the shared module returns the model_id.
    expected_id = expected[1] if expected else None
    assert _catalog().resolve(role) == expected_id


def test_routing_diverges_from_old_platform_on_tiers() -> None:
    # Sanity that the fixture actually captured a real divergence (tool + reason tiers) — i.e. the
    # parity above is meaningful, not vacuous. chp_core follows HOME, not old-platform.
    cat = _catalog()
    diverged = [r for r in _GOLDEN["role_strategy"]
                if _GOLDEN["home_routing_by_role"][r][1] != _GOLDEN["platform_routing_by_role"][r]]
    assert diverged, "fixture should include tiers where old-platform disagreed with home"
    for r in diverged:
        assert cat.resolve(r) == _GOLDEN["home_routing_by_role"][r][1]


@pytest.mark.parametrize("case", _GOLDEN["skill_canonical"], ids=lambda c: c["fields"]["name"])
def test_skill_canonical_bytes_are_byte_identical(case: dict) -> None:
    # HARD GATE: a signed skill's canonical bytes must not change, or every published skill fails verify.
    s = Skill.from_dict(case["fields"])
    assert s.canonical().hex() == case["canonical_hex"]
    assert s.sha256() == case["sha256"]


# tool-RAG: the vectors are the deterministic test inputs; the fixture froze the resulting order.
_TOOL_RAG_VECS = [
    ([1.0, 0.0, 0.0], [[0.9, 0.1, 0.0], [0.0, 1.0, 0.0], [0.8, 0.2, 0.0], [0.0, 0.0, 1.0]],
     ["cap.a", "cap.b", "cap.c", "cap.d"], 4),
    ([0.0, 1.0, 0.0], [[0.0, 0.9, 0.1], [0.5, 0.5, 0.0], [0.0, 0.2, 0.8]], ["x", "y", "z"], 2),
]


@pytest.mark.parametrize("vecs,expected", list(zip(_TOOL_RAG_VECS, [c["order"] for c in _GOLDEN["tool_rag_cases"]])))
def test_tool_rag_order_matches_home(vecs: tuple, expected: list) -> None:
    task_vec, spec_vecs, ids, k = vecs
    assert rank_by_cosine(task_vec, spec_vecs, ids, k) == expected


def test_pin_and_override_rules() -> None:
    cards = [ModelCard.from_name("a:3b"), ModelCard.from_name("b:70b", tools=True)]
    assert resolve_model("reason", cards, pin="a:3b") == "a:3b"          # pin wins
    # a product override rule (cloud "always largest") is honored
    biggest = {"tool": lambda items: max(items, key=lambda c: c.params_b)}
    assert resolve_model("tool", cards, rules=biggest) == "b:70b"


def test_empty_catalog_is_none() -> None:
    assert ModelCatalog([]).resolve("tool") is None
