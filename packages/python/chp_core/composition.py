"""Typed composition DAG — CompositionNode / CompositionEdge / Composition + eligibility semantics.

A composition is a DAG of governed capability invocations, NOT a super-invocation: every node is a
separate governed host.ainvoke (a runtime/adapter executes the nodes; this module defines the typed
structure + the eligibility rules). The whole point is that composing does not weaken governance:

- Edges are TYPED (control / data / evidence) and each type means something different for when a
  downstream node becomes eligible (COMP-003).
- An EVIDENCE edge makes upstream evidence AVAILABLE but NEVER auto-satisfies the downstream node —
  eligibility only schedules the node; it still faces its own governed admission (COMP-006).
- A DATA edge requires the upstream ARTIFACT to be present and carried forward (COMP-007).
- A node marked ``safety_critical`` whose dependency is ``indeterminate`` is BLOCKED, never ready —
  it never proceeds on "don't know" (COMP-010). Indeterminate always has EXPLICIT handling (block if
  safety-critical, else wait); it is never read as completed (COMP-008).
- A JOIN node declares the upstream condition it needs — ``all`` or ``any`` incoming edges (COMP-013).
- Composition state is per-node and spans the full partial-completion taxonomy (COMP-009).
- Compensation is a NEW governed node, never a rollback/undo (COMP-011).

Distributed atomicity is NOT claimed (COMP-012) and no authority/trust flows along an edge
(COMP-004/005): an edge schedules; it never carries a grant or admits a node.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .types import JSON, new_id, utc_now

_EDGE_TYPES = frozenset({"control", "data", "evidence"})
_JOINS = frozenset({"all", "any"})
# The per-node state taxonomy for partial completion (COMP-009).
NODE_STATES = frozenset(
    {"pending", "ready", "running", "completed", "failed", "indeterminate", "blocked", "compensated"}
)


@dataclass(slots=True)
class CompositionNode:
    """One node = one governed capability invocation (never collapsed with others). ``join`` is how
    many incoming edges must be satisfied to become eligible (all|any, COMP-013). ``safety_critical``
    marks a node whose safety depends on its upstream outcomes — it BLOCKS on an indeterminate
    dependency (COMP-010)."""

    id: str
    capability: JSON            # {id, version?}
    join: str = "all"
    safety_critical: bool = False

    JOINS: ClassVar[frozenset[str]] = _JOINS

    def __post_init__(self) -> None:
        if self.join not in _JOINS:
            raise ValueError(f"join must be one of {sorted(_JOINS)}")


@dataclass(slots=True)
class CompositionEdge:
    """A TYPED dependency from ``src`` to ``dst`` (COMP-003): control = ordering only; data = an
    artifact the downstream consumes (COMP-007); evidence = upstream evidence made available, which
    does NOT satisfy the downstream's admission (COMP-006)."""

    src: str
    dst: str
    type: str

    TYPES: ClassVar[frozenset[str]] = _EDGE_TYPES

    def __post_init__(self) -> None:
        if self.type not in _EDGE_TYPES:
            raise ValueError(f"edge type must be one of {sorted(_EDGE_TYPES)}")


@dataclass(slots=True)
class Composition:
    """A DAG of governed nodes + typed edges. Validated acyclic — a composition orders governed
    invocations, it does not permit a cyclic dependency."""

    nodes: list[CompositionNode]
    edges: list[CompositionEdge]
    id: str = field(default_factory=lambda: new_id("comp"))
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        ids = {n.id for n in self.nodes}
        for e in self.edges:
            if e.src not in ids or e.dst not in ids:
                raise ValueError(f"edge {e.src}->{e.dst} references an unknown node")
        if _has_cycle(ids, [(e.src, e.dst) for e in self.edges]):
            raise ValueError("composition graph must be acyclic")

    def node(self, node_id: str) -> CompositionNode:
        return next(n for n in self.nodes if n.id == node_id)

    def to_dict(self) -> JSON:
        return {"id": self.id, "created_at": self.created_at,
                "nodes": [asdict(n) for n in self.nodes],
                "edges": [asdict(e) for e in self.edges]}


def _has_cycle(node_ids: set[str], edges: list[tuple[str, str]]) -> bool:
    adj: dict[str, list[str]] = {}
    for a, b in edges:
        adj.setdefault(a, []).append(b)
    color: dict[str, int] = {}

    def dfs(n: str) -> bool:
        color[n] = 1
        for m in adj.get(n, []):
            if color.get(m, 0) == 1 or (color.get(m, 0) == 0 and dfs(m)):
                return True
        color[n] = 2
        return False

    return any(color.get(n, 0) == 0 and dfs(n) for n in node_ids)


def _edge_satisfied(edge: CompositionEdge, src_state: str, artifacts: set[str]) -> bool:
    """Whether one incoming edge is satisfied, BY TYPE. An evidence edge being satisfied makes the
    node schedulable — it is NOT the node's admission (COMP-006)."""
    if src_state != "completed":
        return False
    if edge.type == "data":
        return edge.src in artifacts        # the upstream artifact must be present (COMP-007)
    return True                             # control + evidence: upstream completed is enough to schedule


def classify(composition: Composition, states: dict[str, str], *,
             artifacts: set[str] | None = None) -> dict[str, str]:
    """Classify every node's readiness given the current per-node ``states`` and available
    ``artifacts``. Returns the full partial-completion snapshot (COMP-009): a node keeps its terminal
    state (completed/failed/indeterminate/compensated); a pending node becomes 'blocked' if a
    safety-critical dependency is indeterminate (COMP-010), 'ready' if its join condition over typed
    incoming edges is met, else stays 'pending'."""
    artifacts = artifacts or set()
    incoming: dict[str, list[CompositionEdge]] = {n.id: [] for n in composition.nodes}
    for e in composition.edges:
        incoming[e.dst].append(e)

    out: dict[str, str] = {}
    for node in composition.nodes:
        cur = states.get(node.id, "pending")
        if cur != "pending":
            out[node.id] = cur              # terminal / in-flight states are preserved
            continue
        deps = incoming[node.id]
        # COMP-010/008: a safety-critical node with an indeterminate dependency BLOCKS (never ready).
        if node.safety_critical and any(states.get(e.src) == "indeterminate" for e in deps):
            out[node.id] = "blocked"
            continue
        if not deps:
            out[node.id] = "ready"
            continue
        sat = [_edge_satisfied(e, states.get(e.src, "pending"), artifacts) for e in deps]
        met = all(sat) if node.join == "all" else any(sat)
        out[node.id] = "ready" if met else "pending"
    return out


def ready_nodes(composition: Composition, states: dict[str, str], *,
                artifacts: set[str] | None = None) -> list[str]:
    """The node ids eligible to be dispatched now (classify() == 'ready'). A ready node still runs
    through the full governed host pipeline — readiness schedules, it never admits (COMP-006)."""
    return [nid for nid, st in classify(composition, states, artifacts=artifacts).items() if st == "ready"]


def compensation_node(for_node: CompositionNode, *, capability: JSON) -> CompositionNode:
    """A compensation is a NEW governed node (COMP-011), never a rollback/undo. It is a fresh
    invocation that runs through the same host pipeline; the caller adds it to the composition with a
    control edge from the node being compensated."""
    return CompositionNode(id=new_id("cnode"), capability=capability)
