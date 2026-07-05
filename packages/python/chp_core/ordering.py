"""chp-causal-order-v1 — deterministic cross-host event ordering (chp-v0.2.md).

v0.1 §10 left cross-host ordering undefined; this defines it. Given the events
of ONE correlation gathered from N hosts, produce a single total order that is:

- **Causally consistent**: an event never precedes what caused it. Edges are
  (1) per-host `sequence` order and (2) the causal spawn edge — an event whose
  `correlation.causation_id` names invocation C is placed after C's first event.
- **Deterministic**: ties between causally-unrelated (concurrent) events break
  by the total sort key K(e) = (timestamp, host_id, sequence, event_id),
  compared byte-wise over UTF-8. Two implementations MUST produce identical
  output for the same event set — this is vector-tested
  (spec/test-vectors/ordering.json).

The tiebreak is arbitrary-but-deterministic: wall clocks skew, so K's timestamp
component is a heuristic for concurrent events, never for causally-related ones.
The function is TOTAL: on cyclic input (tampered/buggy data) the remainder is
emitted in K order — cycle *detection* is a verification concern (task bundles).
"""

from __future__ import annotations

import heapq
from typing import Any

JSON = dict[str, Any]


def _key(ev: JSON) -> tuple[str, str, int, str]:
    """K(e) — the total tiebreak order. Missing fields sort first ('' / 0)."""
    return (
        str(ev.get("timestamp") or ""),
        str(ev.get("host_id") or ""),
        int(ev.get("sequence") or 0),
        str(ev.get("event_id") or ""),
    )


def order_events(events: list[JSON]) -> list[JSON]:
    """Order one correlation's events per chp-causal-order-v1."""
    n = len(events)
    if n <= 1:
        return list(events)

    indexed = list(enumerate(events))

    # First event (K-minimal) of each invocation — the spawn-edge target.
    first_of_invocation: dict[str, int] = {}
    for i, ev in indexed:
        inv = ev.get("invocation_id")
        if not inv:
            continue
        j = first_of_invocation.get(inv)
        if j is None or _key(events[i]) < _key(events[j]):
            first_of_invocation[inv] = i

    # Build edges: successors + indegrees.
    succ: list[list[int]] = [[] for _ in range(n)]
    indeg = [0] * n

    def add_edge(a: int, b: int) -> None:
        succ[a].append(b)
        indeg[b] += 1

    # (1) Per-host sequence order (adjacent-chain edges suffice).
    by_host: dict[str, list[int]] = {}
    for i, ev in indexed:
        by_host.setdefault(str(ev.get("host_id") or ""), []).append(i)
    for idxs in by_host.values():
        idxs.sort(key=lambda i: (int(events[i].get("sequence") or 0), _key(events[i])))
        for a, b in zip(idxs, idxs[1:]):
            add_edge(a, b)

    # (2) Causal spawn: event with causation_id C follows C's first event.
    for i, ev in indexed:
        corr = ev.get("correlation") or {}
        caused_by = corr.get("causation_id") if isinstance(corr, dict) else None
        if caused_by:
            j = first_of_invocation.get(str(caused_by))
            if j is not None and j != i:
                add_edge(j, i)

    # Kahn's with a K-min-heap ready set → one deterministic total order.
    heap = [( _key(events[i]), i) for i in range(n) if indeg[i] == 0]
    heapq.heapify(heap)
    out: list[JSON] = []
    while heap:
        _, i = heapq.heappop(heap)
        out.append(events[i])
        for j in succ[i]:
            indeg[j] -= 1
            if indeg[j] == 0:
                heapq.heappush(heap, (_key(events[j]), j))

    if len(out) < n:  # cycle (tampered data): emit remainder in K order — total fn
        emitted = {id(e) for e in out}
        rest = [e for e in events if id(e) not in emitted]
        out.extend(sorted(rest, key=_key))
    return out
