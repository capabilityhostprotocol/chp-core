/**
 * chp-causal-order-v1 — deterministic cross-host event ordering (chp-v0.2.md).
 * TS twin of chp_core/ordering.py; both MUST produce identical output for the
 * same event set (vector-tested against spec/test-vectors/ordering.json).
 *
 * Edges: per-host `sequence` order + causal spawn (causation_id → after the
 * caused invocation's first event). Kahn's topological sort; concurrent ties
 * break by K(e) = (timestamp, host_id, sequence, event_id) compared byte-wise
 * over UTF-8 (case-SENSITIVE — a locale/case-insensitive comparator diverges).
 * Total function: cyclic remainders (tampered data) are emitted in K order.
 */

import type { EvidenceEvent } from './hash.js';

type Key = [string, string, number, string];

function key(ev: EvidenceEvent): Key {
  return [
    String(ev.timestamp ?? ''),
    String(ev.host_id ?? ''),
    Number(ev.sequence ?? 0),
    String(ev.event_id ?? ''),
  ];
}

/** Byte-wise UTF-8 comparison for the string components (NOT localeCompare). */
function cmpStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0; // JS <,> on strings is code-unit order — matches
}

function cmpKey(a: Key, b: Key): number {
  return cmpStr(a[0], b[0]) || cmpStr(a[1], b[1]) || (a[2] - b[2]) || cmpStr(a[3], b[3]);
}

export function orderEvents(events: EvidenceEvent[]): EvidenceEvent[] {
  const n = events.length;
  if (n <= 1) return [...events];

  // First (K-minimal) event of each invocation — the spawn-edge target.
  const firstOfInvocation = new Map<string, number>();
  events.forEach((ev, i) => {
    const inv = ev.invocation_id;
    if (!inv) return;
    const j = firstOfInvocation.get(inv);
    if (j === undefined || cmpKey(key(ev), key(events[j])) < 0) firstOfInvocation.set(inv, i);
  });

  const succ: number[][] = Array.from({ length: n }, () => []);
  const indeg = new Array<number>(n).fill(0);
  const addEdge = (a: number, b: number): void => {
    succ[a].push(b);
    indeg[b] += 1;
  };

  // (1) Per-host sequence order (adjacent-chain edges).
  const byHost = new Map<string, number[]>();
  events.forEach((ev, i) => {
    const h = String(ev.host_id ?? '');
    if (!byHost.has(h)) byHost.set(h, []);
    byHost.get(h)!.push(i);
  });
  for (const idxs of byHost.values()) {
    idxs.sort((a, b) => (Number(events[a].sequence ?? 0) - Number(events[b].sequence ?? 0))
      || cmpKey(key(events[a]), key(events[b])));
    for (let k = 0; k + 1 < idxs.length; k++) addEdge(idxs[k], idxs[k + 1]);
  }

  // (2) Causal spawn edges.
  events.forEach((ev, i) => {
    const corr = ev.correlation as { causation_id?: string | null } | undefined;
    const causedBy = corr?.causation_id;
    if (causedBy) {
      const j = firstOfInvocation.get(String(causedBy));
      if (j !== undefined && j !== i) addEdge(j, i);
    }
  });

  // Kahn's with a K-ordered ready set.
  // ponytail: O(n²) min-extract over the ready array; heap if correlations exceed ~10k events.
  const ready: number[] = [];
  for (let i = 0; i < n; i++) if (indeg[i] === 0) ready.push(i);
  const out: EvidenceEvent[] = [];
  const emitted = new Set<number>();
  while (ready.length > 0) {
    let best = 0;
    for (let k = 1; k < ready.length; k++) {
      if (cmpKey(key(events[ready[k]]), key(events[ready[best]])) < 0) best = k;
    }
    const i = ready.splice(best, 1)[0];
    out.push(events[i]);
    emitted.add(i);
    for (const j of succ[i]) {
      indeg[j] -= 1;
      if (indeg[j] === 0) ready.push(j);
    }
  }

  if (out.length < n) {
    // cycle (tampered data): emit remainder in K order — total function.
    const rest: number[] = [];
    for (let i = 0; i < n; i++) if (!emitted.has(i)) rest.push(i);
    rest.sort((a, b) => cmpKey(key(events[a]), key(events[b])));
    for (const i of rest) out.push(events[i]);
  }
  return out;
}
