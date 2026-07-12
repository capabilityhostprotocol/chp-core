import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  storeHeadRoot, storeHeadConsistencyProof, CHP_STORE_HEAD_V2,
  monitorAnchorHistoryRemote,
} from '../src/index.js';
import type { JsonValue } from '../src/canon.js';

// Remote log monitor (§12, proposal 0024): a monitor holding only the anchors
// verifies append-only via served consistency proofs — no store copy. Byte-parity
// with Python witnessing.monitor_anchor_history_remote.

// A growing v2 store head: leaves accumulate; each anchor captures the head after
// one more correlation. `served(leaves)` emulates GET /head/consistency.
function growingLog() {
  const all: Record<string, string> = {};
  const snapshots: Record<string, string>[] = [];
  const anchors: Array<Record<string, JsonValue>> = [];
  for (let i = 0; i < 4; i++) {
    all[`c-${i}`] = createHash('sha256').update(`tail-${i}`).digest('hex');
    const snap = { ...all };
    snapshots.push(snap);
    anchors.push({
      kind: 'store-head-anchor', host_id: 'h', sequence: i + 1,
      store_head: storeHeadRoot(CHP_STORE_HEAD_V2, snap), store_head_scheme: CHP_STORE_HEAD_V2,
    });
  }
  // fetchProof(s1, s2) → consistency proof between the two snapshots (1-indexed seqs)
  const fetch = async (s1: number, s2: number) =>
    storeHeadConsistencyProof(snapshots[s1 - 1], snapshots[s2 - 1]) as unknown as Record<string, JsonValue>;
  return { snapshots, anchors, fetch };
}

describe('remote monitor (no store copy)', () => {
  it('a faithful log verifies append-only from served proofs alone', async () => {
    const { anchors, fetch } = growingLog();
    const v = await monitorAnchorHistoryRemote(anchors, fetch);
    expect(v.verdict).toBe('consistent');
    expect(v.verified_through_sequence).toBe(4);
    expect(v.divergence).toBeUndefined();
  });

  it('a rewrite is caught: a served proof whose root ≠ the immutable anchor', async () => {
    const { snapshots, anchors, fetch } = growingLog();
    // The operator rewrites an old leaf; the snapshot the host now serves for seq 2
    // reconstructs a different root than the immutable anchor at seq 2.
    snapshots[1] = { ...snapshots[1], 'c-0': 'd'.repeat(64) };
    for (let i = 2; i < snapshots.length; i++) snapshots[i] = { ...snapshots[i], 'c-0': 'd'.repeat(64) };
    const v = await monitorAnchorHistoryRemote(anchors, fetch);
    expect(v.verdict).toBe('forked');
    expect(v.divergence?.anchored_root).toBe(anchors[1].store_head);
    expect(v.divergence?.reconstructed_root).not.toBe(anchors[1].store_head);
  });

  it('an unreachable host is unprovable → forked, not consistent', async () => {
    const { anchors } = growingLog();
    const v = await monitorAnchorHistoryRemote(anchors, async () => null);
    expect(v.verdict).toBe('forked');
  });

  it('refuses v1 anchors rather than falsely accusing', async () => {
    const { anchors, fetch } = growingLog();
    const v1 = anchors.map((a) => ({ ...a, store_head_scheme: 'chp-store-head-v1' }));
    await expect(monitorAnchorHistoryRemote(v1, fetch)).rejects.toThrow('chp-store-head-v2');
  });
});
