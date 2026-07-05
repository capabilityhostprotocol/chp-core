/**
 * Hash-chain verification: recompute each event's content_hash and confirm the
 * prev_hash links form an unbroken chain (spec/chp-v0.2.md §2).
 */

import { contentHash, rootHash, type EvidenceEvent } from './hash.js';

export interface ChainResult {
  valid: boolean;
  eventHashesOk: boolean;
  rootOk: boolean;
  firstBrokenSequence: number | null;
}

/** Verify per-event hashes + chain continuity; optionally check a claimed root. */
export function verifyChain(events: EvidenceEvent[], expectedRoot?: string): ChainResult {
  let prev: string | null = null;
  let eventHashesOk = true;
  let firstBroken: number | null = null;

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    const storedHash = ev.content_hash ?? null;
    const storedPrev = ev.prev_hash ?? null;
    if (storedHash === null) {
      eventHashesOk = false;
      firstBroken = i;
      break;
    }
    if (contentHash(ev, storedPrev) !== storedHash || storedPrev !== prev) {
      eventHashesOk = false;
      firstBroken = i;
      break;
    }
    prev = storedHash;
  }

  const rootOk = expectedRoot === undefined ? true : rootHash(events) === expectedRoot;
  return { valid: eventHashesOk && rootOk, eventHashesOk, rootOk, firstBrokenSequence: firstBroken };
}
