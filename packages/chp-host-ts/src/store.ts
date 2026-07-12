/**
 * In-memory append-only, SHA256-chained evidence store. The backend is
 * non-normative (spec/chp-v0.2.md) — an array is enough for a conformance host.
 * Chaining matches the Python reference: prev_hash links to the last event with
 * the SAME correlation_id; a global sequence orders the store.
 */

import { computeStoreHead, contentHash, verifyChain, type EvidenceEvent, type ChainResult, type StoreHead } from '@capabilityhostprotocol/sdk';

export class InMemoryEvidenceStore {
  private events: EvidenceEvent[] = [];
  private seq = 0;

  append(ev: EvidenceEvent): EvidenceEvent {
    this.seq += 1;
    const corr = ev.correlation?.correlation_id ?? null;
    let prev: string | null = null;
    for (let i = this.events.length - 1; i >= 0; i--) {
      if ((this.events[i].correlation?.correlation_id ?? null) === corr) {
        prev = this.events[i].content_hash ?? null;
        break;
      }
    }
    ev.sequence = this.seq;
    ev.content_hash = contentHash(ev, prev);
    ev.prev_hash = prev;
    this.events.push(ev);
    return ev;
  }

  byCorrelation(correlationId: string): EvidenceEvent[] {
    return this.events.filter((e) => (e.correlation?.correlation_id ?? null) === correlationId);
  }

  countEventType(correlationId: string, eventType: string): number {
    return this.byCorrelation(correlationId).filter((e) => e.event_type === eventType).length;
  }

  verifyChainFor(correlationId: string): ChainResult {
    return verifyChain(this.byCorrelation(correlationId));
  }

  /** The witnessable store digest (chp-store-head-v1, spec §12): per-correlation
   * head content_hash at sequence ≤ N, digested over sorted leaves. */
  getStoreHead(atSequence?: number, scheme?: string): StoreHead {
    const n = atSequence ?? this.seq;
    const leaves = new Map<string, string | null>();
    for (const e of this.events) {
      if (Number(e.sequence ?? 0) <= n) {
        leaves.set(String(e.correlation?.correlation_id ?? ''), e.content_hash ?? null);
      }
    }
    return computeStoreHead(leaves, n, scheme);
  }
}
