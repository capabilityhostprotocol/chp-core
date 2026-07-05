/**
 * In-memory append-only, SHA256-chained evidence store. The backend is
 * non-normative (spec/chp-v0.2.md) — an array is enough for a conformance host.
 * Chaining matches the Python reference: prev_hash links to the last event with
 * the SAME correlation_id; a global sequence orders the store.
 */

import { contentHash, verifyChain, type EvidenceEvent, type ChainResult } from '@capabilityhostprotocol/sdk';

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
}
