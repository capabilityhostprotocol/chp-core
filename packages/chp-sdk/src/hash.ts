/**
 * Event content hashing + bundle root hash (spec/chp-v0.2.md §2).
 * The stable-field set and ordering match the Python reference exactly.
 */

import { createHash } from 'node:crypto';
import { canon, type JsonValue } from './canon.js';

export interface EvidenceEvent {
  event_id: string;
  event_type: string;
  invocation_id: string;
  capability_id: string;
  host_id: string;
  correlation?: { correlation_id?: string | null; [k: string]: JsonValue | undefined };
  timestamp: string;
  outcome?: string | null;
  payload?: JsonValue;
  content_hash?: string;
  prev_hash?: string | null;
  [k: string]: unknown;
}

const sha256hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

/** SHA-256 over the canonical stable fields of an event (+ prev_hash). */
export function contentHash(ev: EvidenceEvent, prevHash: string | null): string {
  const corr = ev.correlation ?? {};
  const stable: JsonValue = {
    event_id: ev.event_id,
    event_type: ev.event_type,
    invocation_id: ev.invocation_id,
    capability_id: ev.capability_id,
    host_id: ev.host_id,
    correlation_id: (typeof corr === 'object' && corr ? (corr.correlation_id ?? null) : null) as JsonValue,
    timestamp: ev.timestamp,
    outcome: ev.outcome ?? null,
    payload: ev.payload ?? {},
    prev_hash: prevHash ?? null,
  };
  return sha256hex(canon(stable));
}

/** Root hash = SHA-256 over each event's content_hash, each followed by "\n". */
export function rootHash(events: EvidenceEvent[]): string {
  const h = createHash('sha256');
  for (const ev of events) {
    h.update((ev.content_hash ?? '') + '\n');
  }
  return h.digest('hex');
}
