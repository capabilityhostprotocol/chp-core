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
  hash_scheme?: string;
  payload_commitment?: string;
  content_hash?: string;
  prev_hash?: string | null;
  [k: string]: unknown;
}

/** Per-event content-hash scheme names (spec/chp-v0.2.md §2/§14). */
export const EVENT_HASH_V2 = 'chp-event-hash-v2';

const sha256hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

/** chp-event-hash-v2 payload commitment = sha256(chp-stable-v1(payload)). Empty payload = {}. */
export function payloadCommitment(payload: JsonValue | undefined): string {
  return sha256hex(canon(payload ?? {}));
}

/** SHA-256 over the canonical stable fields of an event (+ prev_hash). Under
 * chp-event-hash-v2 (§14) the payload is replaced by its commitment, so the
 * payload can be withheld from a bundle without moving the hash. */
export function contentHash(ev: EvidenceEvent, prevHash: string | null): string {
  const corr = ev.correlation ?? {};
  const stable: Record<string, JsonValue> = {
    event_id: ev.event_id,
    event_type: ev.event_type,
    invocation_id: ev.invocation_id,
    capability_id: ev.capability_id,
    host_id: ev.host_id,
    correlation_id: (typeof corr === 'object' && corr ? (corr.correlation_id ?? null) : null) as JsonValue,
    timestamp: ev.timestamp,
    outcome: ev.outcome ?? null,
    prev_hash: prevHash ?? null,
  };
  if (ev.hash_scheme === EVENT_HASH_V2) {
    stable.payload_commitment = ev.payload_commitment ?? payloadCommitment(ev.payload);
  } else {
    stable.payload = ev.payload ?? {};
  }
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
