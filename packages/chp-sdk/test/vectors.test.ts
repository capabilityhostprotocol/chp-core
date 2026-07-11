import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { contentHash, payloadCommitment, EVENT_HASH_V2, type EvidenceEvent } from '../src/hash.js';
import { verifyBundle } from '../src/verify.js';
import { withholdPayloads } from '../src/signing.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

describe('published test vectors', () => {
  it('recomputes the single-event content_hash', () => {
    const expected = load('expected.json');
    const ev = load('event.json').event as EvidenceEvent;
    expect(contentHash(ev, null)).toBe(expected.event_content_hash);
  });

  it('verifies the Python-signed echo bundle', () => {
    const bundle = load('signed-bundle.json') as Record<string, JsonValue>;
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(true);
    expect(v.checks.signature).toBe(true);
    expect(v.checks.host_identity).toBe(true);
  });

  it('verifies the Python-signed GOVERNED bundle (string-encoded score)', () => {
    const bundle = load('governance-bundle.json') as Record<string, JsonValue>;
    expect(verifyBundle(bundle).valid).toBe(true);
  });

  it('rejects a tampered event payload', () => {
    const bundle = load('signed-bundle.json') as Record<string, JsonValue>;
    (bundle.events as EvidenceEvent[])[0].payload = { note: 'TAMPERED' };
    expect(verifyBundle(bundle).valid).toBe(false);
  });

  it('rejects a relabelled host_id', () => {
    const bundle = load('signed-bundle.json') as Record<string, JsonValue>;
    bundle.host_id = 'prod-gateway-acme';
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(false);
    expect(v.checks.signature).toBe(false);
  });

  // Selective disclosure (§14, proposal 0011) — cross-verify the Python-signed vectors.
  it('recomputes the chp-event-hash-v2 content_hash + commitment', () => {
    const v = load('event-hash-v2.json');
    const ev = v.event as EvidenceEvent;
    expect(ev.hash_scheme).toBe(EVENT_HASH_V2);
    expect(payloadCommitment(ev.payload)).toBe(v.payload_commitment);
    expect(contentHash(ev, v.prev_hash ?? null)).toBe(v.content_hash);
  });

  it('verifies the Python-signed WITHHELD bundle (withheld ok, disclosed bound)', () => {
    const bundle = load('bundle-withheld.json') as Record<string, JsonValue>;
    const events = bundle.events as EvidenceEvent[];
    expect(events[0].payload).toEqual({ chp_withheld: true });   // withheld
    expect(events[1].payload).not.toEqual({ chp_withheld: true }); // disclosed
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(true);
    expect(v.checks.payload_commitments).toBe(true);
    expect(v.checks.event_hashes).toBe(true);
    expect(v.checks.signature).toBe(true);
  });

  it('rejects a tampered DISCLOSED payload in the withheld bundle', () => {
    const bundle = load('bundle-withheld.json') as Record<string, JsonValue>;
    (bundle.events as EvidenceEvent[])[1].payload = { forged: true };
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(false);
    expect(v.checks.payload_commitments).toBe(false);
    expect(v.checks.event_hashes).toBe(true); // hash binds the commitment, not the payload
  });

  it('withholdPayloads keeps the signature valid (TS-native round trip)', () => {
    const bundle = load('bundle-withheld.json') as Record<string, JsonValue>;
    const rootBefore = bundle.root_hash;
    const minimized = withholdPayloads(bundle); // withhold every v2 payload
    expect((minimized.events as EvidenceEvent[]).every((e) => (e.payload as Record<string, unknown>).chp_withheld === true)).toBe(true);
    expect(minimized.root_hash).toBe(rootBefore);
    expect(minimized.signature).toEqual(bundle.signature);
    expect(verifyBundle(minimized).valid).toBe(true);
  });
});
