import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { contentHash, type EvidenceEvent } from '../src/hash.js';
import { verifyBundle } from '../src/verify.js';
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
});
