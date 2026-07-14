import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyRekorAnchor } from '../src/index.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

// Rekor transparency-log anchor (§12, proposal 0033), byte-compatible with the
// Python chp_core.rekor verifier: the SDK verifies the Python-produced anchor
// OFFLINE against the log's pinned public key.
describe('verifyRekorAnchor', () => {
  const vec = load('rekor-anchor.json');
  const anchor = vec.anchor as Record<string, JsonValue>;
  const pem = vec.log_public_key_pem as string;

  it('verifies the Python-produced rekor anchor offline (4 checks pass)', () => {
    const v = verifyRekorAnchor(anchor, pem);
    expect(v.valid).toBe(true);
    expect(v.checks).toEqual({
      structure: true, inclusion: true, set: true, entry_binds_dsse: true, root: true,
    });
  });

  it('a wrong log key fails the SET', () => {
    // a syntactically-valid but unrelated P-256 key
    const other = load('rekor-anchor.json');  // reuse structure; swap in a bad key below
    void other;
    const bogus = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmock' +
      'mockmockmockmockmockmockmockmockmockmockmockmockmockmockmockmockmockmockmock==\n-----END PUBLIC KEY-----\n';
    expect(verifyRekorAnchor(anchor, bogus).checks.set).toBe(false);
  });

  it('a tampered store_head breaks the root binding', () => {
    const bad = JSON.parse(JSON.stringify(vec.anchor)) as Record<string, JsonValue>;
    bad.store_head = 'f'.repeat(64);
    expect(verifyRekorAnchor(bad, pem).checks.root).toBe(false);
  });

  it('a tampered inclusion hash breaks inclusion', () => {
    const bad = JSON.parse(JSON.stringify(vec.anchor)) as Record<string, JsonValue>;
    (bad.anchor as Record<string, JsonValue>).inclusion_hashes = ['0'.repeat(64)];
    expect(verifyRekorAnchor(bad, pem).checks.inclusion).toBe(false);
  });
});
