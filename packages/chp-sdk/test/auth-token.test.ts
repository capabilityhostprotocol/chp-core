import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyAuthToken, buildAuthToken, keypairFromSeed } from '../src/index.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

// Signed bearer tokens (§5, proposal 0027), byte-parity with Python chp_core.signing.
describe('auth-token', () => {
  it('verifies the Python-minted token (signature + attestation + audience + temporal)', () => {
    const t = load('auth-token.json') as Record<string, JsonValue>;
    const v = verifyAuthToken(t, { aud: String(t.aud), atTime: String(t.iat),
      expectedCallerKey: (t.caller as Record<string, JsonValue>).public_key as string });
    expect(v.valid).toBe(true);
    expect(v.checks.signature).toBe(true);
    expect(v.checks.caller_identity).toBe(true);
  });

  it('rejects a wrong audience, an unpinned key, and an expired token', () => {
    const t = load('auth-token.json') as Record<string, JsonValue>;
    expect(verifyAuthToken(t, { aud: 'other-host', atTime: String(t.iat) }).valid).toBe(false);
    expect(verifyAuthToken(t, { aud: String(t.aud), atTime: String(t.iat), expectedCallerKey: 'AAAA' }).valid).toBe(false);
    expect(verifyAuthToken(t, { aud: String(t.aud), atTime: '2099-01-01T00:00:00Z' }).valid).toBe(false);
  });

  it('a raised exp breaks the header signature', () => {
    const t = load('auth-token.json') as Record<string, JsonValue>;
    const bad = { ...t, exp: '2099-01-01T00:00:00Z' };
    expect(verifyAuthToken(bad, { aud: String(t.aud), atTime: String(t.iat) }).checks.signature).toBe(false);
  });

  it('TS-native round trip: mint then verify', () => {
    const key = keypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 7)));
    const tok = buildAuthToken(key, { sub: 'ts-caller', aud: 'ts-host',
      iat: '2026-07-12T00:00:00Z', exp: '2026-07-12T00:05:00Z' }) as Record<string, JsonValue>;
    const v = verifyAuthToken(tok, { aud: 'ts-host', atTime: '2026-07-12T00:01:00Z',
      expectedCallerKey: key.publicKeyB64 });
    expect(v.valid).toBe(true);
  });
});
