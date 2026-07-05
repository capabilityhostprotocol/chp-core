import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { keypairFromSeed, buildBundle, signBundle } from '../src/signing.js';
import { verifyBundle } from '../src/verify.js';
import type { EvidenceEvent } from '../src/hash.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

// The published vectors were signed with this exact seed (bytes 0..31).
const SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i));

describe('cross-language interop (TS ↔ Python)', () => {
  it('derives the same public key + key_id as Python', () => {
    const expected = load('expected.json');
    const key = keypairFromSeed(SEED);
    expect(key.publicKeyB64).toBe(expected.public_key_b64);
    expect(key.keyId).toBe(load('signed-bundle.json').signature.key_id);
  });

  it('produces a byte-identical signature to the Python-signed bundle', () => {
    const original = load('signed-bundle.json') as Record<string, JsonValue>;
    const key = keypairFromSeed(SEED);
    const rebuilt = signBundle(
      buildBundle(
        original.host_id as string,
        original.events as EvidenceEvent[],
        original.created_at as string,
        original.protocol_version as string,
      ),
      key,
    );
    // Same header signature AND same self-attestation signature as Python.
    expect((rebuilt.signature as { signature: string }).signature).toBe(
      (original.signature as { signature: string }).signature,
    );
    expect((rebuilt.host_identity as { signature: string }).signature).toBe(
      (original.host_identity as { signature: string }).signature,
    );
  });

  it('round-trips a freshly TS-signed bundle', () => {
    const key = keypairFromSeed(SEED);
    const events = load('signed-bundle.json').events as EvidenceEvent[];
    const signed = signBundle(buildBundle('ts-host', events, '2026-07-05T00:00:00Z'), key);
    expect(verifyBundle(signed).valid).toBe(true);
    expect(verifyBundle(signed, { expectedKeyId: key.keyId }).valid).toBe(true);
    expect(verifyBundle(signed, { expectedKeyId: 'deadbeefdeadbeef' }).valid).toBe(false);
  });
});
