import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  verifyBundle, sealPayloads, unsealBundle, unsealPayload, generateEncKeypair,
} from '../src/index.js';
import { payloadCommitment } from '../src/hash.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

// Sealed payloads (§16, proposal 0025), byte-compatible with Python chp_core.sealing.
describe('sealed payloads', () => {
  const vec = load('sealed-bundle.json');
  const recipientPriv = Buffer.from(vec.recipient_enc_private, 'base64');

  it('a third party verifies the Python-sealed bundle with NO key', () => {
    const v = verifyBundle(vec.bundle as Record<string, JsonValue>);
    expect(v.valid).toBe(true);
    expect(v.checks.payload_commitments).toBe(true);
    // the sealed payload is only the marker — plaintext gone
    const sealed = (vec.bundle.events as Array<Record<string, JsonValue>>)
      .filter((e) => (e.payload as Record<string, unknown>)?.chp_sealed);
    expect(sealed.length).toBeGreaterThan(0);
  });

  it('the recipient unseals the Python ciphertext (cross-impl ECDH+HKDF+ChaCha20)', () => {
    const opened = unsealBundle(vec.bundle as Record<string, JsonValue>, recipientPriv);
    for (const ev of opened.events as Array<Record<string, JsonValue>>) {
      if (ev.hash_scheme === 'chp-event-hash-v2' && ev.payload_commitment) {
        expect(payloadCommitment(ev.payload)).toBe(ev.payload_commitment);
      }
    }
    // and the unsealed bundle still verifies
    expect(verifyBundle(opened).valid).toBe(true);
  });

  it('a wrong key fails the AEAD tag', () => {
    const wrong = generateEncKeypair().privateRaw;
    expect(() => unsealBundle(vec.bundle as Record<string, JsonValue>, wrong)).toThrow();
  });

  it('TS-native round trip: seal then unseal recovers the original', () => {
    // build a fresh signed-bundle-like structure from a real vector
    const src = load('signed-bundle.json') as Record<string, JsonValue>;
    const { privateRaw, publicB64 } = generateEncKeypair();
    const sealed = sealPayloads(src, publicB64);
    expect(verifyBundle(sealed).valid).toBe(true);          // seals still verify
    const opened = unsealBundle(sealed, privateRaw);
    expect(opened).toEqual(src);                            // exact round trip
  });
});

// chp-sealed-v2 — multi-recipient envelope encryption (proposal 0030).
describe('sealed payloads v2 (multi-recipient)', () => {
  const vec = load('sealed-bundle-v2.json');

  it('ANY of the 3 recipients unseals the Python v2 ciphertext; the bundle verifies keyless', () => {
    expect(verifyBundle(vec.bundle as Record<string, JsonValue>).valid).toBe(true);
    for (const privB64 of vec.recipient_enc_privates as string[]) {
      const opened = unsealBundle(vec.bundle as Record<string, JsonValue>, Buffer.from(privB64, 'base64'));
      for (const ev of opened.events as Array<Record<string, JsonValue>>) {
        if (ev.hash_scheme === 'chp-event-hash-v2' && ev.payload_commitment) {
          expect(payloadCommitment(ev.payload)).toBe(ev.payload_commitment);
        }
      }
    }
  });

  it('an outsider key cannot unseal', () => {
    const outsider = generateEncKeypair().privateRaw;
    expect(() => unsealBundle(vec.bundle as Record<string, JsonValue>, outsider)).toThrow();
  });

  it('TS-native v2 round trip: seal to 2 keys, either unseals', () => {
    const src = load('signed-bundle.json') as Record<string, JsonValue>;
    const a = generateEncKeypair(), b = generateEncKeypair();
    const sealed = sealPayloads(src, [a.publicB64, b.publicB64]);
    expect(verifyBundle(sealed).valid).toBe(true);
    expect(unsealBundle(sealed, a.privateRaw)).toEqual(src);
    expect(unsealBundle(sealed, b.privateRaw)).toEqual(src);
  });
});
