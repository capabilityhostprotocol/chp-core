import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  verifyAttestation, verifyDsse, dsseStatement, attestationToBundle,
  bundleToAttestation, IN_TOTO_PAYLOAD_TYPE,
} from '../src/dsse.js';
import { keypairFromSeed } from '../src/signing.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));
const CHP_SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i)); // bytes(range(32))

// in-toto / DSSE attestation bridge (§15, proposal 0021), byte-parity with Python.
describe('dsse in-toto attestation', () => {
  it('verifies the Python-generated attestation vector (DSSE sig + embedded bundle)', () => {
    const env = load('dsse-attestation.json');
    const v = verifyAttestation(env);
    expect(v.valid).toBe(true);
    expect(v.checks).toEqual({ dsse_signature: true, statement_type: true, subject_digest: true, bundle: true });
  });

  it('the embedded bundle round-trips and verifies', () => {
    const env = load('dsse-attestation.json');
    const stmt = dsseStatement(env);
    expect(stmt._type).toBe('https://in-toto.io/Statement/v1');
    expect(stmt.predicateType).toBe('https://chp.dev/attestation/evidence-bundle/v1');
    const bundle = attestationToBundle(env);
    expect((stmt.subject as Array<Record<string, JsonValue>>)[0].digest).toEqual({ sha256: bundle.root_hash });
  });

  it('rebuilds byte-identically from the same seed key (cross-impl determinism)', () => {
    // The vector was signed by keypairFromSeed(bytes(range(32))) over the embedded
    // bundle — rebuild in TS and expect the SAME payload + signature.
    const env = load('dsse-attestation.json');
    const bundle = attestationToBundle(env);
    const key = keypairFromSeed(CHP_SEED);
    const rebuilt = bundleToAttestation(bundle, key);
    expect(rebuilt.payload).toBe(env.payload);            // identical Statement bytes (PAE body)
    expect(rebuilt.payloadType).toBe(IN_TOTO_PAYLOAD_TYPE);
    expect(rebuilt.signatures[0].sig).toBe(env.signatures[0].sig); // identical ed25519(PAE)
    expect(rebuilt.signatures[0].keyid).toBe(env.signatures[0].keyid);
  });

  it('a forged tail fails the DSSE signature', () => {
    const env = load('dsse-attestation.json');
    const bundle = attestationToBundle(env);
    // relabel the subject digest, re-encode payload WITHOUT re-signing → PAE no longer matches
    const stmt = dsseStatement(env);
    (stmt.subject as Array<Record<string, JsonValue>>)[0].digest = { sha256: '0'.repeat(64) };
    const bad = { ...env, payload: Buffer.from(JSON.stringify(stmt)).toString('base64') };
    expect(verifyDsse(bad, String(bundle.public_key))).toBe(false);
    expect(verifyAttestation(bad).valid).toBe(false);
  });
});
