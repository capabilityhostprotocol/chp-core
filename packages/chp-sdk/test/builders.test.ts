import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  buildChainWitness,
  buildContinuityStatement,
  buildMandate,
  buildMandateRevocation,
  buildProvenanceStatement,
  computeStoreHead,
  keypairFromSeed,
  verifyChainWitness,
  verifyContinuity,
  verifyMandate,
  verifyMandateRevocation,
  verifyProvenanceStatement,
} from '../src/index.js';

const key = keypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 11)));
const TS = '2026-01-01T00:00:00Z';

describe('statement builders — TS build parity (round-trip under own verifiers)', () => {
  it('buildMandate → verifyMandate valid; scope sorted before signing', () => {
    const m = buildMandate('principal-b', key, {
      delegateId: 'agent-z', scope: ['z.last', 'a.first'],
      validFrom: TS, validUntil: '2027-01-01T00:00:00Z', createdAt: TS,
      mandateId: 'mnd_builder_test',
    });
    expect(m.scope).toEqual(['a.first', 'z.last']);
    expect((m.principal as Record<string, unknown>).key_history).toBeUndefined();
    const v = verifyMandate(m, { atTime: TS, capabilityId: 'a.first', delegateId: 'agent-z' });
    expect(v.valid).toBe(true);
  });

  it('buildMandateRevocation → verifyMandateRevocation; revokes under verifyMandate', () => {
    const m = buildMandate('principal-b', key, {
      delegateId: 'agent-z', scope: ['a.first'],
      validFrom: TS, validUntil: '2027-01-01T00:00:00Z', createdAt: TS,
      mandateId: 'mnd_revoke_test',
    });
    const rev = buildMandateRevocation(m, key, { revokedAt: TS, reason: 'test' });
    expect(verifyMandateRevocation(rev).valid).toBe(true);
    const revoked = verifyMandate(m, { atTime: TS, revocations: [rev] });
    expect(revoked.valid).toBe(false);
    expect(revoked.checks.not_revoked).toBe(false);
    expect(verifyMandate(m, { atTime: TS, revocations: [] }).valid).toBe(true);
  });

  it('a revocation signed by a non-issuer key is INERT (issuer-only rule)', () => {
    const m = buildMandate('principal-b', key, {
      delegateId: 'agent-z', scope: ['a.first'],
      validFrom: TS, validUntil: '2027-01-01T00:00:00Z', createdAt: TS,
      mandateId: 'mnd_forge_test',
    });
    const attacker = keypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 77)));
    // buildMandateRevocation itself refuses a non-issuer key...
    expect(() => buildMandateRevocation(m, attacker, { revokedAt: TS })).toThrow(/issuer/);
    // ...so forge via an impostor mandate naming the same id: self-consistent
    // but inert against the real mandate (key mismatch at verification).
    const impostor = buildMandate('principal-b', attacker, {
      delegateId: 'agent-z', scope: ['a.first'],
      validFrom: TS, validUntil: '2027-01-01T00:00:00Z', createdAt: TS,
      mandateId: 'mnd_forge_test',
    });
    const forged = buildMandateRevocation(impostor, attacker, { revokedAt: TS });
    expect(verifyMandateRevocation(forged).valid).toBe(true);
    const v = verifyMandate(m, { atTime: TS, revocations: [forged] });
    expect(v.valid).toBe(true);
    expect(v.checks.not_revoked).toBe(true);
  });

  it('cross-verifies the Python-signed mandate-revocation vector pair', () => {
    const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
    const mandate = JSON.parse(readFileSync(dir + 'mandate.json', 'utf8'));
    const rev = JSON.parse(readFileSync(dir + 'mandate-revocation.json', 'utf8'));
    expect(verifyMandateRevocation(rev).valid).toBe(true);
    const revoked = verifyMandate(mandate, { atTime: TS, revocations: [rev] });
    expect(revoked.checks.not_revoked).toBe(false);
  });

  it('tampered mandate fails its own verifier', () => {
    const m = buildMandate('principal-b', key, {
      delegateId: 'agent-z', scope: ['a.first'],
      validFrom: TS, validUntil: '2027-01-01T00:00:00Z', createdAt: TS,
    });
    m.delegate_id = 'someone-else';
    expect(verifyMandate(m).checks.signature).toBe(false);
  });

  it('buildProvenanceStatement → verifyProvenanceStatement valid incl. artifact hash', () => {
    const sha = 'ab'.repeat(32);
    const stmt = buildProvenanceStatement('chp-adapter-x', '1.2.3', sha, key, {
      publisherId: 'acme-release', createdAt: TS,
    });
    expect((stmt.publisher as Record<string, unknown>).key_history).toBeUndefined();
    const v = verifyProvenanceStatement(stmt, { wheelSha256: sha });
    expect(v.valid).toBe(true);
    const bad = verifyProvenanceStatement({ ...stmt, version: '9.9.9' });
    expect(bad.checks.signature).toBe(false);
  });

  it('buildContinuityStatement → verifyContinuity; tampered new key fails', () => {
    const newKey = keypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 99)));
    const stmt = buildContinuityStatement(key, newKey, TS);
    expect(verifyContinuity(stmt)).toBe(true);
    expect(verifyContinuity({ ...stmt, new_key_id: 'deadbeef' })).toBe(false);
    expect(verifyContinuity({ ...stmt, old_public_key: newKey.publicKeyB64 })).toBe(false);
  });
});

describe('chain witnessing (§12)', () => {
  it('buildChainWitness → verifyChainWitness valid; tamper breaks it', () => {
    const stmt = buildChainWitness('audited-host', 42, 'ab'.repeat(32), key, {
      witnessId: 'peer-w', witnessedAt: TS,
    });
    const v = verifyChainWitness(stmt, { expectedHostId: 'audited-host' });
    expect(v.valid).toBe(true);
    expect(verifyChainWitness({ ...stmt, store_head: 'cd'.repeat(32) }).checks.signature).toBe(false);
    expect(verifyChainWitness(stmt, { expectedHostId: 'someone-else' }).valid).toBe(false);
  });

  it('computeStoreHead matches the Python-generated vector scheme', () => {
    // The vector's head is computed over these exact fixture leaves in
    // scripts/gen-test-vectors.py — cross-language head-scheme parity.
    const alpha = createHash('sha256').update('chp fixture head alpha v1').digest('hex');
    const beta = createHash('sha256').update('chp fixture head beta v1').digest('hex');
    const head = computeStoreHead({ corr_alpha: alpha, corr_beta: beta }, 42);
    const vector = JSON.parse(readFileSync(
      fileURLToPath(new URL('../../../spec/test-vectors/chain-witness.json', import.meta.url)),
      'utf8'));
    expect(head.store_head).toBe(vector.store_head);
  });

  it('vector verifies under verifyChainWitness', () => {
    const vector = JSON.parse(readFileSync(
      fileURLToPath(new URL('../../../spec/test-vectors/chain-witness.json', import.meta.url)),
      'utf8'));
    expect(verifyChainWitness(vector, { expectedHostId: 'vector-witnessed-host' }).valid).toBe(true);
  });
});
