import { describe, it, expect } from 'vitest';
import {
  buildContinuityStatement,
  buildMandate,
  buildProvenanceStatement,
  keypairFromSeed,
  verifyContinuity,
  verifyMandate,
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
