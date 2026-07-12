import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyBundle, auditCompleteness } from '../src/verify.js';
import { computeStoreHead, buildChainWitness, generateKeypair, COMPLETENESS_SCHEME } from '../src/signing.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8')) as Record<string, JsonValue>;

// Non-omission / completeness (§12, proposal 0018) — cross-verify the
// Python-signed vector + the witness-side audit, byte-parity with
// chp_core.witnessing.audit_completeness.
describe('completeness (chp-completeness-v1)', () => {
  it('verifies the Python-signed completeness bundle (claim in the signed header)', () => {
    const bundle = load('signed-bundle-complete.json');
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(true);
    expect(v.checks.completeness).toBe(true);
    expect(v.checks.signature).toBe(true);
    expect((bundle.completeness as Record<string, JsonValue>).scheme).toBe(COMPLETENESS_SCHEME);
  });

  it('rejects a completeness claim whose head_hash is not the tail', () => {
    const bundle = load('signed-bundle-complete.json');
    (bundle.completeness as Record<string, JsonValue>).head_hash = '0'.repeat(64);
    expect(verifyBundle(bundle).checks.completeness).toBe(false);
  });

  // Build a witnessed head over the bundle's correlation and audit against it.
  const bundle = load('signed-bundle-complete.json');
  const claim = bundle.completeness as Record<string, JsonValue>;
  const corr = String(claim.correlation_id);
  const asOf = Number(claim.as_of_sequence);
  const headHash = String(claim.head_hash);
  const wkey = generateKeypair();

  const receiptAt = (seq: number, leaf: string) => {
    const head = computeStoreHead({ [corr]: leaf }, seq);
    const statement = buildChainWitness('vector-host', seq, head.store_head, wkey, {
      witnessId: 'witness-1', witnessedAt: '2026-07-12T00:00:00Z',
    });
    return { statement, leaves: head.leaves } as unknown as Record<string, JsonValue>;
  };

  it('audits COMPLETE against a witnessed head whose leaf matches the tail', () => {
    const audit = auditCompleteness(bundle, [receiptAt(asOf, headHash)]);
    expect(audit.verdict).toBe('complete');
  });

  it('audits INCOMPLETE when a fresher witnessed head advanced the correlation', () => {
    // A later head where the correlation's tail moved past the claimed one.
    const audit = auditCompleteness(bundle, [receiptAt(asOf + 5, 'a'.repeat(64))]);
    expect(audit.verdict).toBe('incomplete');
  });

  it('audits UNWITNESSED when no head covers the claim', () => {
    expect(auditCompleteness(bundle, []).verdict).toBe('unwitnessed');
  });

  it('audits SNAPSHOT_INVALID when the leaves snapshot is tampered', () => {
    const r = receiptAt(asOf, headHash);
    (r.leaves as Record<string, string>)[corr] = 'f'.repeat(64); // no longer hashes to signed store_head
    expect(auditCompleteness(bundle, [r]).verdict).toBe('snapshot_invalid');
  });
});
