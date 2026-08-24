/**
 * Dual-digest consistency (CHP-CORE-026) — the machine-contract teeth beyond schema shape, verified by the
 * SECOND implementation. A collapsed pair (action === invocation) and a swapped-routing tamper both pass a
 * shape schema but are rejected here; a genuine derived pair is accepted. Twin of chp_core's
 * dual_digest_consistent — same canonicalization, so the two implementations agree.
 */
import { describe, it, expect } from 'vitest';
import { actionDigest, invocationDocument, documentDigest, dualDigestConsistent } from '../src/digests.js';

describe('dualDigestConsistent — CORE-026 machine-contract teeth', () => {
  const ad = actionDigest({ capability: { id: 'svc.x' }, principal: { id: 'p' }, actionInput: { n: 1 } });
  const doc = invocationDocument({
    invocationId: 'i', actionDigest: ad, actor: { id: 'a' }, principal: { id: 'p' },
    binding: { id: 'b1' }, provider: { id: 'prov' }, host: { id: 'h' },
  });
  const idig = documentDigest(doc);

  it('accepts a genuine derived pair, with and without the document', () => {
    expect(dualDigestConsistent(ad, idig, doc)).toBe(true);
    expect(dualDigestConsistent(ad, idig)).toBe(true);
  });

  it('rejects a collapsed pair (action === invocation) the shape schema would miss', () => {
    expect(dualDigestConsistent(ad, ad)).toBe(false);
  });

  it('rejects swapped routing and a mismatched action_digest against the document', () => {
    const tampered = { ...doc, binding: { id: 'b2' } };
    expect(dualDigestConsistent(ad, idig, tampered)).toBe(false);            // does not recompute
    expect(dualDigestConsistent('sha256:' + 'c'.repeat(64), idig, doc)).toBe(false); // doc carries a different action_digest
  });

  it('rejects malformed digests', () => {
    expect(dualDigestConsistent('not-a-digest', idig)).toBe(false);
    expect(dualDigestConsistent(ad, 42)).toBe(false);
  });
});
