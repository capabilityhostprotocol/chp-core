/**
 * Verifier robustness (TS parity with the Python fail-closed verifier audit).
 * Every public verifier, given malformed input (null / array / string / number /
 * boolean / empty / wrong-typed / deeply-nested garbage), must FAIL CLOSED:
 * return a not-valid verdict, NEVER throw, and NEVER false-verify. An
 * unauthenticated caller POSTing a JSON array/string as a "bundle" must not crash
 * a host or slip past a check.
 */

import { describe, it, expect } from 'vitest';
import {
  verifyBundle,
  verifyMandate,
  verifyMandateRevocation,
  verifyAuthToken,
  verifyApprovalGrant,
  verifyChainWitness,
  verifyProvenanceStatement,
  verifyStoreHeadMonitorReport,
  verifyStoreHeadAnchor,
  verifyRekorAnchor,
  verifyContinuity,
  verifyDidAnchor,
  verifyTaskBundle,
} from '../src/verify.js';
import { verifyAttestation } from '../src/dsse.js';

// The garbage matrix — each is a value a hostile / buggy caller might pass.
const GARBAGE: unknown[] = [
  null,
  undefined,
  [],
  ['not', 'an', 'object'],
  'a string',
  42,
  true,
  {},
  { events: 'not-an-array' },
  { events: [null, 42, 'x'] },
  { anchor: 42 },
  { signature: 123, header: [] },
  { payload: { chp_sealed: 999 } },
  { mandate: { scope: 'not-a-list' } },
  { deeply: { nested: { junk: [{ a: [1, { b: null }] }] } } },
];

// dummy second args so REQUIRED opts are present (the point is the first arg is garbage)
const VERIFIERS: Array<{ name: string; run: (g: any) => unknown }> = [
  { name: 'verifyBundle', run: (g) => verifyBundle(g) },
  { name: 'verifyMandate', run: (g) => verifyMandate(g, { atTime: '2026-07-15T00:00:00Z' }) },
  { name: 'verifyMandateRevocation', run: (g) => verifyMandateRevocation(g) },
  { name: 'verifyAuthToken', run: (g) => verifyAuthToken(g, { aud: 'h', atTime: '2026-07-15T00:00:00Z' }) },
  { name: 'verifyApprovalGrant', run: (g) => verifyApprovalGrant(g, { atTime: '2026-07-15T00:00:00Z' }) },
  { name: 'verifyChainWitness', run: (g) => verifyChainWitness(g) },
  { name: 'verifyProvenanceStatement', run: (g) => verifyProvenanceStatement(g) },
  { name: 'verifyStoreHeadMonitorReport', run: (g) => verifyStoreHeadMonitorReport(g) },
  { name: 'verifyStoreHeadAnchor', run: (g) => verifyStoreHeadAnchor(g) },
  { name: 'verifyRekorAnchor', run: (g) => verifyRekorAnchor(g, 'not-a-real-pem') },
  { name: 'verifyContinuity', run: (g) => verifyContinuity(g) },
  { name: 'verifyDidAnchor', run: (g) => verifyDidAnchor(g, 'pubkeyb64', 'host-id') },
  { name: 'verifyTaskBundle', run: (g) => verifyTaskBundle(g) },
  { name: 'verifyAttestation', run: (g) => verifyAttestation(g) },
];

function isNotValid(r: unknown): boolean {
  if (typeof r === 'boolean') return r === false;
  if (r && typeof r === 'object') return (r as { valid?: unknown }).valid === false;
  return true; // a non-object result from a verdict fn is itself a failure to fail-closed
}

describe('verifier robustness — fail closed on malformed input', () => {
  for (const { name, run } of VERIFIERS) {
    for (let i = 0; i < GARBAGE.length; i++) {
      const g = GARBAGE[i];
      it(`${name} fails closed on garbage[${i}] (${JSON.stringify(g)?.slice(0, 40)})`, () => {
        let result: unknown;
        expect(() => { result = run(g); }, `${name} threw on ${JSON.stringify(g)}`).not.toThrow();
        expect(isNotValid(result), `${name} FALSE-VERIFIED ${JSON.stringify(g)} -> ${JSON.stringify(result)}`).toBe(true);
      });
    }
  }
});
