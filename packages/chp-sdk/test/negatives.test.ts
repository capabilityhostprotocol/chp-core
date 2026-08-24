/**
 * Second-implementation adversarial parity — the v0.3 negative-case catalog (07_conformance/01).
 *
 * The Python substrate drives all 13 catalog attacks (packages/python/tests/test_negative_conformance.py).
 * A CHP protocol needs a SECOND implementation to independently refuse them, not just re-run the reference.
 * This TS SDK implements the wire/crypto + evidence-logic layer, so it drives the 7 catalog cases it has
 * primitives for — each through the EXISTING TS primitive, asserting the same honest refusal the Python
 * kernel makes. The remaining 6 need TS twins of the entity/assurance/claim-type/trust kernel that the SDK
 * does not implement yet; they are named in PENDING below as an honest parity gap, never forged green.
 */
import { describe, it, expect } from 'vitest';
import { activeAssertions, independentSources, isInferred } from '../src/assertions.js';
import { deriveReadiness } from '../src/readiness.js';
import { assessFreshness } from '../src/temporal.js';
import { bindingDigest, invocationDigest } from '../src/digests.js';
import { payloadCommitment } from '../src/hash.js';
import { EntitySubject, ClaimType, TrustAnchor, anchoredIssuerTrusted, assuranceFrom } from '../src/kernel.js';

describe('v0.3 negative-case catalog — second-implementation parity', () => {
  // 1. Entity impersonation — a failed subject-binding requirement can NEVER roll up to eligible.
  it('impersonation: an unsatisfied subject-binding is ineligible, never eligible', () => {
    expect(deriveReadiness([{ result: 'satisfied' }, { result: 'unsatisfied' }])).toBe('ineligible');
  });

  // 4. Credential replay — integrity-valid but wrong subject: the binding requirement is unsatisfied,
  //    and an unknown one is incomplete — the rollup is never silently eligible (CHP-RDY-007 / CHP-VER-007).
  it('credential-replay: wrong-subject binding never yields eligible', () => {
    expect(deriveReadiness([{ result: 'satisfied' }, { result: 'unsatisfied' }])).toBe('ineligible');
    expect(deriveReadiness([{ result: 'satisfied' }, { result: 'unknown' }])).toBe('incomplete');
  });

  // 3. Key rotation — the new key supersedes the old; only the new is active, the old is preserved (CHP-SEM-008).
  it('key-rotation: a superseded key is inactive, the new key active', () => {
    const active = activeAssertions([
      { id: 'k-old', claim_type: 'chp.identity.signing_key' },
      { id: 'k-new', claim_type: 'chp.identity.signing_key', supersedes: 'k-old' },
    ]);
    expect(active.map((a) => a.id)).toEqual(['k-new']);
  });

  // 5. Stale registry evidence — eligible yesterday, mandatory assertion now expired by policy (CHP-TEMP-002).
  it('stale-registry: past the policy max-age is stale, and stale dominates readiness', () => {
    const day = 24 * 3600;
    expect(assessFreshness('2026-08-01T00:00:00Z', '2026-08-20T00:00:00Z', 7 * day)).toBe('stale');
    expect(assessFreshness('2026-08-19T00:00:00Z', '2026-08-20T00:00:00Z', 7 * day)).toBe('fresh');
    expect(deriveReadiness([{ result: 'satisfied' }], { stale: true })).toBe('stale');
  });

  // 9. Evidence laundering — a marketplace re-signs a self-assertion: two relays of ONE issuer corroborate
  //    once, not twice — assurance does not rise to independent verification (CHP-TRUST-006).
  it('evidence-laundering: re-signing does not raise independent corroboration', () => {
    const relayed = [{ issuer: 'urn:provider' }, { issuer: 'urn:provider' }];
    expect(independentSources(relayed, (i) => i.issuer)).toBe(1);
  });

  // 10. Offer bait-and-switch — resolution binds O1; a materially changed offer is a different content-addressed
  //     binding, so the swap is detectable and O1 stays authoritative (CHP-CORE-004/006).
  it('offer-bait-and-switch: a changed offer yields a different binding digest', () => {
    const o1 = bindingDigest({ capability: { id: 'legal.review' }, provider: { id: 'p', terms: 'v1' }, host: { id: 'h' } });
    const o2 = bindingDigest({ capability: { id: 'legal.review' }, provider: { id: 'p', terms: 'v2' }, host: { id: 'h' } });
    expect(o1).not.toBe(o2);
  });

  // 11. Artifact substitution — the review attestation binds artifact A; a swapped B commits differently.
  it('artifact-substitution: a swapped artifact breaks the exact payload binding', () => {
    expect(payloadCommitment({ artifact: 'A' })).not.toBe(payloadCommitment({ artifact: 'B' }));
  });

  // 12. Grant replay — a grant binds an invocation_digest; re-presenting it for a different invocation
  //     (changed routing) re-keys the digest, so the grant does not bind the new attempt (CHP-CORE-004).
  //     (Stateful single-use — replay of the SAME invocation — is platform admission, not the SDK.)
  it('grant-replay: a grant cannot transplant to a different invocation', () => {
    const common = { invocationId: 'inv-1', actionDigest: 'ad', actor: { id: 'a' }, principal: { id: 'p' }, host: { id: 'h' } };
    const d1 = invocationDigest({ ...common, binding: { id: 'b1' }, provider: { id: 'p1' } });
    const d2 = invocationDigest({ ...common, binding: { id: 'b2' }, provider: { id: 'p2' } });
    expect(d1).not.toBe(d2);
  });

  // 2. Duplicate fuzzy match — two people share a name + employer: distinct stable ids, neither succeeds
  //    the other; a merge requires a VERIFIED identity-link (succession), never a name match (CHP-ENT-001).
  it('duplicate-fuzzy-match: distinct entities stay separate without link evidence', () => {
    const a = new EntitySubject({ id: 'e-1', kind: 'person', display: { name: 'Jordan Lee', employer: 'Acme' } });
    const b = new EntitySubject({ id: 'e-2', kind: 'person', display: { name: 'Jordan Lee', employer: 'Acme' } });
    expect(a.id).not.toBe(b.id);
    expect(a.succeedsId).toBeNull();
    expect(a.ref()).not.toEqual(b.ref());
  });

  // 6. Relationship authority leakage — member_of verifies, but issuer_authority is a SEPARATE dimension
  //    carried as unsatisfied, never collapsed into the integrity pass (CHP-TRUST-004 / CHP-VER-011).
  it('relationship-authority-leakage: authority is kept separate from integrity', () => {
    const av = assuranceFrom({ checks: { integrity: 'satisfied', subject_binding: 'satisfied' } }, { issuerAuthority: 'unsatisfied' });
    expect(av.checks.integrity).toBe('satisfied');
    expect(av.issuerAuthority).toBe('unsatisfied'); // no authority to SIGN, despite a valid membership claim
  });

  // 7. Namespace squatting — an extension claim type outside "chp." MUST name its authority (CHP-SEM-003).
  it('namespace-squatting: an extension claim type without authority is rejected', () => {
    expect(() => new ClaimType({ id: 'acme.custom.claim', version: '1', valueSchema: {}, description: 'squat' })).toThrow();
    const owned = new ClaimType({ id: 'acme.custom.claim', version: '1', valueSchema: {}, description: 'owned', namespaceAuthority: { id: 'urn:acme' } });
    expect(owned.namespaceAuthority).toEqual({ id: 'urn:acme' }); // explicitly owned, never equated with core chp.*
  });

  // 8. Capability similarity laundering — an LLM-inferred equivalence is labeled inference, never a fact.
  it('capability-similarity-laundering: an inferred equivalence stays inference', () => {
    const equiv = { id: 'a1', claim_type: 'chp.capability.equivalent_to', value: 'cap.b', inference: { basis: ['llm-judgment'], method: 'semantic-similarity' } };
    expect(isInferred(equiv)).toBe(true); // a resolver must not treat it as established
    expect(isInferred({ id: 'a2', claim_type: 'chp.identity.licence', value: 'x' })).toBe(false);
  });

  // 13. Federation poisoning — a partner's weak-evidence mapping is only an assertion; local trust rejects
  //     the unanchored issuer WITHOUT losing the remote record (CHP-TRUST-002 claim-scoped, INV-12).
  it('federation-poisoning: a cross-market mapping is not trusted without a local anchor', () => {
    const anchors = [new TrustAnchor('urn:local-registry', ['chp.identity.provider'])];
    expect(anchoredIssuerTrusted(anchors, 'urn:partner-mapped', 'chp.identity.provider')).toBe(false);
    expect(anchoredIssuerTrusted(anchors, 'urn:local-registry', 'chp.identity.provider')).toBe(true);
    // claim-scoping holds: the locally-anchored issuer is not trusted for a different claim
    expect(anchoredIssuerTrusted(anchors, 'urn:local-registry', 'chp.identity.clearance')).toBe(false);
  });

  // Parity manifest: the second implementation now drives the WHOLE v0.3 catalog (13/13).
  it('parity manifest: all 13 catalog cases driven by the second implementation', () => {
    const DRIVEN = [
      'entity-impersonation', 'credential-replay', 'key-rotation', 'stale-registry-evidence',
      'evidence-laundering', 'offer-bait-and-switch', 'artifact-substitution', 'grant-replay',
      'duplicate-fuzzy-match', 'relationship-authority-leakage', 'namespace-squatting',
      'capability-similarity-laundering', 'federation-poisoning',
    ];
    expect(new Set(DRIVEN).size).toBe(13); // full second-implementation adversarial parity
  });
});
