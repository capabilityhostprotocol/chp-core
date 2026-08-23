import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { contentHash, payloadCommitment, chunkSeqDigest, EVENT_HASH_V2, type EvidenceEvent } from '../src/hash.js';
import { verifyBundle, verifyApprovalGrant } from '../src/verify.js';
import { withholdPayloads } from '../src/signing.js';
import { documentDigest } from '../src/digests.js';
import { assessFreshness, grantOutlivesBound, concurrent, STALE } from '../src/temporal.js';
import type { JsonValue } from '../src/canon.js';

type Doc = Record<string, JsonValue>;

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

describe('published test vectors', () => {
  it('recomputes the single-event content_hash', () => {
    const expected = load('expected.json');
    const ev = load('event.json').event as EvidenceEvent;
    expect(contentHash(ev, null)).toBe(expected.event_content_hash);
  });

  // Capability Economy parity (proposal 0043): the second implementation reproduces the shipped
  // execution-truth digests byte-for-byte over chp-jcs-v1 — the keystone dual-digest model is a
  // PROTOCOL, not a Python library.
  it('reproduces the execution-truth digests (CHP-CORE-024)', () => {
    const v = load('digests.json');
    expect(documentDigest(v.action_document as Doc)).toBe(v.action_digest);
    expect(documentDigest(v.invocation_document as Doc)).toBe(v.invocation_digest);
    // the invocation BINDS the action digest (CHP-CORE-005)
    expect((v.invocation_document as Doc).action_digest).toBe(v.action_digest);
  });

  it('provider substitution keeps action_digest, changes invocation_digest (CHP-CORE-004/006)', () => {
    const v = load('provider-substitution.json');
    const a = v.invocation_a as Doc, b = v.invocation_b as Doc;
    // the SDK reproduces each stated invocation_digest from its document
    expect(documentDigest(a.invocation_document as Doc)).toBe(a.invocation_digest);
    expect(documentDigest(b.invocation_document as Doc)).toBe(b.invocation_digest);
    // both carry the SAME semantic action_digest (routing is not semantic) — stable across providers
    expect((a.invocation_document as Doc).action_digest).toBe(v.action_digest);
    expect((b.invocation_document as Doc).action_digest).toBe(v.action_digest);
    // but the governed-attempt digests DIFFER (provider changed → new admission required)
    expect(a.invocation_digest).not.toBe(b.invocation_digest);
  });

  // Temporal-truth parity (CHP-TEMP-006): the second implementation reproduces the shipped temporal
  // NEGATIVE vectors — a stale evidence, a grant overrun, and overlapping clock uncertainty.
  it('reproduces the temporal negative vectors (CHP-TEMP-002/003/004)', () => {
    const vecs: Record<string, Doc> = {};
    for (const v of (load('temporal-negative.json').vectors as Doc[])) vecs[v.id as string] = v;

    const s = vecs['stale-evidence'];
    expect(assessFreshness(s.issued_at as string, s.at_time as string, s.max_age_seconds as number)).toBe(STALE);

    const g = vecs['grant-overrun'];
    expect(grantOutlivesBound(g.grant_valid_until as string, g.depended_bounds as string[])).not.toBeNull();

    const c = vecs['overlapping-clock-uncertainty'];
    expect(concurrent(c.a as { time: string; uncertainty_s: number }, c.b as { time: string; uncertainty_s: number })).toBe(true);
  });

  it('verifies the Python-signed echo bundle', () => {
    const bundle = load('signed-bundle.json') as Record<string, JsonValue>;
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(true);
    expect(v.checks.signature).toBe(true);
    expect(v.checks.host_identity).toBe(true);
  });

  // chp-jcs-v1 (§2, proposal 0015): the canonicalization dispatch seam — a
  // Python-signed JCS bundle must verify through the TS SDK's header dispatch.
  it('verifies the Python-signed chp-jcs-v1 bundle (dispatch seam)', () => {
    const bundle = load('signed-bundle-jcs.json') as Record<string, JsonValue>;
    expect(bundle.canonicalization).toBe('chp-jcs-v1');
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(true);
    expect(v.checks.signature).toBe(true);
    expect(v.checks.host_identity).toBe(true);
  });

  it('rejects a chp-jcs-v1 bundle relabelled chp-stable-v1 (header bytes differ)', () => {
    const bundle = load('signed-bundle-jcs.json') as Record<string, JsonValue>;
    bundle.canonicalization = 'chp-stable-v1';
    expect(verifyBundle(bundle).checks.signature).toBe(false);
  });

  it('fails an unknown canonicalization scheme without throwing', () => {
    const bundle = load('signed-bundle-jcs.json') as Record<string, JsonValue>;
    bundle.canonicalization = 'chp-bogus-v1';
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(false);
    expect(v.checks.signature).toBe(false);
  });

  it('verifies the Python-signed GOVERNED bundle (string-encoded score)', () => {
    const bundle = load('governance-bundle.json') as Record<string, JsonValue>;
    expect(verifyBundle(bundle).valid).toBe(true);
  });

  it('rejects a tampered event payload', () => {
    const bundle = load('signed-bundle.json') as Record<string, JsonValue>;
    (bundle.events as EvidenceEvent[])[0].payload = { note: 'TAMPERED' };
    expect(verifyBundle(bundle).valid).toBe(false);
  });

  it('rejects a relabelled host_id', () => {
    const bundle = load('signed-bundle.json') as Record<string, JsonValue>;
    bundle.host_id = 'prod-gateway-acme';
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(false);
    expect(v.checks.signature).toBe(false);
  });

  // Selective disclosure (§14, proposal 0011) — cross-verify the Python-signed vectors.
  it('recomputes the chp-event-hash-v2 content_hash + commitment', () => {
    const v = load('event-hash-v2.json');
    const ev = v.event as EvidenceEvent;
    expect(ev.hash_scheme).toBe(EVENT_HASH_V2);
    expect(payloadCommitment(ev.payload)).toBe(v.payload_commitment);
    expect(contentHash(ev, v.prev_hash ?? null)).toBe(v.content_hash);
  });

  it('verifies the Python-signed WITHHELD bundle (withheld ok, disclosed bound)', () => {
    const bundle = load('bundle-withheld.json') as Record<string, JsonValue>;
    const events = bundle.events as EvidenceEvent[];
    expect(events[0].payload).toEqual({ chp_withheld: true });   // withheld
    expect(events[1].payload).not.toEqual({ chp_withheld: true }); // disclosed
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(true);
    expect(v.checks.payload_commitments).toBe(true);
    expect(v.checks.event_hashes).toBe(true);
    expect(v.checks.signature).toBe(true);
  });

  it('rejects a tampered DISCLOSED payload in the withheld bundle', () => {
    const bundle = load('bundle-withheld.json') as Record<string, JsonValue>;
    (bundle.events as EvidenceEvent[])[1].payload = { forged: true };
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(false);
    expect(v.checks.payload_commitments).toBe(false);
    expect(v.checks.event_hashes).toBe(true); // hash binds the commitment, not the payload
  });

  it('recomputes the chp-chunk-seq-v1 digest (§13.1)', () => {
    const v = load('chunk-seq.json');
    expect(chunkSeqDigest(v.deltas)).toBe(v.chunk_seq_digest);
    // order matters — a permutation must not match
    expect(chunkSeqDigest([...v.deltas].reverse())).not.toBe(v.chunk_seq_digest);
  });

  it('withholdPayloads keeps the signature valid (TS-native round trip)', () => {
    const bundle = load('bundle-withheld.json') as Record<string, JsonValue>;
    const rootBefore = bundle.root_hash;
    const minimized = withholdPayloads(bundle); // withhold every v2 payload
    expect((minimized.events as EvidenceEvent[]).every((e) => (e.payload as Record<string, unknown>).chp_withheld === true)).toBe(true);
    expect(minimized.root_hash).toBe(rootBefore);
    expect(minimized.signature).toEqual(bundle.signature);
    expect(verifyBundle(minimized).valid).toBe(true);
  });

  it('verifies the approval-grant vector (proposal 0037)', () => {
    const doc = load('approval-grant.json') as { cases: Array<{ grant: Record<string, JsonValue>; at_time: string; valid: boolean }> };
    for (const c of doc.cases) {
      expect(verifyApprovalGrant(c.grant, { atTime: c.at_time }).valid).toBe(c.valid);
    }
  });
});
