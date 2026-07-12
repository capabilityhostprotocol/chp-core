import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  merkleRoot, storeHeadRoot, storeHeadInclusionProof, verifyStoreHeadInclusion,
  storeHeadSchemeMatching, CHP_STORE_HEAD_V1, CHP_STORE_HEAD_V2,
} from '../src/merkle.js';
import { verifyStoreHeadAnchor, auditCompletenessViaAnchor } from '../src/verify.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

// RFC 6962 Merkle store head + third-party inclusion (§12, proposal 0019),
// byte-parity with Python chp_core.merkle.
describe('chp-store-head-v2 (RFC 6962 Merkle)', () => {
  it('empty tree is SHA256("")', () => {
    expect(merkleRoot([]).toString('hex')).toBe(
      createHash('sha256').update(Buffer.alloc(0)).digest('hex'));
  });

  it('cross-verifies the Python v2 head vector (root recomputes)', () => {
    const hv = load('store-head-v2.json');
    expect(storeHeadRoot(CHP_STORE_HEAD_V2, hv.leaves)).toBe(hv.store_head);
    expect(storeHeadRoot(CHP_STORE_HEAD_V1, hv.leaves)).not.toBe(hv.store_head);
  });

  it('cross-verifies the Python inclusion vector (anchor + proof, third-party)', () => {
    const iv = load('store-head-inclusion.json');
    expect(verifyStoreHeadAnchor(iv.anchor).valid).toBe(true);
    expect(verifyStoreHeadInclusion(
      iv.anchor.store_head, iv.proof.correlation_id, iv.proof.head_hash, iv.proof)).toBe(true);
    // a forged tail fails; the proof does not transfer to another correlation
    expect(verifyStoreHeadInclusion(
      iv.anchor.store_head, iv.proof.correlation_id, 'f'.repeat(64), iv.proof)).toBe(false);
    expect(verifyStoreHeadInclusion(
      iv.anchor.store_head, 'other', iv.proof.head_hash, iv.proof)).toBe(false);
  });

  it('TS-native round trip: every leaf verifies for sizes 1..8', () => {
    for (let n = 1; n <= 8; n++) {
      const leaves: Record<string, string> = {};
      for (let i = 0; i < n; i++) leaves[`c${i}`] = createHash('sha256').update(`${i}`).digest('hex');
      const root = storeHeadRoot(CHP_STORE_HEAD_V2, leaves);
      for (const cid of Object.keys(leaves)) {
        const proof = storeHeadInclusionProof(leaves, cid);
        expect(verifyStoreHeadInclusion(root, cid, leaves[cid], proof)).toBe(true);
      }
    }
  });

  it('storeHeadSchemeMatching self-validates', () => {
    const leaves = { c1: 'a'.repeat(64), c2: 'b'.repeat(64) };
    expect(storeHeadSchemeMatching(leaves, storeHeadRoot(CHP_STORE_HEAD_V1, leaves))).toBe(CHP_STORE_HEAD_V1);
    expect(storeHeadSchemeMatching(leaves, storeHeadRoot(CHP_STORE_HEAD_V2, leaves))).toBe(CHP_STORE_HEAD_V2);
    expect(storeHeadSchemeMatching(leaves, '0'.repeat(64))).toBeNull();
  });

  it('auditCompletenessViaAnchor: complete when the anchored tail matches, incomplete otherwise', () => {
    const iv = load('store-head-inclusion.json');
    const corr = iv.proof.correlation_id;
    const realTail = iv.proof.head_hash;
    const complete = { completeness: { correlation_id: corr, as_of_sequence: 1, head_hash: realTail } } as Record<string, JsonValue>;
    expect(auditCompletenessViaAnchor(complete, iv.anchor, iv.proof).verdict).toBe('complete');
    // a bundle that claims a DIFFERENT (truncated) tail — the anchored proof exposes it
    const truncated = { completeness: { correlation_id: corr, as_of_sequence: 1, head_hash: 'a'.repeat(64) } } as Record<string, JsonValue>;
    expect(auditCompletenessViaAnchor(truncated, iv.anchor, iv.proof).verdict).toBe('incomplete');
  });
});
