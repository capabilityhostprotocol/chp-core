/**
 * RFC 6962 (Certificate Transparency) Merkle tree — the `chp-store-head-v2`
 * construction (proposal 0019). Domain-separated: leaf `SHA256(0x00‖data)`,
 * node `SHA256(0x01‖left‖right)`, odd sizes split at the largest power of two
 * `< n`. Byte-for-byte identical to Python `chp_core.merkle`.
 */

import { createHash } from 'node:crypto';

export const CHP_STORE_HEAD_V1 = 'chp-store-head-v1';
export const CHP_STORE_HEAD_V2 = 'chp-store-head-v2';

const _leafHash = (data: Buffer): Buffer =>
  createHash('sha256').update(Buffer.concat([Buffer.from([0]), data])).digest();
const _nodeHash = (l: Buffer, r: Buffer): Buffer =>
  createHash('sha256').update(Buffer.concat([Buffer.from([1]), l, r])).digest();

function _split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function merkleRoot(leaves: Buffer[]): Buffer {
  const n = leaves.length;
  if (n === 0) return createHash('sha256').update(Buffer.alloc(0)).digest();
  if (n === 1) return _leafHash(leaves[0]);
  const k = _split(n);
  return _nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

export function inclusionProof(leaves: Buffer[], index: number): Buffer[] {
  const n = leaves.length;
  if (index < 0 || index >= n) throw new RangeError(`leaf index ${index} out of range for ${n}`);
  if (n === 1) return [];
  const k = _split(n);
  if (index < k) return [...inclusionProof(leaves.slice(0, k), index), merkleRoot(leaves.slice(k))];
  return [...inclusionProof(leaves.slice(k), index - k), merkleRoot(leaves.slice(0, k))];
}

// Recompute by replaying the split: the recursion consumes deeper path entries
// FIRST, then the sibling is shifted — bind the recursion result explicitly (do
// NOT rely on argument evaluation order).
function _walk(size: number, index: number, path: Buffer[], leaf: Buffer): Buffer {
  if (size === 1) return leaf;
  const k = _split(size);
  if (index < k) {
    const left = _walk(k, index, path, leaf);
    return _nodeHash(left, path.shift() as Buffer);
  }
  const right = _walk(size - k, index - k, path, leaf);
  return _nodeHash(path.shift() as Buffer, right);
}

export function verifyInclusion(
  root: Buffer, leafData: Buffer, index: number, treeSize: number, auditPath: Buffer[],
): boolean {
  if (index < 0 || index >= treeSize) return false;
  const path = [...auditPath];
  const computed = _walk(treeSize, index, path, _leafHash(leafData));
  return path.length === 0 && computed.equals(root);
}

// ── Store-head schemes (chp-v0.2.md §12) ────────────────────────────────────

export type Leaves = Record<string, string | null>;

export function storeHeadLeaf(correlationId: string, headHash: string | null): Buffer {
  return Buffer.from(`${correlationId}\x00${headHash ?? ''}\n`, 'utf8');
}

export function storeHeadRoot(scheme: string, leaves: Leaves): string {
  const ordered = Object.keys(leaves).sort();
  if (scheme === CHP_STORE_HEAD_V1) {
    const h = createHash('sha256');
    for (const cid of ordered) h.update(storeHeadLeaf(cid, leaves[cid]));
    return h.digest('hex');
  }
  if (scheme === CHP_STORE_HEAD_V2) {
    return merkleRoot(ordered.map((cid) => storeHeadLeaf(cid, leaves[cid]))).toString('hex');
  }
  throw new Error(`unknown store-head scheme: ${scheme}`);
}

export function storeHeadSchemeMatching(leaves: Leaves, signedRoot: string): string | null {
  for (const scheme of [CHP_STORE_HEAD_V1, CHP_STORE_HEAD_V2]) {
    if (storeHeadRoot(scheme, leaves) === signedRoot) return scheme;
  }
  return null;
}

export interface StoreHeadInclusion {
  scheme: string;
  correlation_id: string;
  head_hash: string | null;
  leaf_index: number;
  tree_size: number;
  audit_path: string[];
}

export function storeHeadInclusionProof(leaves: Leaves, correlationId: string): StoreHeadInclusion {
  const ordered = Object.keys(leaves).sort();
  const index = ordered.indexOf(correlationId);
  if (index < 0) throw new Error(`correlation ${correlationId} not in leaves`);
  const path = inclusionProof(ordered.map((cid) => storeHeadLeaf(cid, leaves[cid])), index);
  return {
    scheme: CHP_STORE_HEAD_V2,
    correlation_id: correlationId,
    head_hash: leaves[correlationId],
    leaf_index: index,
    tree_size: ordered.length,
    audit_path: path.map((p) => p.toString('hex')),
  };
}

export function verifyStoreHeadInclusion(
  root: string, correlationId: string, headHash: string | null, proof: StoreHeadInclusion,
): boolean {
  if (proof.scheme !== CHP_STORE_HEAD_V2) return false;
  if (proof.correlation_id !== correlationId || proof.head_hash !== headHash) return false;
  try {
    const path = (proof.audit_path ?? []).map((h) => Buffer.from(h, 'hex'));
    return verifyInclusion(
      Buffer.from(root, 'hex'), storeHeadLeaf(correlationId, headHash),
      proof.leaf_index, proof.tree_size, path);
  } catch {
    return false;
  }
}
