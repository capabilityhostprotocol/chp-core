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

// ── Consistency proofs (RFC 6962 §2.1.2, proposal 0022) ─────────────────────
// Prove a later tree (size n) is an append-only extension of an earlier one
// (size m ≤ n). Replay the prover's split so verify is the inverse of the build.

export function consistencyProof(leaves: Buffer[], m: number): Buffer[] {
  const n = leaves.length;
  if (m < 0 || m > n) throw new RangeError(`consistency: need 0 <= m(${m}) <= n(${n})`);
  if (m === 0 || m === n) return [];
  return _subproof(m, leaves, true);
}

function _subproof(m: number, leaves: Buffer[], b: boolean): Buffer[] {
  const n = leaves.length;
  if (m === n) return b ? [] : [merkleRoot(leaves)];
  const k = _split(n);
  if (m <= k) return [..._subproof(m, leaves.slice(0, k), b), merkleRoot(leaves.slice(k))];
  return [..._subproof(m - k, leaves.slice(k), false), merkleRoot(leaves.slice(0, k))];
}

// Returns [oldRoot@m, newRoot@n]; bind each shifted entry AFTER the recursion.
function _consistencyWalk(
  m: number, n: number, b: boolean, path: Buffer[], firstRoot: Buffer,
): [Buffer, Buffer] {
  if (m === n) {
    if (b) return [firstRoot, firstRoot];
    const h = path.shift() as Buffer;
    return [h, h];
  }
  const k = _split(n);
  if (m <= k) {
    const [old, newLeft] = _consistencyWalk(m, k, b, path, firstRoot);
    const right = path.shift() as Buffer;
    return [old, _nodeHash(newLeft, right)];
  }
  const [oldRight, newRight] = _consistencyWalk(m - k, n - k, false, path, firstRoot);
  const left = path.shift() as Buffer;
  return [_nodeHash(left, oldRight), _nodeHash(left, newRight)];
}

export function verifyConsistency(
  firstRoot: Buffer, secondRoot: Buffer, m: number, n: number, proof: Buffer[],
): boolean {
  if (m < 0 || m > n) return false;
  if (m === 0) return proof.length === 0;
  if (m === n) return proof.length === 0 && firstRoot.equals(secondRoot);
  const path = [...proof];
  const [old, next] = _consistencyWalk(m, n, true, path, firstRoot);
  return path.length === 0 && old.equals(firstRoot) && next.equals(secondRoot);
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

export interface StoreHeadConsistency {
  scheme: string;
  first_size: number;
  second_size: number;
  first_root: string;
  second_root: string;
  proof: string[];
}

export function storeHeadConsistencyProof(oldLeaves: Leaves, newLeaves: Leaves): StoreHeadConsistency {
  const oldOrdered = Object.keys(oldLeaves).sort();
  const newOrdered = Object.keys(newLeaves).sort();
  const newBytes = newOrdered.map((cid) => storeHeadLeaf(cid, newLeaves[cid]));
  return {
    scheme: CHP_STORE_HEAD_V2,
    first_size: oldOrdered.length,
    second_size: newOrdered.length,
    first_root: storeHeadRoot(CHP_STORE_HEAD_V2, oldLeaves),
    second_root: merkleRoot(newBytes).toString('hex'),
    proof: consistencyProof(newBytes, oldOrdered.length).map((h) => h.toString('hex')),
  };
}

export function verifyStoreHeadConsistency(
  oldRoot: string, newRoot: string, proof: StoreHeadConsistency,
): boolean {
  if (proof.scheme !== CHP_STORE_HEAD_V2) return false;
  if (proof.first_root !== oldRoot || proof.second_root !== newRoot) return false;
  try {
    const path = (proof.proof ?? []).map((h) => Buffer.from(h, 'hex'));
    return verifyConsistency(
      Buffer.from(oldRoot, 'hex'), Buffer.from(newRoot, 'hex'),
      proof.first_size, proof.second_size, path);
  } catch {
    return false;
  }
}
