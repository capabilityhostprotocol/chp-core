/**
 * ed25519 signing for CHP evidence bundles (spec/chp-v0.2.md §3).
 *
 * Uses only `node:crypto`. Ed25519 raw keys are wrapped in DER (SPKI for public,
 * PKCS8 for private seed) — the same wrapping proven in verify.mjs. Signs the
 * canonical bundle HEADER (not bare root_hash) and attaches a self-signed
 * host-identity attestation.
 */

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as edSign, type KeyObject } from 'node:crypto';
import { canon, type JsonValue } from './canon.js';
import { rootHash, type EvidenceEvent } from './hash.js';

export const CANONICALIZATION = 'chp-stable-v1';
export const SIGNATURE_ALGORITHM = 'ed25519';

// DER wrappers for raw 32-byte ed25519 keys.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); // + 32-byte public key
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex'); // + 32-byte seed

export interface HostKey {
  keyId: string;
  publicKeyB64: string;
  privateKey?: KeyObject; // absent → verify-only
}

const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();

/** key_id = first 16 hex chars of SHA-256(raw public key). */
export function keyIdFor(rawPublicKey: Buffer): string {
  return sha256(rawPublicKey).toString('hex').slice(0, 16);
}

export function publicKeyFromB64(b64: string): KeyObject {
  const raw = Buffer.from(b64, 'base64');
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

function privateKeyFromSeed(seed: Buffer): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
}

/** Last 32 bytes of a public key's SPKI DER export = the raw ed25519 public key. */
function rawPublicOf(pub: KeyObject): Buffer {
  const der = pub.export({ format: 'der', type: 'spki' }) as Buffer;
  return der.subarray(-32);
}

/** Deterministic keypair from a 32-byte seed (used for test vectors). */
export function keypairFromSeed(seed: Buffer): HostKey {
  const priv = privateKeyFromSeed(seed);
  const rawPub = rawPublicOf(createPublicKey(priv));
  return { keyId: keyIdFor(rawPub), publicKeyB64: rawPub.toString('base64'), privateKey: priv };
}

/** Fresh random keypair. */
export function generateKeypair(): HostKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const rawPub = rawPublicOf(publicKey);
  return { keyId: keyIdFor(rawPub), publicKeyB64: rawPub.toString('base64'), privateKey };
}

function signCanon(priv: KeyObject, obj: JsonValue): string {
  return edSign(null, Buffer.from(canon(obj), 'utf8'), priv).toString('base64');
}

const HEADER_FIELDS = ['host_id', 'protocol_version', 'created_at', 'canonicalization', 'root_hash'] as const;

export function bundleHeader(bundle: Record<string, JsonValue>): JsonValue {
  const h: Record<string, JsonValue> = {};
  for (const f of HEADER_FIELDS) h[f] = bundle[f] ?? null;
  return h;
}

export function buildAttestation(
  hostId: string,
  key: HostKey,
  validFrom: string,
  validUntil: string | null = null,
  anchors: JsonValue[] | null = null,
): JsonValue {
  if (!key.privateKey) throw new Error('host key has no private component; cannot attest');
  const claim: Record<string, JsonValue> = {
    host_id: hostId,
    public_key: key.publicKeyB64,
    key_id: key.keyId,
    valid_from: validFrom,
    valid_until: validUntil,
  };
  // Omit-when-empty (spec §3 Anchors): emitting "anchors": [] would change the
  // canonical bytes and break every published vector. Anchors live INSIDE the
  // signed claim so they can be neither stripped nor stapled on.
  if (anchors && anchors.length > 0) claim.anchors = anchors;
  return { ...claim, signature: signCanon(key.privateKey, claim as JsonValue) } as JsonValue;
}

export function buildBundle(
  hostId: string,
  events: EvidenceEvent[],
  createdAt: string,
  protocolVersion = '0.2',
): Record<string, JsonValue> {
  return {
    host_id: hostId,
    protocol_version: protocolVersion,
    created_at: createdAt,
    canonicalization: CANONICALIZATION,
    assurance: 'hash-chain',
    events: events as unknown as JsonValue,
    root_hash: rootHash(events),
  };
}

export function signBundle(
  bundle: Record<string, JsonValue>,
  key: HostKey,
  opts: { validUntil?: string | null; anchors?: JsonValue[] | null } = {},
): Record<string, JsonValue> {
  if (!key.privateKey) throw new Error('host key has no private component; cannot sign');
  const signed: Record<string, JsonValue> = { ...bundle, assurance: 'signed', public_key: key.publicKeyB64 };
  signed.host_identity = buildAttestation(
    signed.host_id as string,
    key,
    (signed.created_at as string) ?? '',
    opts.validUntil ?? null,
    opts.anchors ?? null,
  );
  signed.signature = {
    algorithm: SIGNATURE_ALGORITHM,
    key_id: key.keyId,
    signature: signCanon(key.privateKey, bundleHeader(signed)),
  };
  return signed;
}

// ── Task bundles — cross-host verification unit (chp-v0.2.md §8) ────────────

/** SHA256 over member root_hashes joined by "\n" — the task's fingerprint. */
export function computeTaskRootHash(bundles: Record<string, JsonValue>[]): string {
  const h = createHash('sha256');
  for (const b of bundles) h.update(String(b.root_hash ?? '') + '\n');
  return h.digest('hex');
}

const memberKey = (b: Record<string, JsonValue>): [string, string] =>
  [String(b.host_id ?? ''), String(b.root_hash ?? '')];

const cmpMember = (a: Record<string, JsonValue>, b: Record<string, JsonValue>): number => {
  const [ah, ar] = memberKey(a);
  const [bh, br] = memberKey(b);
  return ah < bh ? -1 : ah > bh ? 1 : ar < br ? -1 : ar > br ? 1 : 0;
};

/** Aggregate one correlation's per-host signed bundles (members byte-untouched,
 * canonically sorted; assurance = MIN member tier — degradation surfaced). */
export function buildTaskBundle(
  correlationId: string,
  bundles: Record<string, JsonValue>[],
  createdAt: string,
): Record<string, JsonValue> {
  const members = [...bundles].sort(cmpMember);
  const tiers = new Set(members.map((b) => String(b.assurance ?? 'none')));
  const assurance = tiers.has('none') ? 'none' : tiers.has('hash-chain') ? 'hash-chain' : 'signed';
  return {
    kind: 'task-bundle',
    correlation_id: correlationId,
    created_at: createdAt,
    protocol_version: '0.2',
    canonicalization: CANONICALIZATION,
    assurance,
    bundles: members as unknown as JsonValue,
    task_root_hash: computeTaskRootHash(members),
  };
}

const TASK_HEADER_FIELDS = [
  'kind', 'correlation_id', 'protocol_version', 'created_at', 'canonicalization', 'task_root_hash',
] as const;

/** The aggregator-signed header — task_root_hash commits to every member root. */
export function taskBundleHeader(task: Record<string, JsonValue>): JsonValue {
  const h: Record<string, JsonValue> = {};
  for (const f of TASK_HEADER_FIELDS) h[f] = task[f] ?? null;
  return h;
}

/** Attach the AGGREGATOR signature (spec §8): the assembling gateway signs the
 * canonical task-bundle header with its own key + attestation. Omit-when-empty:
 * an unsigned task bundle stays byte-identical to the pre-aggregator format. */
export function signTaskBundle(
  task: Record<string, JsonValue>,
  key: HostKey,
  aggregatorHostId: string,
  opts: { validUntil?: string | null; anchors?: JsonValue[] | null } = {},
): Record<string, JsonValue> {
  if (!key.privateKey) throw new Error('aggregator key has no private component; cannot sign');
  return {
    ...task,
    aggregator: {
      host_id: aggregatorHostId,
      public_key: key.publicKeyB64,
      host_identity: buildAttestation(
        aggregatorHostId, key, String(task.created_at ?? ''),
        opts.validUntil ?? null, opts.anchors ?? null),
      signature: {
        algorithm: SIGNATURE_ALGORITHM,
        key_id: key.keyId,
        signature: signCanon(key.privateKey, taskBundleHeader(task)),
      },
    },
  };
}

// ── Statement family: mandates (§10), adapter provenance (§9), continuity ───

const MANDATE_HEADER_FIELDS = [
  'kind', 'mandate_id', 'delegate_id', 'scope',
  'valid_from', 'valid_until', 'created_at', 'canonicalization',
] as const;

/** The principal-signed header of a mandate (§10). `?? null` mirrors the
 * Python reference's `.get` semantics — deviating breaks signatures. */
export function mandateHeader(mandate: Record<string, JsonValue>): JsonValue {
  const h: Record<string, JsonValue> = {};
  for (const f of MANDATE_HEADER_FIELDS) h[f] = mandate[f] ?? null;
  return h;
}

/** A principal's signed grant of BOUNDED authority to a delegate (proposal
 * 0002, chp-v0.2.md §10) — byte-compatible with Python `build_mandate`:
 * scope is sorted BEFORE signing; the principal attestation uses
 * valid_from = created_at with NO valid_until; key_history omit-when-empty. */
export function buildMandate(
  principalId: string,
  key: HostKey,
  opts: {
    delegateId: string;
    scope: string[];
    validFrom: string;
    validUntil: string;
    createdAt: string;
    mandateId?: string;
    anchors?: JsonValue[] | null;
    keyHistory?: JsonValue[] | null;
  },
): Record<string, JsonValue> {
  if (!key.privateKey) throw new Error('principal key has no private component; cannot sign');
  const mandate: Record<string, JsonValue> = {
    kind: 'mandate',
    mandate_id: opts.mandateId ?? `mnd_${randomBytes(16).toString('hex')}`,
    delegate_id: opts.delegateId,
    scope: [...opts.scope].sort(),
    valid_from: opts.validFrom,
    valid_until: opts.validUntil,
    created_at: opts.createdAt,
    canonicalization: CANONICALIZATION,
  };
  const principal: Record<string, JsonValue> = {
    host_id: principalId,
    public_key: key.publicKeyB64,
    host_identity: buildAttestation(
      principalId, key, opts.createdAt, null, opts.anchors ?? null),
  };
  if (opts.keyHistory && opts.keyHistory.length > 0) principal.key_history = opts.keyHistory;
  mandate.principal = principal;
  mandate.signature = {
    algorithm: SIGNATURE_ALGORITHM,
    key_id: key.keyId,
    signature: signCanon(key.privateKey, mandateHeader(mandate)),
  };
  return mandate;
}

const PROVENANCE_HEADER_FIELDS_SIGN = [
  'kind', 'package', 'version', 'wheel_sha256', 'created_at', 'canonicalization',
] as const;

/** The publisher-signed header of an adapter-provenance statement (§9). */
export function provenanceHeader(stmt: Record<string, JsonValue>): JsonValue {
  const h: Record<string, JsonValue> = {};
  for (const f of PROVENANCE_HEADER_FIELDS_SIGN) h[f] = stmt[f] ?? null;
  return h;
}

/** A publisher's signed claim "I built this exact artifact" (proposal 0001,
 * chp-v0.2.md §9) — byte-compatible with Python `build_provenance_statement`.
 * `wheelSha256` is the SHA-256 of the artifact FILE (pre-execution invariant);
 * the publisher attestation DOES take validUntil; key_history omit-when-empty. */
export function buildProvenanceStatement(
  pkg: string,
  version: string,
  wheelSha256: string,
  key: HostKey,
  opts: {
    publisherId: string;
    createdAt: string;
    validUntil?: string | null;
    anchors?: JsonValue[] | null;
    keyHistory?: JsonValue[] | null;
  },
): Record<string, JsonValue> {
  if (!key.privateKey) throw new Error('publisher key has no private component; cannot sign');
  const stmt: Record<string, JsonValue> = {
    kind: 'adapter-provenance',
    package: pkg,
    version,
    wheel_sha256: wheelSha256,
    created_at: opts.createdAt,
    canonicalization: CANONICALIZATION,
  };
  const publisher: Record<string, JsonValue> = {
    host_id: opts.publisherId,
    public_key: key.publicKeyB64,
    host_identity: buildAttestation(
      opts.publisherId, key, opts.createdAt, opts.validUntil ?? null, opts.anchors ?? null),
  };
  if (opts.keyHistory && opts.keyHistory.length > 0) publisher.key_history = opts.keyHistory;
  stmt.publisher = publisher;
  stmt.signature = {
    algorithm: SIGNATURE_ALGORITHM,
    key_id: key.keyId,
    signature: signCanon(key.privateKey, provenanceHeader(stmt)),
  };
  return stmt;
}

/** A rotation continuity statement (§3.2): the OLD key signs a claim vouching
 * for the new one, so a verifier pinned to the old key can follow the lineage.
 * Byte-compatible with the statement `rotate_keypair` appends to
 * key_history.json (the disk/archival half stays Python-side). */
export function buildContinuityStatement(
  oldKey: HostKey,
  newKey: HostKey,
  rotatedAt: string,
): Record<string, JsonValue> {
  if (!oldKey.privateKey) throw new Error('old key has no private component; cannot vouch');
  const claim: Record<string, JsonValue> = {
    old_key_id: oldKey.keyId,
    old_public_key: oldKey.publicKeyB64,
    new_key_id: newKey.keyId,
    new_public_key: newKey.publicKeyB64,
    rotated_at: rotatedAt,
  };
  return { ...claim, signature: signCanon(oldKey.privateKey, claim as JsonValue) };
}
