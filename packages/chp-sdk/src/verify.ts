/**
 * Offline verification of a CHP evidence bundle (spec/chp-v0.2.md §3):
 * per-event hashes, chain continuity, root hash, the header signature, and the
 * host-identity attestation (binding + temporal validity). Library form of
 * spec/test-vectors/verify.mjs.
 */

import { verify as edVerify } from 'node:crypto';
import { canon, canonFor, type JsonValue } from './canon.js';
import { EVENT_HASH_V2, payloadCommitment, rootHash, type EvidenceEvent } from './hash.js';
import { verifyChain } from './chain.js';
import { attenuates, bundleHeader, computeTaskRootHash, mandateHeader, publicKeyFromB64, taskBundleHeader } from './signing.js';
import { didKeyToRaw, verifySshsig, STORE_HEAD_ANCHOR_NAMESPACE } from './sshsig.js';
import { orderEvents } from './ordering.js';

export interface BundleVerification {
  valid: boolean;
  assurance: string;
  checks: Record<string, boolean>;
  reason?: string;
  /** The DID that countersigned the key, when a did anchor verified (offline). */
  anchoredDid?: string | null;
}

function verifyCanon(pubB64: string, obj: JsonValue, sigB64: string): boolean {
  return edVerify(null, Buffer.from(canon(obj), 'utf8'), publicKeyFromB64(pubB64), Buffer.from(sigB64, 'base64'));
}

export function verifyBundle(
  bundle: Record<string, JsonValue>,
  opts: { expectedKeyId?: string } = {},
): BundleVerification {
  const checks: Record<string, boolean> = {};
  let anchoredDid: string | null = null;
  const events = (bundle.events as EvidenceEvent[] | undefined) ?? [];

  const chain = verifyChain(events);
  checks.event_hashes = chain.eventHashesOk;
  checks.root_hash = bundle.root_hash === rootHash(events);

  // Selective disclosure (§14): a DISCLOSED chp-event-hash-v2 payload must match
  // the commitment its content_hash bound; a WITHHELD payload ({chp_withheld:true})
  // is skipped — the commitment alone secures the chain. v1 events are not checked.
  checks.payload_commitments = events.every((ev) => {
    if (ev.hash_scheme !== EVENT_HASH_V2) return true;
    const payload = ev.payload as Record<string, unknown> | undefined;
    if (payload && payload.chp_withheld === true) return true;
    return payloadCommitment(ev.payload) === ev.payload_commitment;
  });

  const assurance = (bundle.assurance as string) ?? 'none';

  if (assurance === 'signed') {
    const sig = bundle.signature as { key_id?: string; signature?: string } | undefined;
    const pub = bundle.public_key as string | undefined;
    if (!sig || !sig.signature) return { valid: false, assurance, checks, reason: 'signed bundle missing signature' };
    if (!pub) return { valid: false, assurance, checks, reason: 'signed bundle missing public_key' };
    if (opts.expectedKeyId !== undefined && sig.key_id !== opts.expectedKeyId) {
      return { valid: false, assurance, checks, reason: `signed by unexpected key ${sig.key_id}` };
    }
    // Header-signature serializer dispatches on `canonicalization` (§2 seam,
    // proposal 0015): chp-stable-v1 (absent/legacy) or chp-jcs-v1. An unknown
    // scheme is a failed signature, never a throw. The attestation below stays
    // chp-stable-v1 (signed at keygen time, independent of any bundle).
    try {
      const headerCanon = canonFor(bundle.canonicalization as string | null | undefined);
      checks.signature = edVerify(
        null,
        Buffer.from(headerCanon(bundleHeader(bundle)), 'utf8'),
        publicKeyFromB64(pub),
        Buffer.from(sig.signature, 'base64'),
      );
    } catch {
      return { valid: false, assurance, checks: { ...checks, signature: false },
        reason: `unknown canonicalization scheme ${String(bundle.canonicalization)}` };
    }

    const att = bundle.host_identity as Record<string, JsonValue> | undefined;
    if (att) {
      // Conditional-anchors rule (spec §3 Anchors): "anchors" participates in
      // the signed bytes only when present — same omit-when-empty rule as build.
      const claim: Record<string, JsonValue> = {
        host_id: att.host_id,
        public_key: att.public_key,
        key_id: att.key_id,
        valid_from: att.valid_from,
        valid_until: att.valid_until,
      };
      if ('anchors' in att) claim.anchors = att.anchors;
      const created = bundle.created_at as string | null;
      const vf = att.valid_from as string | null;
      const vu = att.valid_until as string | null;
      const temporalOk =
        (vf === null || created === null || vf <= created) &&
        (vu === null || created === null || created <= vu);
      checks.host_identity =
        att.host_id === bundle.host_id &&
        att.public_key === pub &&
        temporalOk &&
        verifyCanon(pub, claim, att.signature as string);

      // DID anchor (offline — no network, no CA/DNS): the Radicle identity key
      // countersigned this CHP key. Verified whenever present.
      const dAnchor = didAnchor(att);
      if (dAnchor) {
        checks.did_anchor = verifyDidAnchor(dAnchor, pub, bundle.host_id as string);
        if (checks.did_anchor) anchoredDid = dAnchor.did as string;
      }
    }
  }

  const valid = Object.values(checks).every(Boolean);
  const reason = valid
    ? undefined
    : 'failed checks: ' + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', ');
  return { valid, assurance, checks, reason, anchoredDid };
}

/** First `{"type":"did"}` anchor in an attestation, or null. */
export function didAnchor(attestation: Record<string, JsonValue>): Record<string, JsonValue> | null {
  const anchors = (attestation.anchors as JsonValue[] | undefined) ?? [];
  for (const a of anchors) {
    if (a && typeof a === 'object' && !Array.isArray(a)) {
      const o = a as Record<string, JsonValue>;
      if (o.type === 'did' && typeof o.did === 'string' && o.did) return o;
    }
  }
  return null;
}

/** The exact bytes a DID key countersigns to anchor a CHP key (§3.1). */
export function didAnchorMessage(chpPublicKeyB64: string, hostId: string): Buffer {
  return Buffer.from(canon({ chp_public_key: chpPublicKeyB64, host_id: hostId }), 'utf8');
}

/** Offline-verify a `did` anchor: the DID's key countersigned THIS CHP key. */
export function verifyDidAnchor(
  anchor: Record<string, JsonValue>,
  chpPublicKeyB64: string,
  hostId: string,
): boolean {
  let rawPub: Buffer;
  try {
    rawPub = didKeyToRaw(String(anchor.did ?? ''));
  } catch {
    return false;
  }
  return verifySshsig(String(anchor.countersignature ?? ''),
    didAnchorMessage(chpPublicKeyB64, hostId), { expectedRawPubkey: rawPub });
}

/** The exact bytes an external DID key countersigns to anchor a store head
 * (§12 External anchoring, proposal 0013). */
export function storeHeadAnchorMessage(
  hostId: string, sequence: number, storeHead: string, anchoredAt: string,
): Buffer {
  return Buffer.from(canon({ kind: 'store-head-anchor', host_id: hostId,
    sequence, store_head: storeHead, anchored_at: anchoredAt }), 'utf8');
}

/** Offline-verify a store-head anchor (§12, proposal 0013): the external did:key
 * must have SSHSIG-countersigned THIS (host_id, sequence, store_head, anchored_at)
 * under namespace chp-store-head-anchor. Independent of the witness peer set. */
export function verifyStoreHeadAnchor(
  statement: Record<string, JsonValue>,
): { valid: boolean; checks: Record<string, boolean>; anchoredDid: string | null } {
  const checks: Record<string, boolean> = {};
  checks.structure = statement.kind === 'store-head-anchor' && !!statement.host_id
    && Number.isInteger(statement.sequence) && !!statement.store_head;
  const anchor = (statement.anchor ?? {}) as Record<string, JsonValue>;
  let anchoredDid: string | null = null;
  try {
    const rawPub = didKeyToRaw(String(anchor.did ?? ''));
    checks.anchor = verifySshsig(String(anchor.countersignature ?? ''),
      storeHeadAnchorMessage(String(statement.host_id), Number(statement.sequence),
        String(statement.store_head), String(statement.anchored_at ?? '')),
      { namespace: STORE_HEAD_ANCHOR_NAMESPACE, expectedRawPubkey: rawPub });
    if (checks.anchor) anchoredDid = String(anchor.did);
  } catch {
    checks.anchor = false;
  }
  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, anchoredDid };
}

/** Witness quorum (§12, proposal 0013): verify each chain-witness statement over
 * the same head, dedupe by the witness's signature.key_id, optionally restrict
 * to a witness set, count vs k → quorum_met / quorum_short. */
export function evaluateWitnessQuorum(
  statements: Record<string, JsonValue>[],
  opts: { hostId: string; sequence: number; storeHead: string; k: number; witnessSet?: string[] },
): { verdict: string; k: number; distinct: number; witnesses: string[] } {
  const allowed = opts.witnessSet ? new Set(opts.witnessSet) : null;
  const distinct = new Map<string, string>();
  for (const s of statements) {
    if (s.host_id !== opts.hostId || s.sequence !== opts.sequence || s.store_head !== opts.storeHead) continue;
    if (!verifyChainWitness(s, { expectedHostId: opts.hostId }).valid) continue;
    const kid = String((s.signature as Record<string, JsonValue> | undefined)?.key_id ?? '');
    if (!kid || (allowed && !allowed.has(kid))) continue;
    if (!distinct.has(kid)) distinct.set(kid, String((s.witness as Record<string, JsonValue> | undefined)?.host_id ?? ''));
  }
  const met = distinct.size >= opts.k;
  return { verdict: met ? 'quorum_met' : 'quorum_short', k: opts.k,
    distinct: distinct.size, witnesses: [...distinct.keys()].sort() };
}

// ── Anchor resolution (spec §3 Anchors) ─────────────────────────────────────

export const WELL_KNOWN_IDENTITY_PATH = '/.well-known/chp-identity';
const IDENTITY_DOC_MAX_BYTES = 64 * 1024;

/** First `{"type":"domain"}` anchor's domain in an attestation, or null. */
export function domainAnchor(attestation: Record<string, JsonValue>): string | null {
  const anchors = (attestation.anchors as JsonValue[] | undefined) ?? [];
  for (const a of anchors) {
    if (a && typeof a === 'object' && !Array.isArray(a) && (a as Record<string, JsonValue>).type === 'domain') {
      const d = (a as Record<string, JsonValue>).domain;
      if (typeof d === 'string' && d) return d;
    }
  }
  return null;
}

/**
 * Fetch a host's identity document from its well-known endpoint. The doc's
 * authority comes from the TLS origin serving it (Web-PKI root), so https is
 * REQUIRED and redirects are refused. `fetchImpl` is test injection only.
 */
export async function resolveHostIdentity(
  domainOrUrl: string,
  opts: { timeoutMs?: number; fetchImpl?: typeof fetch } = {},
): Promise<Record<string, JsonValue>> {
  let url = domainOrUrl.includes('://') ? domainOrUrl : `https://${domainOrUrl}`;
  if (!url.startsWith('https://')) {
    throw new Error(`identity resolution requires https, got: ${url}`);
  }
  if (!url.includes(WELL_KNOWN_IDENTITY_PATH)) {
    url = url.replace(/\/+$/, '') + WELL_KNOWN_IDENTITY_PATH;
  }
  const f = opts.fetchImpl ?? fetch;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 5000);
  try {
    const resp = await f(url, { redirect: 'error', signal: ctrl.signal });
    if (!resp.ok) throw new Error(`identity endpoint returned ${resp.status}`);
    const text = await resp.text();
    if (text.length > IDENTITY_DOC_MAX_BYTES) throw new Error('identity document too large');
    const doc = JSON.parse(text) as JsonValue;
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      throw new Error('identity document is not a JSON object');
    }
    return doc as Record<string, JsonValue>;
  } finally {
    clearTimeout(t);
  }
}

/**
 * verifyBundle + anchor resolution: when the signed attestation carries a
 * domain anchor, fetch the domain's identity doc and confirm it vouches for
 * the bundle's key. `anchoredDomain` — not host_id — answers "whose?".
 * A no-anchor bundle resolves to the plain (TOFU-floor) result, visibly.
 */
export async function verifyBundleResolved(
  bundle: Record<string, JsonValue>,
  opts: { expectedKeyId?: string; fetchImpl?: typeof fetch } = {},
): Promise<BundleVerification & { anchoredDomain: string | null }> {
  const base = verifyBundle(bundle, { expectedKeyId: opts.expectedKeyId });
  const att = bundle.host_identity as Record<string, JsonValue> | undefined;
  const domain = att ? domainAnchor(att) : null;
  if (!base.valid || !att || !domain) return { ...base, anchoredDomain: null };
  try {
    const doc = await resolveHostIdentity(domain, { fetchImpl: opts.fetchImpl });
    const docKeys = new Set([
      doc.public_key,
      (doc.host_identity as Record<string, JsonValue> | undefined)?.public_key,
    ]);
    const anchorOk = docKeys.has(bundle.public_key);
    const checks = { ...base.checks, anchor: anchorOk };
    return {
      valid: base.valid && anchorOk,
      assurance: base.assurance,
      checks,
      reason: anchorOk ? base.reason : 'anchor domain does not vouch for this key',
      anchoredDomain: anchorOk ? domain : null,
    };
  } catch (err) {
    return {
      valid: false,
      assurance: base.assurance,
      checks: { ...base.checks, anchor: false },
      reason: `anchor resolution failed: ${(err as Error).message}`,
      anchoredDomain: null,
    };
  }
}

// ── Adapter provenance — supply chain (chp-v0.2.md §9, proposal 0001) ───────

const PROVENANCE_HEADER_FIELDS = [
  'kind', 'package', 'version', 'wheel_sha256', 'created_at', 'canonicalization',
] as const;

/** Verify a publisher's adapter-provenance statement: header signature,
 * publisher attestation (binding + temporal), DID anchor when present, and —
 * when `wheelSha256` is supplied — that the artifact on hand is the signed one. */
export function verifyProvenanceStatement(
  stmt: Record<string, JsonValue>,
  opts: { expectedKeyId?: string; wheelSha256?: string } = {},
): BundleVerification {
  const checks: Record<string, boolean> = {};
  let anchoredDid: string | null = null;
  checks.structure = stmt.kind === 'adapter-provenance'
    && !!stmt.package && !!stmt.version && !!stmt.wheel_sha256;

  const pub = (stmt.publisher as Record<string, JsonValue> | undefined) ?? {};
  const pubKey = String(pub.public_key ?? '');
  const sig = (stmt.signature as Record<string, JsonValue> | undefined) ?? {};
  if (opts.expectedKeyId !== undefined && sig.key_id !== opts.expectedKeyId) {
    return { valid: false, assurance: 'signed', checks, reason: `signed by unexpected key ${String(sig.key_id)}` };
  }

  const header: Record<string, JsonValue> = {};
  for (const f of PROVENANCE_HEADER_FIELDS) header[f] = stmt[f] ?? null;
  checks.signature = sig.algorithm === 'ed25519' && !!pubKey
    && verifyCanon(pubKey, header, String(sig.signature ?? ''));

  const att = pub.host_identity as Record<string, JsonValue> | undefined;
  if (att) {
    const claim: Record<string, JsonValue> = {
      host_id: att.host_id, public_key: att.public_key, key_id: att.key_id,
      valid_from: att.valid_from, valid_until: att.valid_until,
    };
    if ('anchors' in att) claim.anchors = att.anchors;
    const created = (stmt.created_at as string | null) ?? null;
    const vf = att.valid_from as string | null;
    const vu = att.valid_until as string | null;
    const temporalOk = (vf === null || created === null || vf <= created)
      && (vu === null || created === null || created <= vu);
    checks.publisher_identity = att.host_id === pub.host_id
      && att.public_key === pubKey && temporalOk
      && verifyCanon(pubKey, claim, att.signature as string);
    const dAnchor = didAnchor(att);
    if (dAnchor) {
      checks.did_anchor = verifyDidAnchor(dAnchor, pubKey, String(pub.host_id ?? ''));
      if (checks.did_anchor) anchoredDid = dAnchor.did as string;
    }
  } else {
    checks.publisher_identity = false; // a provenance claim must say WHO
  }

  if (opts.wheelSha256 !== undefined) {
    checks.artifact_hash = opts.wheelSha256 === stmt.wheel_sha256;
  }

  const valid = Object.values(checks).every(Boolean);
  return {
    valid, assurance: 'signed', checks, anchoredDid,
    reason: valid ? undefined : 'provenance checks failed: '
      + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', '),
  };
}

// ── Key rotation continuity (chp-v0.2.md §3.2) ──────────────────────────────

/** Verify a rotation continuity statement: signed by the OLD key it names.
 * Self-contained (one hop, exactly the Python `verify_continuity` scope — the
 * multi-hop walk from a pin lives with the pin store, not here). A verifier
 * holding an independently-pinned old key SHOULD check `old_public_key`
 * against its pin before trusting the statement. */
export function verifyContinuity(statement: Record<string, JsonValue>): boolean {
  const claim: Record<string, JsonValue> = {
    old_key_id: statement.old_key_id ?? null,
    old_public_key: statement.old_public_key ?? null,
    new_key_id: statement.new_key_id ?? null,
    new_public_key: statement.new_public_key ?? null,
    rotated_at: statement.rotated_at ?? null,
  };
  const oldPub = statement.old_public_key;
  if (!oldPub) return false;
  return verifyCanon(String(oldPub), claim, String(statement.signature ?? ''));
}

// ── Chain witnessing (chp-v0.2.md §12, proposal 0005) ───────────────────────

const CHAIN_WITNESS_VERIFY_FIELDS = [
  'kind', 'host_id', 'sequence', 'store_head', 'witnessed_at', 'canonicalization',
] as const;

/** Offline-verify a chain-witness statement: structure, header signature,
 * witness attestation (binding + temporal), DID anchor when present, and —
 * when supplied — the witnessed-host binding. Store-head RECOMPUTATION is a
 * separate act that needs the store itself. */
export function verifyChainWitness(
  statement: Record<string, JsonValue>,
  opts: { expectedHostId?: string; expectedWitnessKey?: string } = {},
): BundleVerification {
  const checks: Record<string, boolean> = {};
  let anchoredDid: string | null = null;
  checks.structure = statement.kind === 'chain-witness'
    && !!statement.host_id && Number.isInteger(statement.sequence)
    && !!statement.store_head;

  const witness = (statement.witness as Record<string, JsonValue> | undefined) ?? {};
  const pubKey = String(witness.public_key ?? '');
  const sig = (statement.signature as Record<string, JsonValue> | undefined) ?? {};
  if (opts.expectedWitnessKey !== undefined && sig.key_id !== opts.expectedWitnessKey) {
    return { valid: false, assurance: 'signed', checks, reason: `signed by unexpected witness key ${String(sig.key_id)}` };
  }

  const header: Record<string, JsonValue> = {};
  for (const f of CHAIN_WITNESS_VERIFY_FIELDS) header[f] = statement[f] ?? null;
  // revocation_head (proposal 0010) is header-signed only when present.
  if (statement.revocation_head) header.revocation_head = statement.revocation_head;
  checks.signature = sig.algorithm === 'ed25519' && !!pubKey
    && verifyCanon(pubKey, header, String(sig.signature ?? ''));

  const att = witness.host_identity as Record<string, JsonValue> | undefined;
  if (att) {
    checks.witness_identity = attestationOk(
      att, pubKey, String(witness.host_id ?? ''),
      (statement.witnessed_at as string | null) ?? null);
    const dAnchor = didAnchor(att);
    if (dAnchor) {
      checks.did_anchor = verifyDidAnchor(dAnchor, pubKey, String(witness.host_id ?? ''));
      if (checks.did_anchor) anchoredDid = dAnchor.did as string;
    }
  } else {
    checks.witness_identity = false; // a countersignature must say WHO witnessed
  }

  if (opts.expectedHostId !== undefined) {
    checks.witnessed_host = statement.host_id === opts.expectedHostId;
  }

  const valid = Object.values(checks).every(Boolean);
  return {
    valid, assurance: 'signed', checks, anchoredDid,
    reason: valid ? undefined : 'chain-witness checks failed: '
      + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', '),
  };
}

// ── Mandates — delegated authority on the wire (chp-v0.2.md §10, proposal 0002)

const MANDATE_HEADER_FIELDS = [
  'kind', 'mandate_id', 'delegate_id', 'scope',
  'valid_from', 'valid_until', 'created_at', 'canonicalization',
] as const;

/** The http-binding §2 scope grammar: exact capability id or trailing-`*` prefix. */
export function scopeAllows(scope: JsonValue[], capabilityId: string): boolean {
  return scope.some((s) => {
    const entry = String(s);
    return capabilityId === entry
      || (entry.endsWith('*') && capabilityId.startsWith(entry.slice(0, -1)));
  });
}

/** Offline-verify a mandate: structure, header signature, principal attestation
 * (binding + temporal), DID anchor when present, the validity window at
 * `atTime`, delegate binding, and — when `capabilityId` is supplied — scope. */
const MANDATE_REVOCATION_VERIFY_FIELDS = [
  'kind', 'mandate_id', 'revoked_at', 'reason', 'canonicalization',
] as const;

/** Offline-verify a mandate-revocation statement (§10, proposal 0007):
 * structure, header signature, principal attestation. SELF-consistency only —
 * whether it revokes a GIVEN mandate is `verifyMandate({revocations})`, which
 * checks the signature against the MANDATE's principal key (issuer-only). */
export function verifyMandateRevocation(
  statement: Record<string, JsonValue>,
  opts: { expectedPrincipalKey?: string } = {},
): BundleVerification {
  const checks: Record<string, boolean> = {};
  let anchoredDid: string | null = null;
  checks.structure = statement.kind === 'mandate-revocation'
    && !!statement.mandate_id && !!statement.revoked_at;

  const principal = (statement.principal as Record<string, JsonValue> | undefined) ?? {};
  const pubKey = String(principal.public_key ?? '');
  const sig = (statement.signature as Record<string, JsonValue> | undefined) ?? {};
  if (opts.expectedPrincipalKey !== undefined && sig.key_id !== opts.expectedPrincipalKey) {
    return { valid: false, assurance: 'signed', checks, reason: `signed by unexpected key ${String(sig.key_id)}` };
  }

  const header: Record<string, JsonValue> = {};
  for (const f of MANDATE_REVOCATION_VERIFY_FIELDS) header[f] = statement[f] ?? null;
  checks.signature = sig.algorithm === 'ed25519' && !!pubKey
    && verifyCanon(pubKey, header, String(sig.signature ?? ''));

  const att = principal.host_identity as Record<string, JsonValue> | undefined;
  if (att) {
    checks.principal_identity = attestationOk(
      att, pubKey, String(principal.host_id ?? ''),
      (statement.revoked_at as string | null) ?? null);
    const dAnchor = didAnchor(att);
    if (dAnchor) {
      checks.did_anchor = verifyDidAnchor(dAnchor, pubKey, String(principal.host_id ?? ''));
      if (checks.did_anchor) anchoredDid = dAnchor.did as string;
    }
  } else {
    checks.principal_identity = false; // a revocation must say WHOSE authority
  }

  const valid = Object.values(checks).every(Boolean);
  return {
    valid, assurance: 'signed', checks, anchoredDid,
    reason: valid ? undefined : 'mandate-revocation checks failed: '
      + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', '),
  };
}

export function verifyMandate(
  mandate: Record<string, JsonValue>,
  opts: {
    atTime?: string; capabilityId?: string;
    delegateId?: string; expectedPrincipalKey?: string;
    revocations?: Record<string, JsonValue>[];
  } = {},
): BundleVerification {
  const checks: Record<string, boolean> = {};
  let anchoredDid: string | null = null;
  checks.structure = mandate.kind === 'mandate'
    && !!mandate.mandate_id && !!mandate.delegate_id
    && Array.isArray(mandate.scope) && !!mandate.valid_until;

  const principal = (mandate.principal as Record<string, JsonValue> | undefined) ?? {};
  const pubKey = String(principal.public_key ?? '');
  const sig = (mandate.signature as Record<string, JsonValue> | undefined) ?? {};
  if (opts.expectedPrincipalKey !== undefined && sig.key_id !== opts.expectedPrincipalKey) {
    return { valid: false, assurance: 'signed', checks, reason: `signed by unexpected key ${String(sig.key_id)}` };
  }

  // mandateHeader adds depth+parent_id for a sub-mandate (proposal 0009);
  // a single-hop mandate's header is unchanged (byte-identical).
  const header = mandateHeader(mandate) as Record<string, JsonValue>;
  checks.signature = sig.algorithm === 'ed25519' && !!pubKey
    && verifyCanon(pubKey, header, String(sig.signature ?? ''));

  const att = principal.host_identity as Record<string, JsonValue> | undefined;
  if (att) {
    checks.principal_identity = attestationOk(
      att, pubKey, String(principal.host_id ?? ''),
      (mandate.created_at as string | null) ?? null);
    const dAnchor = didAnchor(att);
    if (dAnchor) {
      checks.did_anchor = verifyDidAnchor(dAnchor, pubKey, String(principal.host_id ?? ''));
      if (checks.did_anchor) anchoredDid = dAnchor.did as string;
    }
  } else {
    checks.principal_identity = false; // authority must say WHOSE
  }

  if (opts.atTime !== undefined) {
    const vf = mandate.valid_from as string | null;
    const vu = mandate.valid_until as string | null;
    checks.temporal = (vf === null || vf <= opts.atTime)
      && (vu === null || opts.atTime <= vu);
  }
  if (opts.delegateId !== undefined) {
    checks.delegate = mandate.delegate_id === opts.delegateId;
  }
  if (opts.capabilityId !== undefined) {
    checks.scope = scopeAllows((mandate.scope as JsonValue[]) ?? [], opts.capabilityId);
  }
  if (opts.revocations !== undefined) {
    // Issuer-only rule (§10 Revocation): the revocation signature is verified
    // against the MANDATE's principal key, never the statement's self-declared
    // key — otherwise anyone could revoke anyone by naming the mandate_id.
    checks.not_revoked = !opts.revocations.some((r) => {
      if (r.kind !== 'mandate-revocation' || r.mandate_id !== mandate.mandate_id) return false;
      const rp = (r.principal as Record<string, JsonValue> | undefined) ?? {};
      if (String(rp.public_key ?? '') !== pubKey) return false;
      const rHeader: Record<string, JsonValue> = {};
      for (const f of MANDATE_REVOCATION_VERIFY_FIELDS) rHeader[f] = r[f] ?? null;
      const rSig = (r.signature as Record<string, JsonValue> | undefined) ?? {};
      return verifyCanon(pubKey, rHeader, String(rSig.signature ?? ''));
    });
  }

  // Sub-delegation (§10, proposal 0009): an embedded parent must be attenuated
  // by this link and must itself verify — recursively to the root. Carries
  // host time + revocations (every ancestor's temporal + not_revoked run
  // against ITS key), not the leaf's delegate/capability bindings.
  const parent = mandate.parent as Record<string, JsonValue> | undefined;
  if (parent) {
    const att2 = attenuates(mandate, parent);
    for (const [k, v] of Object.entries(att2)) checks[k] = v;
    if (att2.depth && typeof parent === 'object') {
      checks.parent_valid = verifyMandate(parent, {
        atTime: opts.atTime, revocations: opts.revocations,
      }).valid;
    } else {
      checks.parent_valid = false;
    }
  }

  const valid = Object.values(checks).every(Boolean);
  return {
    valid, assurance: 'signed', checks, anchoredDid,
    reason: valid ? undefined : 'mandate checks failed: '
      + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', '),
  };
}

// ── Task bundles — cross-host verification unit (chp-v0.2.md §8) ────────────

export interface TaskBundleVerification {
  valid: boolean;
  assurance: string;
  checks: Record<string, boolean>;
  correlationId: string;
  taskRootHash: string | null;
  hosts: Array<Record<string, JsonValue>>;
  reason?: string;
  /** Who ASSEMBLED the set (null = unsigned assembly — surfaced, not hidden). */
  aggregator?: Record<string, JsonValue> | null;
}

/** Verify an attestation claim against a public key + host_id at a time —
 * shared by member bundles (host_identity) and the task aggregator. */
function attestationOk(
  att: Record<string, JsonValue>,
  pub: string,
  hostId: string,
  atTime: string | null,
): boolean {
  const claim: Record<string, JsonValue> = {
    host_id: att.host_id,
    public_key: att.public_key,
    key_id: att.key_id,
    valid_from: att.valid_from,
    valid_until: att.valid_until,
  };
  if ('anchors' in att) claim.anchors = att.anchors;
  const vf = att.valid_from as string | null;
  const vu = att.valid_until as string | null;
  const temporalOk =
    (vf === null || atTime === null || vf <= atTime) &&
    (vu === null || atTime === null || atTime <= vu);
  return (
    att.host_id === hostId &&
    att.public_key === pub &&
    temporalOk &&
    verifyCanon(pub, claim, att.signature as string)
  );
}

const taskMemberKey = (b: Record<string, JsonValue>): string =>
  `${String(b.host_id ?? '')} ${String(b.root_hash ?? '')}`;

/**
 * Verify a task's evidence spanning N hosts as a unit. Proves integrity of
 * every part, identity of every contributor, and CAUSAL CLOSURE — it does NOT
 * prove absence of evidence (a leaf contributor can be omitted undetectably;
 * a causal ancestor cannot — its children's causation_ids would dangle).
 */
export function verifyTaskBundle(task: Record<string, JsonValue>): TaskBundleVerification {
  const checks: Record<string, boolean> = {};
  const correlationId = String(task.correlation_id ?? '');
  const members = (task.bundles as Record<string, JsonValue>[] | undefined) ?? [];

  checks.structure = task.kind === 'task-bundle' && !!correlationId && members.length > 0;
  const keys = members.map(taskMemberKey);
  checks.member_order = keys.every((k, i) => i === 0 || keys[i - 1] <= k);
  checks.task_root_hash = task.task_root_hash === computeTaskRootHash(members);

  const hosts: Array<Record<string, JsonValue>> = [];
  let membersValid = true;
  const allEvents: EvidenceEvent[] = [];
  for (const b of members) {
    const v = verifyBundle(b);
    membersValid = membersValid && v.valid;
    const events = (b.events as EvidenceEvent[] | undefined) ?? [];
    allEvents.push(...events);
    hosts.push({
      host_id: (b.host_id ?? null) as JsonValue,
      key_id: ((b.signature as Record<string, JsonValue> | undefined)?.key_id ?? null) as JsonValue,
      assurance: v.assurance,
      anchored_did: v.anchoredDid ?? null,
      valid: v.valid,
      event_count: events.length,
    });
  }
  checks.members_valid = membersValid;

  checks.correlation = allEvents.every(
    (e) => (e.correlation as { correlation_id?: string } | undefined)?.correlation_id === correlationId,
  );
  const hostIds = members.map((b) => String(b.host_id ?? ''));
  checks.distinct_hosts = new Set(hostIds).size === hostIds.length;

  const invocationIds = new Set(allEvents.map((e) => e.invocation_id));
  const dangling = new Set<string>();
  for (const e of allEvents) {
    const c = (e.correlation as { causation_id?: string | null } | undefined)?.causation_id;
    if (c && !invocationIds.has(c)) dangling.add(c);
  }
  checks.causal_closure = dangling.size === 0;

  // Acyclicity via the topological property of the ordered union.
  const ordered = orderEvents(allEvents);
  const firstPos = new Map<string, number>();
  ordered.forEach((e, i) => {
    if (e.invocation_id && !firstPos.has(e.invocation_id)) firstPos.set(e.invocation_id, i);
  });
  let acyclic = true;
  ordered.forEach((e, i) => {
    const c = (e.correlation as { causation_id?: string | null } | undefined)?.causation_id;
    const p = c ? firstPos.get(c) : undefined;
    if (c && p !== undefined && p > i) acyclic = false;
  });
  checks.causal_acyclic = acyclic;

  // Participation manifest (§8): a declared member set (task_participants_declared,
  // riding the declarer's signed chain) must be fully present. Absent → no check.
  const declared = new Set<string>();
  for (const e of allEvents) {
    if (e.event_type === 'task_participants_declared') {
      const ps = ((e.payload as Record<string, JsonValue> | undefined)?.participants as JsonValue[] | undefined) ?? [];
      for (const p of ps) declared.add(String(p));
    }
  }
  const missingParticipants = new Set<string>();
  if (declared.size > 0) {
    const memberIds = new Set(members.map((b) => String(b.host_id ?? '')));
    for (const d of declared) if (!memberIds.has(d)) missingParticipants.add(d);
    checks.participation = missingParticipants.size === 0;
  }

  // Aggregator signature (§8 `aggregated` layer): verified whenever present.
  let aggregatorInfo: Record<string, JsonValue> | null = null;
  const agg = task.aggregator as Record<string, JsonValue> | undefined;
  if (agg) {
    const sig = (agg.signature as Record<string, JsonValue> | undefined) ?? {};
    const pub = String(agg.public_key ?? '');
    const att = agg.host_identity as Record<string, JsonValue> | undefined;
    let aggOk =
      sig.algorithm === 'ed25519' &&
      !!pub &&
      verifyCanon(pub, taskBundleHeader(task), String(sig.signature ?? ''));
    aggOk = aggOk && !!att
      && attestationOk(att, pub, String(agg.host_id ?? ''), (task.created_at as string | null) ?? null);
    checks.aggregator = aggOk;
    aggregatorInfo = {
      host_id: (agg.host_id ?? null) as JsonValue,
      key_id: (sig.key_id ?? null) as JsonValue,
      anchored_domain: att ? domainAnchor(att) : null,
      anchored_did: att ? ((didAnchor(att)?.did as string | undefined) ?? null) : null,
      valid: aggOk,
    };
  }

  const valid = Object.values(checks).every(Boolean);
  return {
    valid,
    assurance: String(task.assurance ?? 'none'),
    checks,
    correlationId,
    taskRootHash: (task.task_root_hash as string | undefined) ?? null,
    hosts,
    aggregator: aggregatorInfo,
    reason: valid
      ? undefined
      : 'task-bundle checks failed: '
        + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', ')
        + (dangling.size ? ` (dangling: ${[...dangling].slice(0, 3).join(',')})` : '')
        + (missingParticipants.size ? ` (declared but missing: ${[...missingParticipants].slice(0, 3).join(',')})` : ''),
  };
}
