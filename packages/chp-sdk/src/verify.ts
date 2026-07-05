/**
 * Offline verification of a CHP evidence bundle (spec/chp-v0.2.md §3):
 * per-event hashes, chain continuity, root hash, the header signature, and the
 * host-identity attestation (binding + temporal validity). Library form of
 * spec/test-vectors/verify.mjs.
 */

import { verify as edVerify } from 'node:crypto';
import { canon, type JsonValue } from './canon.js';
import { rootHash, type EvidenceEvent } from './hash.js';
import { verifyChain } from './chain.js';
import { bundleHeader, publicKeyFromB64 } from './signing.js';
import { didKeyToRaw, verifySshsig } from './sshsig.js';

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

  const assurance = (bundle.assurance as string) ?? 'none';

  if (assurance === 'signed') {
    const sig = bundle.signature as { key_id?: string; signature?: string } | undefined;
    const pub = bundle.public_key as string | undefined;
    if (!sig || !sig.signature) return { valid: false, assurance, checks, reason: 'signed bundle missing signature' };
    if (!pub) return { valid: false, assurance, checks, reason: 'signed bundle missing public_key' };
    if (opts.expectedKeyId !== undefined && sig.key_id !== opts.expectedKeyId) {
      return { valid: false, assurance, checks, reason: `signed by unexpected key ${sig.key_id}` };
    }
    checks.signature = verifyCanon(pub, bundleHeader(bundle), sig.signature);

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
