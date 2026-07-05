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
import { bundleHeader, computeTaskRootHash, publicKeyFromB64 } from './signing.js';
import { didKeyToRaw, verifySshsig } from './sshsig.js';
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

// ── Task bundles — cross-host verification unit (chp-v0.2.md §8) ────────────

export interface TaskBundleVerification {
  valid: boolean;
  assurance: string;
  checks: Record<string, boolean>;
  correlationId: string;
  taskRootHash: string | null;
  hosts: Array<Record<string, JsonValue>>;
  reason?: string;
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

  const valid = Object.values(checks).every(Boolean);
  return {
    valid,
    assurance: String(task.assurance ?? 'none'),
    checks,
    correlationId,
    taskRootHash: (task.task_root_hash as string | undefined) ?? null,
    hosts,
    reason: valid
      ? undefined
      : 'task-bundle checks failed: '
        + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', ')
        + (dangling.size ? ` (dangling: ${[...dangling].slice(0, 3).join(',')})` : ''),
  };
}
