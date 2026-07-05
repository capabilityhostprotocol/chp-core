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

export interface BundleVerification {
  valid: boolean;
  assurance: string;
  checks: Record<string, boolean>;
  reason?: string;
}

function verifyCanon(pubB64: string, obj: JsonValue, sigB64: string): boolean {
  return edVerify(null, Buffer.from(canon(obj), 'utf8'), publicKeyFromB64(pubB64), Buffer.from(sigB64, 'base64'));
}

export function verifyBundle(
  bundle: Record<string, JsonValue>,
  opts: { expectedKeyId?: string } = {},
): BundleVerification {
  const checks: Record<string, boolean> = {};
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
      const claim: JsonValue = {
        host_id: att.host_id,
        public_key: att.public_key,
        key_id: att.key_id,
        valid_from: att.valid_from,
        valid_until: att.valid_until,
      };
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
    }
  }

  const valid = Object.values(checks).every(Boolean);
  const reason = valid
    ? undefined
    : 'failed checks: ' + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', ');
  return { valid, assurance, checks, reason };
}
