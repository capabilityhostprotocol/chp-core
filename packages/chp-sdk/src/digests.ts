/**
 * Canonical action / invocation / binding documents and their digests (proposal 0043) — the TS twin
 * of `chp_core/digests.py`. The execution-truth keystone: a governed invocation carries TWO distinct
 * digests.
 *
 * - `actionDigest` identifies the SEMANTIC action — capability + principal + input + semantic_context.
 *   Provider/host/binding are EXCLUDED (routing, not semantic action) so substituting a provider
 *   leaves it UNCHANGED (CHP-CORE-004/006).
 * - `invocationDigest` binds the exact governed attempt — invocation identity plus the
 *   governance-relevant routing. Any routing change changes it (CHP-CORE-005/007).
 *
 * Both use chp-jcs-v1 (RFC 8785 JCS) — the same canonicalization as header signatures — so this
 * SECOND implementation reproduces the Python digests byte-for-byte (CHP-CORE-024), cross-verified
 * against spec/test-vectors/digests.json + provider-substitution.json.
 */
import { canonJcs, type JsonValue } from './canon.js';
import { sha256hex } from './crypto.js';

const PROTOCOL = 'chp/0.1';
type Doc = Record<string, JsonValue>;

/** `sha256:` digest of a canonical (chp-jcs-v1) document. */
export function documentDigest(doc: Doc): string {
  return 'sha256:' + sha256hex(canonJcs(doc));
}

const SHA256 = /^sha256:[0-9a-f]{64}$/;

/**
 * Verify the 0043 dual-digest INVARIANT on a received pair (CHP-CORE-026) — the machine-contract teeth a
 * JSON Schema cannot express. A genuine invocationDigest is over a document that CONTAINS actionDigest plus
 * routing, so it can never equal actionDigest — a collapsed pair (action === invocation) is a forgery the
 * shape schema misses. Checks: both are well-formed sha256; they are DISTINCT; and when the full canonical
 * invocation `document` is supplied, it carries exactly the claimed actionDigest AND its recomputed digest
 * equals the claimed invocationDigest (a swapped-routing tamper is caught, CHP-CORE-006). Returns false
 * rather than throwing. Twin of chp_core.digests.dual_digest_consistent — same canonicalization, so the two
 * implementations agree byte-for-byte (CHP-CORE-024).
 */
export function dualDigestConsistent(actionDigest: unknown, invocationDigest: unknown, document?: Doc): boolean {
  if (typeof actionDigest !== 'string' || typeof invocationDigest !== 'string') return false;
  if (!SHA256.test(actionDigest) || !SHA256.test(invocationDigest)) return false;
  if (actionDigest === invocationDigest) return false; // collapsed pair — never a genuine 0043 derivation
  if (document !== undefined) {
    if (document.action_digest !== actionDigest) return false; // doc does not carry the claimed action_digest
    if (documentDigest(document) !== invocationDigest) return false; // does not recompute (tampered routing)
  }
  return true;
}

export function actionDocument(a: {
  capability: JsonValue;
  principal: JsonValue;
  actionInput?: JsonValue;
  semanticContext?: JsonValue;
  protocol?: string;
}): Doc {
  return {
    protocol: a.protocol ?? PROTOCOL,
    capability: a.capability,
    principal: a.principal,
    input: a.actionInput ?? {},
    semantic_context: a.semanticContext ?? {},
  };
}
export const actionDigest = (a: Parameters<typeof actionDocument>[0]): string =>
  documentDigest(actionDocument(a));

export function invocationDocument(a: {
  invocationId: string;
  actionDigest: string;
  actor: JsonValue;
  principal: JsonValue;
  binding: JsonValue;
  provider: JsonValue;
  host: JsonValue;
  governanceContext?: JsonValue;
  protocol?: string;
}): Doc {
  return {
    protocol: a.protocol ?? PROTOCOL,
    invocation_id: a.invocationId,
    action_digest: a.actionDigest,
    actor: a.actor,
    principal: a.principal,
    binding: a.binding,
    provider: a.provider,
    host: a.host,
    governance_context: a.governanceContext ?? {},
  };
}
export const invocationDigest = (a: Parameters<typeof invocationDocument>[0]): string =>
  documentDigest(invocationDocument(a));

export function bindingDocument(a: {
  capability: JsonValue;
  provider: JsonValue;
  host: JsonValue;
  protocol?: string;
}): Doc {
  return { protocol: a.protocol ?? PROTOCOL, capability: a.capability, provider: a.provider, host: a.host };
}
export const bindingDigest = (a: Parameters<typeof bindingDocument>[0]): string =>
  documentDigest(bindingDocument(a));
