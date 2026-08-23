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
