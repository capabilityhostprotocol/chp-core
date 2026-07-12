/**
 * in-toto / DSSE attestation bridge (chp-v0.2.md §15, proposal 0021). Export a
 * signed CHP evidence bundle as a standard in-toto Statement wrapped in a DSSE
 * envelope, signed by the host ed25519 key over the DSSE PAE — portable into the
 * Sigstore/in-toto/SLSA ecosystem. Byte-for-byte identical to Python
 * `chp_core.dsse`: the Statement body is `canon()`'d (chp-stable-v1 = Python
 * `json.dumps(sort_keys=True)`), so the PAE — and the signature — match.
 */

import { sign as edSign, verify as edVerify } from 'node:crypto';
import { canon, type JsonValue } from './canon.js';
import { publicKeyFromB64, type HostKey } from './signing.js';
import { verifyBundle } from './verify.js';

export const IN_TOTO_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const IN_TOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const CHP_BUNDLE_PREDICATE_TYPE = 'https://chp.dev/attestation/evidence-bundle/v1';

/** DSSE PAE: `DSSEv1 SP LEN(type) SP type SP LEN(body) SP body` (byte lengths). */
function pae(payloadType: Buffer, body: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from('DSSEv1 '), Buffer.from(String(payloadType.length)), Buffer.from(' '),
    payloadType, Buffer.from(' '), Buffer.from(String(body.length)), Buffer.from(' '), body,
  ]);
}

function subjectName(bundle: Record<string, JsonValue>): string {
  const comp = bundle.completeness as Record<string, JsonValue> | undefined;
  if (comp?.correlation_id) return String(comp.correlation_id);
  const events = (bundle.events as Array<Record<string, JsonValue>>) ?? [];
  for (let i = events.length - 1; i >= 0; i--) {
    const cid = (events[i].correlation as Record<string, JsonValue> | undefined)?.correlation_id;
    if (cid) return String(cid);
  }
  return 'chp-evidence-bundle';
}

export function bundleToStatement(bundle: Record<string, JsonValue>): Record<string, JsonValue> {
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [{ name: subjectName(bundle), digest: { sha256: String(bundle.root_hash ?? '') } }],
    predicateType: CHP_BUNDLE_PREDICATE_TYPE,
    predicate: bundle as JsonValue,
  };
}

export interface DsseEnvelope {
  payload: string;
  payloadType: string;
  signatures: Array<{ keyid: string; sig: string }>;
}

export function dsseSign(statement: Record<string, JsonValue>, key: HostKey): DsseEnvelope {
  if (!key.privateKey) throw new Error('host key has no private component; cannot sign a DSSE envelope');
  const body = Buffer.from(canon(statement as JsonValue), 'utf8');
  const sig = edSign(null, pae(Buffer.from(IN_TOTO_PAYLOAD_TYPE, 'utf8'), body), key.privateKey);
  return {
    payload: body.toString('base64'),
    payloadType: IN_TOTO_PAYLOAD_TYPE,
    signatures: [{ keyid: key.keyId, sig: sig.toString('base64') }],
  };
}

export function bundleToAttestation(bundle: Record<string, JsonValue>, key: HostKey): DsseEnvelope {
  return dsseSign(bundleToStatement(bundle), key);
}

export function dsseStatement(envelope: DsseEnvelope): Record<string, JsonValue> {
  return JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
}

export function attestationToBundle(envelope: DsseEnvelope): Record<string, JsonValue> {
  return (dsseStatement(envelope).predicate as Record<string, JsonValue>) ?? {};
}

/** Level 1 — any DSSE verifier: recompute the PAE and check ed25519. */
export function verifyDsse(envelope: DsseEnvelope, publicKeyB64: string): boolean {
  try {
    const body = Buffer.from(envelope.payload, 'base64');
    const p = pae(Buffer.from(String(envelope.payloadType), 'utf8'), body);
    const pub = publicKeyFromB64(publicKeyB64);
    return (envelope.signatures ?? []).some((s) => edVerify(null, p, pub, Buffer.from(s.sig ?? '', 'base64')));
  } catch {
    return false;
  }
}

export interface AttestationVerification {
  valid: boolean;
  checks: Record<string, boolean>;
  reason?: string;
}

/** Level 2 — the full CHP check: PAE signature + subject digest + verifyBundle. */
export function verifyAttestation(envelope: DsseEnvelope, publicKey?: string): AttestationVerification {
  let stmt: Record<string, JsonValue>;
  try {
    stmt = dsseStatement(envelope);
  } catch (e) {
    return { valid: false, checks: { envelope: false }, reason: `malformed DSSE payload: ${(e as Error).message}` };
  }
  const bundle = (stmt.predicate as Record<string, JsonValue>) ?? {};
  const pub = publicKey ?? (bundle.public_key as string | undefined);
  const checks: Record<string, boolean> = {
    dsse_signature: !!pub && verifyDsse(envelope, String(pub)),
    statement_type: stmt._type === IN_TOTO_STATEMENT_TYPE && stmt.predicateType === CHP_BUNDLE_PREDICATE_TYPE,
    subject_digest: ((stmt.subject as Array<Record<string, JsonValue>>)?.[0]?.digest as Record<string, JsonValue>)?.sha256 === bundle.root_hash,
    bundle: verifyBundle(bundle).valid,
  };
  const valid = Object.values(checks).every(Boolean);
  return {
    valid, checks,
    reason: valid ? undefined : 'attestation checks failed: ' + Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).join(', '),
  };
}
