// SECURITY regression (rad 0ae5fec): the approver identity MUST be cryptographically bound to the
// signing key material. Parity with Python tests/test_approval_grant.py
// test_forged_grant_rejected__identity_must_bind_to_key_material.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { verifyApprovalGrant } from '../src/verify.js';
import { generateKeypair, keyIdFor, publicKeyFromB64 } from '../src/signing.js';
import { edSign } from '../src/crypto.js';
import { canon, type JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

// Rebuild exactly the header verifyApprovalGrant signs (chp-jcs-v1 canonical; key order irrelevant).
function header(g: Record<string, JsonValue>): Record<string, JsonValue> {
  return {
    kind: g.kind, approval_id: g.approval_id, invocation_id: g.invocation_id,
    decision: g.decision, approver: g.approver, valid_until: g.valid_until,
    payload_commitment: g.payload_commitment, canonicalization: g.canonicalization,
  };
}

describe('approval-grant forgery (rad 0ae5fec)', () => {
  const doc = load('approval-grant.json') as {
    cases: Array<{ grant: Record<string, JsonValue>; at_time: string; valid: boolean }>;
  };
  const good = doc.cases.find((c) => c.valid);
  if (!good) throw new Error('no valid approval-grant vector case to base the forgery on');

  it('rejects a grant whose embedded key does not hash to the claimed approver', () => {
    const attacker = generateKeypair();
    // Forge: keep the legit approver string, but embed the attacker's pubkey and re-sign with the
    // attacker's key over the (unchanged) header. Pre-fix this verified; now key_binding must fail.
    const g: Record<string, JsonValue> = JSON.parse(JSON.stringify(good.grant));
    (g.approver_identity as Record<string, JsonValue>).public_key = attacker.publicKeyB64;
    (g.signature as Record<string, JsonValue>).signature =
      Buffer.from(edSign(Buffer.from(canon(header(g)), 'utf8'), attacker.privateKey!)).toString('base64');

    // The embedded pubkey's real key_id is the attacker's, not the claimed approver.
    expect(keyIdFor(publicKeyFromB64(attacker.publicKeyB64))).toBe(attacker.keyId);
    expect((g.approver as string)).not.toBe(attacker.keyId);

    const v = verifyApprovalGrant(g, { atTime: good.at_time, expectedApproverKey: g.approver as string });
    expect(v.valid).toBe(false);
    expect(v.checks.key_binding).toBe(false);
  });

  it('still verifies the honest grant vector (no regression)', () => {
    expect(verifyApprovalGrant(good.grant, { atTime: good.at_time }).valid).toBe(true);
  });
});
