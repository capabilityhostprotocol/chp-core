import { describe, it, expect } from 'vitest';
import { keypairFromSeed, buildAttestation } from '../src/signing.js';
import { verifyHostIdentity } from '../src/verify.js';
import type { JsonValue } from '../src/canon.js';

const SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i));

function descriptor(): Record<string, JsonValue> {
  const key = keypairFromSeed(SEED);
  const att = buildAttestation('vector-host', key, '2026-01-01T00:00:00Z') as Record<string, JsonValue>;
  return {
    id: 'vector-host',
    version: '0.1.0',
    protocol_version: '0.2',
    assurance: 'signed',
    public_key: key.publicKeyB64,
    key_id: key.keyId,
    host_identity: att,
    capabilities: [],
  };
}

describe('verifyHostIdentity (host descriptor self-signed attestation, spec §3)', () => {
  it('verifies a well-formed signed descriptor', () => {
    const v = verifyHostIdentity(descriptor());
    expect(v.valid).toBe(true);
    expect(v.checks.signature).toBe(true);
    expect(v.checks.host_id_matches).toBe(true);
    expect(v.checks.public_key_matches).toBe(true);
    expect(v.checks.temporal).toBe(true);
    expect(v.keyId).toBeTruthy();
  });

  it('fails closed when the attestation signature is tampered', () => {
    const d = descriptor();
    const att = { ...(d.host_identity as Record<string, JsonValue>) };
    const sig = att.signature as string;
    att.signature = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const v = verifyHostIdentity({ ...d, host_identity: att });
    expect(v.valid).toBe(false);
    expect(v.checks.signature).toBe(false);
  });

  it('fails when the attestation does not bind to the descriptor id', () => {
    const v = verifyHostIdentity({ ...descriptor(), id: 'someone-else' });
    expect(v.valid).toBe(false);
    expect(v.checks.host_id_matches).toBe(false);
  });

  it('fails closed on a missing attestation and on malformed input', () => {
    expect(verifyHostIdentity({ id: 'x', capabilities: [] }).valid).toBe(false);
    expect(verifyHostIdentity(null).valid).toBe(false);
    expect(verifyHostIdentity('nope').valid).toBe(false);
  });
});
