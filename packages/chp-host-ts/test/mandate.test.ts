import { describe, it, expect } from 'vitest';
import { keypairFromSeed, buildAttestation, canon, type JsonValue } from '@capabilityhostprotocol/sdk';
import { sign as edSign } from 'node:crypto';
import { createPrivateKey } from 'node:crypto';
import { buildFixtureHost } from '../src/fixtures.js';

// Build a mandate the same way the Python reference does (signing.build_mandate):
// canonical header signed by the principal key, attestation inside.
function buildMandate(opts: { delegate?: string; scope?: string[]; hours?: number } = {}): Record<string, JsonValue> {
  const key = keypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 7)));
  const now = new Date();
  const iso = (d: Date) => d.toISOString().replace(/\.\d+Z$/, 'Z');
  const hours = opts.hours ?? 1;
  const mandate: Record<string, JsonValue> = {
    kind: 'mandate',
    mandate_id: 'mnd_ts_test_0001',
    delegate_id: opts.delegate ?? 'steward-x',
    scope: (opts.scope ?? ['conformance.echo']).sort(),
    valid_from: iso(new Date(now.getTime() - 60_000)),
    valid_until: iso(new Date(now.getTime() + hours * 3_600_000)),
    created_at: iso(now),
    canonicalization: 'chp-stable-v1',
  };
  mandate.principal = {
    host_id: 'principal-ts',
    public_key: key.publicKeyB64,
    host_identity: buildAttestation('principal-ts', key, mandate.created_at as string),
  };
  const header = {
    kind: mandate.kind, mandate_id: mandate.mandate_id, delegate_id: mandate.delegate_id,
    scope: mandate.scope, valid_from: mandate.valid_from, valid_until: mandate.valid_until,
    created_at: mandate.created_at, canonicalization: mandate.canonicalization,
  };
  const priv = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'),
                        Buffer.from(Array.from({ length: 32 }, (_, i) => i + 7))]),
    format: 'der', type: 'pkcs8',
  });
  mandate.signature = {
    algorithm: 'ed25519',
    key_id: key.keyId,
    signature: edSign(null, Buffer.from(canon(header), 'utf8'), priv).toString('base64'),
  };
  return mandate;
}

describe('mandate gate (§10, pipeline gate 5) — TS host parity', () => {
  it('valid in-scope mandate → success with the mandate subject in evidence', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({
      capability_id: 'conformance.echo', payload: { value: 'x' },
      correlation: { correlation_id: 'c' }, mandate: buildMandate(),
    });
    expect(r.outcome).toBe('success');
    const subj = (h.replay('c')[0] as { subject?: Record<string, JsonValue> }).subject ?? {};
    expect(subj.type).toBe('mandate');
    expect(subj.id).toBe('steward-x');
    expect(subj.principal).toBe('principal-ts');
    expect(subj.verified).toBe(true);
  });

  it('expired mandate → mandate_invalid', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({
      capability_id: 'conformance.echo', correlation: { correlation_id: 'c' },
      mandate: buildMandate({ hours: -1 }),
    });
    expect(r.denial?.code).toBe('mandate_invalid');
    expect(r.denial?.retryable).toBe(false);
  });

  it('tampered scope → mandate_invalid (signature)', async () => {
    const h = buildFixtureHost();
    const m = buildMandate();
    m.scope = ['*'];
    const r = await h.ainvokeEnvelope({
      capability_id: 'conformance.echo', correlation: { correlation_id: 'c' }, mandate: m,
    });
    expect(r.denial?.code).toBe('mandate_invalid');
  });

  it('out-of-scope capability → policy_blocked', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({
      capability_id: 'conformance.echo', correlation: { correlation_id: 'c' },
      mandate: buildMandate({ scope: ['other.cap'] }),
    });
    expect(r.denial?.code).toBe('policy_blocked');
    expect(r.denial?.message).toMatch(/scope/);
  });

  it('mandate naming a different delegate than the verified caller → mandate_invalid', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({
      capability_id: 'conformance.echo', correlation: { correlation_id: 'c' },
      subject: { id: 'alice', type: 'api_key', verified: true },
      mandate: buildMandate({ delegate: 'steward-x' }),
    });
    expect(r.denial?.code).toBe('mandate_invalid');
  });

  it('no mandate → today\'s behavior', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({
      capability_id: 'conformance.echo', payload: { value: 'x' }, correlation: { correlation_id: 'c' },
    });
    expect(r.outcome).toBe('success');
  });
});
