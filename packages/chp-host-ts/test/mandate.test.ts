import { describe, it, expect } from 'vitest';
import { buildMandate as sdkBuildMandate, keypairFromSeed, type JsonValue } from '@capabilityhostprotocol/sdk';
import { buildFixtureHost } from '../src/fixtures.js';

// The SDK builder (byte-compatible with Python signing.build_mandate) — this
// test used to hand-roll the mandate before the SDK grew build parity.
function buildMandate(opts: { delegate?: string; scope?: string[]; hours?: number; maxInvocations?: number } = {}): Record<string, JsonValue> {
  const key = keypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 7)));
  const now = new Date();
  const iso = (d: Date) => d.toISOString().replace(/\.\d+Z$/, 'Z');
  const hours = opts.hours ?? 1;
  return sdkBuildMandate('principal-ts', key, {
    delegateId: opts.delegate ?? 'steward-x',
    scope: opts.scope ?? ['conformance.echo'],
    validFrom: iso(new Date(now.getTime() - 60_000)),
    validUntil: iso(new Date(now.getTime() + hours * 3_600_000)),
    createdAt: iso(now),
    mandateId: 'mnd_ts_test_0001',
    ...(opts.maxInvocations !== undefined ? { maxInvocations: opts.maxInvocations } : {}),
  });
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

  // max_invocations enforcement (§10, proposal 0026) — TS host parity with Python.
  it('max_invocations: cap enforced, replay-safe, denies mandate_exhausted', async () => {
    const h = buildFixtureHost();
    const m = buildMandate({ maxInvocations: 2 });
    const call = (inv: string) => h.ainvokeEnvelope({
      capability_id: 'conformance.echo', payload: { value: 'x' },
      correlation: { correlation_id: inv }, invocation_id: inv, mandate: m,
    });
    expect((await call('inv-1')).outcome).toBe('success');
    expect((await call('inv-2')).outcome).toBe('success');
    // the 3rd distinct invocation exceeds the cap
    const third = await call('inv-3');
    expect(third.outcome).toBe('denied');
    expect(third.denial?.code).toBe('mandate_exhausted');
    expect(third.denial?.retryable).toBe(false);
    expect((third.denial?.details as { used?: number }).used).toBe(2);
    // replay of an already-charged invocation_id does NOT consume a new use
    expect((await call('inv-1')).outcome).toBe('success');
    // and a fresh id is still denied (cap unchanged by the replay)
    expect((await call('inv-4')).denial?.code).toBe('mandate_exhausted');
  });

  it('max_invocations: an uncapped mandate is unbounded (no cap = pre-0026 behavior)', async () => {
    const h = buildFixtureHost();
    const m = buildMandate();  // no maxInvocations
    for (const inv of ['a', 'b', 'c', 'd', 'e']) {
      const r = await h.ainvokeEnvelope({
        capability_id: 'conformance.echo', correlation: { correlation_id: inv },
        invocation_id: inv, mandate: m,
      });
      expect(r.outcome).toBe('success');
    }
  });
});
