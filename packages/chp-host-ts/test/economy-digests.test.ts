import { describe, it, expect } from 'vitest';
import { actionDigest } from '@capabilityhostprotocol/sdk';
import { buildFixtureHost } from '../src/fixtures.js';

const started = (h: ReturnType<typeof buildFixtureHost>, corr: string) =>
  h.replay(corr).find((e) => e.event_type === 'execution_started') as Record<string, unknown>;

describe('economy wiring: the host stamps the execution-truth dual digests (proposal 0043)', () => {
  it('stamps action_digest + invocation_digest, reproducibly by an independent computation', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({
      capability_id: 'conformance.echo', invocation_id: 'inv-1',
      payload: { value: 'x' }, correlation: { correlation_id: 'c' },
    });
    expect(r.outcome).toBe('success');

    const ev = started(h, 'c');
    expect(ev.action_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(ev.invocation_digest).toMatch(/^sha256:[0-9a-f]{64}$/);

    // the host-stamped action_digest is REPRODUCIBLE — an independent SDK computation over the same
    // inputs yields the identical digest (execution-truth consistency in the second-impl HOST).
    const independent = actionDigest({
      capability: { id: 'conformance.echo', version: r.capability_version! },
      principal: ev.subject as Record<string, unknown>, // the exact principal the host recorded
      actionInput: { value: 'x' },
    });
    expect(ev.action_digest).toBe(independent);
  });

  it('action_digest is routing-independent; invocation_digest binds the attempt (CHP-CORE-004/005)', async () => {
    const h = buildFixtureHost();
    await h.ainvokeEnvelope({ capability_id: 'conformance.echo', invocation_id: 'inv-a', payload: { value: 'x' }, correlation: { correlation_id: 'a' } });
    await h.ainvokeEnvelope({ capability_id: 'conformance.echo', invocation_id: 'inv-b', payload: { value: 'x' }, correlation: { correlation_id: 'b' } });
    const a = started(h, 'a'), b = started(h, 'b');
    // same semantic action → identical action_digest (routing/identity is not semantic)
    expect(a.action_digest).toBe(b.action_digest);
    // but a different governed attempt (invocation_id) → different invocation_digest
    expect(a.invocation_digest).not.toBe(b.invocation_digest);
  });
});
