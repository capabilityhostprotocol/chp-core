import { describe, it, expect } from 'vitest';
import { buildFixtureHost } from '../src/fixtures.js';
import { LocalCapabilityHost } from '../src/host.js';

const types = (evs: { event_type: string }[]) => evs.map((e) => e.event_type);

describe('governed invocation pipeline (spec/chp-invocation-pipeline.md)', () => {
  it('echo → success with started+completed', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({ capability_id: 'conformance.echo', payload: { value: 'x' }, correlation: { correlation_id: 'c' } });
    expect(r.outcome).toBe('success');
    expect(types(h.replay('c'))).toContain('execution_completed');
  });

  it('missing capability → denied capability_not_found', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({ capability_id: 'nope.x', correlation: { correlation_id: 'c' } });
    expect(r.outcome).toBe('denied');
    expect(r.denial?.code).toBe('capability_not_found');
  });

  it('near-miss capability id → denial details carry suggestions', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({ capability_id: 'conformance.ecoh', correlation: { correlation_id: 'c' } });
    expect(r.outcome).toBe('denied');
    const details = r.denial?.details as { suggestions?: string[]; hint?: string };
    expect(details?.suggestions).toContain('conformance.echo');
    expect(details?.hint).toMatch(/capabilities/);
  });

  it('guarded {} → denied invariant_failed', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({ capability_id: 'conformance.guarded', payload: {}, correlation: { correlation_id: 'c' } });
    expect(r.denial?.code).toBe('invariant_failed');
  });

  it('approval → approval_requested BEFORE denial, no execution', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({ capability_id: 'conformance.approval', correlation: { correlation_id: 'c' } });
    expect(r.denial?.code).toBe('approval_required');
    const t = types(h.replay('c'));
    expect(t).toEqual(['approval_requested', 'execution_denied']);
  });

  it('budgeted twice → 2nd is budget_exceeded', async () => {
    const h = buildFixtureHost();
    const first = await h.ainvokeEnvelope({ capability_id: 'conformance.budgeted', correlation: { correlation_id: 'c' } });
    const second = await h.ainvokeEnvelope({ capability_id: 'conformance.budgeted', correlation: { correlation_id: 'c' } });
    expect(first.success).toBe(true);
    expect(second.denial?.code).toBe('budget_exceeded');
    expect(types(h.replay('c'))).toContain('budget_exceeded');
  });

  it('risky → policy_blocked, no safety events (policy precedes safety)', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({ capability_id: 'conformance.risky', correlation: { correlation_id: 'c' } });
    expect(r.denial?.code).toBe('policy_blocked');
    expect(types(h.replay('c'))).toEqual(['execution_denied']);
  });

  it('unsafe → safety_blocked with the full assessment sequence', async () => {
    const h = buildFixtureHost();
    const r = await h.ainvokeEnvelope({ capability_id: 'conformance.unsafe', correlation: { correlation_id: 'c' } });
    expect(r.denial?.code).toBe('safety_blocked');
    const t = types(h.replay('c'));
    expect(t).toEqual([
      'safety_assessment_started', 'safety_assessment_completed',
      'safety_guardrail_triggered', 'safety_action_blocked', 'execution_denied',
    ]);
  });

  it('disabled capability → skipped, not denied', async () => {
    const h = new LocalCapabilityHost('t');
    h.register({ id: 'd.x', version: '1.0.0', enabled: false }, async () => ({}));
    const r = await h.ainvokeEnvelope({ capability_id: 'd.x', correlation: { correlation_id: 'c' } });
    expect(r.outcome).toBe('skipped');
    expect(types(h.replay('c'))).toEqual(['execution_skipped']);
  });

  it('emits a verifiable hash chain', async () => {
    const h = buildFixtureHost();
    await h.ainvokeEnvelope({ capability_id: 'conformance.echo', payload: { value: 'x' }, correlation: { correlation_id: 'c' } });
    expect(h.store.verifyChainFor('c').valid).toBe(true);
  });
});
