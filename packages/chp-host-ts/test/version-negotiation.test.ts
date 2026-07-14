import { describe, it, expect } from 'vitest';
import { LocalCapabilityHost } from '../src/host.js';

// Capability-version negotiation (§1.1, proposal 0028) — TS host parity with Python.
// A host runs several versions of an id; requested_capability_version (a semver range)
// resolves to the highest satisfying version, else capability_version_unsupported (the
// id EXISTS — distinct from capability_not_found).
describe('capability-version negotiation (proposal 0028) — TS host', () => {
  function twoVersionHost(): LocalCapabilityHost {
    const h = new LocalCapabilityHost('analyze-host');
    h.register({ id: 'analyze', version: '1.4.0' }, async () => ({ engine: 'v1' }));
    h.register({ id: 'analyze', version: '2.1.0' }, async () => ({ engine: 'v2' }));
    return h;
  }

  it('^1.0.0 resolves to the highest 1.x (1.4.0), not 2.x', async () => {
    const r = await twoVersionHost().ainvokeEnvelope({
      capability_id: 'analyze', requested_capability_version: '^1.0.0',
      correlation: { correlation_id: 'c' },
    });
    expect(r.outcome).toBe('success');
    expect(r.capability_version).toBe('1.4.0');
    expect(r.data).toEqual({ engine: 'v1' });
  });

  it('>=2.0.0 <3 resolves to 2.1.0', async () => {
    const r = await twoVersionHost().ainvokeEnvelope({
      capability_id: 'analyze', requested_capability_version: '>=2.0.0 <3',
      correlation: { correlation_id: 'c' },
    });
    expect(r.outcome).toBe('success');
    expect(r.capability_version).toBe('2.1.0');
  });

  it('^3.0.0 → capability_version_unsupported (available listed, NOT capability_not_found)', async () => {
    const r = await twoVersionHost().ainvokeEnvelope({
      capability_id: 'analyze', requested_capability_version: '^3.0.0',
      correlation: { correlation_id: 'c' },
    });
    expect(r.outcome).toBe('denied');
    expect(r.denial?.code).toBe('capability_version_unsupported');
    expect((r.denial?.details as { available?: string[] }).available?.sort()).toEqual(['1.4.0', '2.1.0']);
  });

  it('an unregistered id is still capability_not_found (the capability does not exist)', async () => {
    const r = await twoVersionHost().ainvokeEnvelope({
      capability_id: 'missing', requested_capability_version: '^1.0.0',
      correlation: { correlation_id: 'c' },
    });
    expect(r.denial?.code).toBe('capability_not_found');
  });

  it('no range + multiple versions is ambiguous → capability_not_found; a single registration resolves', async () => {
    const ambiguous = await twoVersionHost().ainvokeEnvelope({
      capability_id: 'analyze', correlation: { correlation_id: 'c' },
    });
    expect(ambiguous.denial?.code).toBe('capability_not_found');
    // an explicit exact version resolves even when several are registered
    const exact = await twoVersionHost().ainvokeEnvelope({
      capability_id: 'analyze', version: '2.1.0', correlation: { correlation_id: 'c' },
    });
    expect(exact.outcome).toBe('success');
    expect(exact.capability_version).toBe('2.1.0');
  });
});
