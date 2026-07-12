import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyMandate, scopeAllows } from '../src/verify.js';
import type { JsonValue } from '../src/canon.js';

const vecPath = fileURLToPath(new URL('../../../spec/test-vectors/mandate.json', import.meta.url));
const load = (): Record<string, JsonValue> => JSON.parse(readFileSync(vecPath, 'utf8'));

describe('mandates (§10) — cross-language vs the Python-generated vector', () => {
  it('verifies an in-scope invocation inside the validity window', () => {
    const v = verifyMandate(load(), {
      atTime: '2026-06-01T00:00:00Z',
      capabilityId: 'demo.echo',
      delegateId: 'vector-delegate',
    });
    expect(v.valid).toBe(true);
    expect(v.checks.principal_identity).toBe(true);
    expect(v.checks.scope).toBe(true);
  });

  it('wildcard scope entries follow the §2 grammar', () => {
    const scope = load().scope as JsonValue[];
    expect(scopeAllows(scope, 'chp.adapters.audit.stats')).toBe(true);
    expect(scopeAllows(scope, 'chp.adapters.git.push')).toBe(false);
  });

  it('expired mandate fails temporal only', () => {
    const v = verifyMandate(load(), { atTime: '2027-06-01T00:00:00Z' });
    expect(v.valid).toBe(false);
    expect(v.checks.temporal).toBe(false);
    expect(v.checks.signature).toBe(true);
  });

  it('out-of-scope capability fails scope', () => {
    const v = verifyMandate(load(), {
      atTime: '2026-06-01T00:00:00Z', capabilityId: 'demo.other',
    });
    expect(v.checks.scope).toBe(false);
  });

  it('wrong delegate fails delegate binding', () => {
    const v = verifyMandate(load(), { delegateId: 'someone-else' });
    expect(v.checks.delegate).toBe(false);
  });

  it('widened scope breaks the signature', () => {
    const t = load();
    t.scope = ['*'];
    const v = verifyMandate(t);
    expect(v.checks.signature).toBe(false);
  });

  it('unexpected principal key is rejected', () => {
    const v = verifyMandate(load(), { expectedPrincipalKey: 'deadbeefdeadbeef' });
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/unexpected key/);
  });
});

// max_invocations (§10, proposal 0026): the cap is signed in the header.
describe('capped mandate (max_invocations) — cross-language', () => {
  const cappedPath = fileURLToPath(new URL('../../../spec/test-vectors/mandate-capped.json', import.meta.url));
  const loadCapped = (): Record<string, JsonValue> => JSON.parse(readFileSync(cappedPath, 'utf8'));

  it('verifies the Python capped mandate (header signs the cap)', () => {
    const m = loadCapped();
    expect(m.max_invocations).toBe(3);
    const v = verifyMandate(m, { atTime: m.valid_from as string, capabilityId: 'demo.echo', delegateId: 'vector-delegate' });
    expect(v.valid).toBe(true);
    expect(v.checks.signature).toBe(true);
  });

  it('raising the cap breaks the signature', () => {
    const m = loadCapped();
    m.max_invocations = 999;
    expect(verifyMandate(m).checks.signature).toBe(false);
  });
});
