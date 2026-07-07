import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyTaskBundle } from '../src/verify.js';
import { buildTaskBundle, computeTaskRootHash } from '../src/signing.js';
import type { JsonValue } from '../src/canon.js';

const vecPath = fileURLToPath(new URL('../../../spec/test-vectors/task-bundle.json', import.meta.url));
const load = (): Record<string, JsonValue> => JSON.parse(readFileSync(vecPath, 'utf8'));

describe('task bundle (chp-v0.2.md §8) — cross-language vs the Python-generated vector', () => {
  it('verifies the published task bundle', () => {
    const v = verifyTaskBundle(load());
    expect(v.valid).toBe(true);
    expect(Object.values(v.checks).every(Boolean)).toBe(true);
    expect(v.hosts.map((h) => h.host_id)).toEqual(['task-host-a', 'task-host-b']);
  });

  it('rebuilds byte-consistently from the members (canonical sort + root)', () => {
    const t = load();
    const members = t.bundles as Record<string, JsonValue>[];
    const rebuilt = buildTaskBundle(t.correlation_id as string, [...members].reverse(), t.created_at as string);
    expect(rebuilt.task_root_hash).toBe(t.task_root_hash);
    expect(JSON.stringify(rebuilt.bundles)).toBe(JSON.stringify(t.bundles));
  });

  it('tampered member fails members_valid and names the culprit', () => {
    const t = load();
    ((t.bundles as Record<string, JsonValue>[])[0].events as Record<string, JsonValue>[])[0].payload = { n: 999 };
    const v = verifyTaskBundle(t);
    expect(v.valid).toBe(false);
    expect(v.checks.members_valid).toBe(false);
    expect(v.hosts[0].valid).toBe(false);
    expect(v.hosts[1].valid).toBe(true);
  });

  it('dropped causal ancestor fails causal_closure', () => {
    const t = load();
    const members = (t.bundles as Record<string, JsonValue>[]).filter((b) => b.host_id !== 'task-host-a');
    t.bundles = members as unknown as JsonValue;
    t.task_root_hash = computeTaskRootHash(members); // attacker recomputes
    const v = verifyTaskBundle(t);
    expect(v.valid).toBe(false);
    expect(v.checks.causal_closure).toBe(false);
    expect(v.reason).toMatch(/dangling/);
  });

  it('reordered members fail member_order + task_root_hash', () => {
    const t = load();
    t.bundles = [...(t.bundles as Record<string, JsonValue>[])].reverse() as unknown as JsonValue;
    const v = verifyTaskBundle(t);
    expect(v.valid).toBe(false);
    expect(v.checks.member_order).toBe(false);
    expect(v.checks.task_root_hash).toBe(false);
  });
});

const aggPath = fileURLToPath(new URL('../../../spec/test-vectors/task-bundle-aggregated.json', import.meta.url));
const loadAgg = (): Record<string, JsonValue> => JSON.parse(readFileSync(aggPath, 'utf8'));

describe('aggregated task bundle (§8) — aggregator + participation, cross-language', () => {
  it('verifies the published aggregated vector incl. aggregator + participation', () => {
    const v = verifyTaskBundle(loadAgg());
    expect(v.valid).toBe(true);
    expect(v.checks.aggregator).toBe(true);
    expect(v.checks.participation).toBe(true);
    expect(v.aggregator?.host_id).toBe('agg-gateway');
  });

  it('unsigned assembly surfaces aggregator: null, no aggregator check', () => {
    const t = loadAgg();
    delete t.aggregator;
    const v = verifyTaskBundle(t);
    expect(v.valid).toBe(true);
    expect('aggregator' in v.checks).toBe(false);
    expect(v.aggregator).toBe(null);
  });

  it('dropping a DECLARED member fails participation (completeness limit closed)', () => {
    const t = loadAgg();
    delete t.aggregator; // isolate the participation check
    const members = (t.bundles as Record<string, JsonValue>[]).filter((b) => b.host_id !== 'agg-host-b');
    t.bundles = members as unknown as JsonValue;
    t.task_root_hash = computeTaskRootHash(members);
    const v = verifyTaskBundle(t);
    expect(v.valid).toBe(false);
    expect(v.checks.participation).toBe(false);
    expect(v.reason).toMatch(/declared but missing/);
  });

  it('re-assembled (tampered) set fails the aggregator signature', () => {
    const t = loadAgg();
    const members = (t.bundles as Record<string, JsonValue>[]).filter((b) => b.host_id !== 'agg-host-b');
    t.bundles = members as unknown as JsonValue;
    t.task_root_hash = computeTaskRootHash(members); // attacker recomputes root...
    const v = verifyTaskBundle(t);
    expect(v.checks.aggregator).toBe(false); // ...but cannot re-sign the header
  });

  it('signTaskBundle round-trips in TS', async () => {
    const { keypairFromSeed, signTaskBundle } = await import('../src/signing.js');
    const t = loadAgg();
    delete t.aggregator;
    const key = keypairFromSeed(Buffer.alloc(32, 7));
    const signed = signTaskBundle(t, key, 'ts-gateway');
    const v = verifyTaskBundle(signed);
    expect(v.checks.aggregator).toBe(true);
    expect(v.aggregator?.host_id).toBe('ts-gateway');
  });
});
