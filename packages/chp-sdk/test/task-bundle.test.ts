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
