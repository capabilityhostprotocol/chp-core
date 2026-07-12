import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { versionSatisfies, bestSatisfying } from '../src/index.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

// Capability-version negotiation (§1.1, proposal 0028): the semver subset must
// agree with Python chp_core.semver on every known-answer case.
describe('semver matcher', () => {
  it('agrees with the Python matcher vector on every case', () => {
    const vec = load('version-negotiation.json');
    for (const c of vec.cases as Array<{ version: string; spec: string; satisfies: boolean }>) {
      expect(versionSatisfies(c.version, c.spec), `${c.version} vs ${c.spec}`).toBe(c.satisfies);
    }
  });

  it('bestSatisfying picks the highest compatible version', () => {
    expect(bestSatisfying(['1.0.0', '1.5.0', '2.0.0'], '^1.0.0')).toBe('1.5.0');
    expect(bestSatisfying(['2.0.0', '3.0.0'], '^1.0.0')).toBeNull();
  });
});
