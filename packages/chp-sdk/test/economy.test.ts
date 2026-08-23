import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { activeAssertions, independentSources, conflictingAssertions } from '../src/assertions.js';
import { resolve } from '../src/resolver.js';
import { isEvidenceSubject, isEffectEvidence } from '../src/economy-types.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

describe('economy pure-function parity', () => {
  it('independentSources collapses projections of one source (CHP-TRUST-006)', () => {
    const edges = [{ df: 'a1' }, { df: 'a1' }, { df: 'a2' }];
    expect(independentSources(edges, (e) => e.df)).toBe(2); // not 3
    // unattributed items count as their own source
    expect(independentSources([{ df: 'a1' }, { df: null }, { df: null }], (e) => e.df)).toBe(3);
  });

  it('conflictingAssertions preserves conflict, superseded does not (CHP-TRUST-008/SEM-008)', () => {
    const s = { kind: 'person', id: 'jane' };
    const a1 = { id: 'x1', claim_type: 'lic', subject: s, value: { no: 'P-1' } };
    const a2 = { id: 'x2', claim_type: 'lic', subject: s, value: { no: 'P-2' } };
    const conflicts = conflictingAssertions([a1, a2]);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].values.map((v) => (v as { no: string }).no).sort()).toEqual(['P-1', 'P-2']);
    // agreement is not a conflict
    expect(conflictingAssertions([a1, { ...a2, value: { no: 'P-1' } }])).toHaveLength(0);
    // a superseded assertion cannot create a false conflict
    expect(conflictingAssertions([a1, { ...a2, supersedes: 'x1' }])).toHaveLength(0);
    // and active-set filtering drops the superseded one
    expect(activeAssertions([a1, { ...a2, supersedes: 'x1' }]).map((a) => a.id)).toEqual(['x2']);
  });

  it('resolve hard-filter: no score compensates a missing hard constraint (CHP-RES-002)', () => {
    const req = { id: 'r1', capability: { id: 'legal.review' }, hard: ['licence'] };
    const decoy = { binding: { id: 'decoy' }, satisfied_hard: [], score: 999 }; // huge score, ineligible
    const ok = { binding: { id: 'ok' }, satisfied_hard: ['licence'], score: 1 };
    const res = resolve(req, [decoy, ok]);
    expect(res.result).toBe('resolved');
    expect(res.selected?.id).toBe('ok'); // the eligible score-1 beats the ineligible score-999
    // no eligible candidate → unresolved, never a silent pick
    expect(resolve(req, [decoy]).result).toBe('unresolved');
  });
});

describe('economy type-contract parity vs core-schema-vectors.json', () => {
  const vecs = load('core-schema-vectors.json');
  const guardFor: Record<string, (v: unknown) => boolean> = {
    'evidence-subject.schema.json': isEvidenceSubject,
    'effect-evidence.schema.json': isEffectEvidence,
  };

  it('accepts every positive vector its guard covers', () => {
    for (const p of vecs.positive as Array<{ schema: string; instance: unknown }>) {
      const g = guardFor[p.schema];
      if (g) expect(g(p.instance), `positive ${p.schema}`).toBe(true);
    }
  });

  it('rejects every negative vector its guard covers', () => {
    for (const n of vecs.negative as Array<{ schema: string; instance: unknown }>) {
      const g = guardFor[n.schema];
      if (g) expect(g(n.instance), `negative ${n.schema}`).toBe(false);
    }
  });
});
