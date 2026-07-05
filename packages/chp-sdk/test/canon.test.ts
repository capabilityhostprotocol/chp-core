import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canon, type JsonValue } from '../src/canon.js';

const vectorsDir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));

describe('chp-stable-v1 canon() vs the published golden set', () => {
  const golden = JSON.parse(readFileSync(vectorsDir + 'canon/cases.json', 'utf8')) as {
    cases: { name: string; input: JsonValue; expected_canon: string }[];
  };

  for (const c of golden.cases) {
    it(`reproduces ${c.name} byte-for-byte`, () => {
      expect(canon(c.input)).toBe(c.expected_canon);
    });
  }

  it('throws on a non-integer number (chp-stable-v1 §2 rule 6)', () => {
    expect(() => canon(0.5 as JsonValue)).toThrow(/non-integer/);
  });
});
