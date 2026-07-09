import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { verifyProvenanceStatement } from '../src/verify.js';
import type { JsonValue } from '../src/canon.js';

const vecPath = fileURLToPath(new URL('../../../spec/test-vectors/adapter-provenance.json', import.meta.url));
const load = (): Record<string, JsonValue> => JSON.parse(readFileSync(vecPath, 'utf8'));
const fixtureWheelSha = createHash('sha256').update('chp fixture wheel bytes v1').digest('hex');

describe('adapter provenance (§9) — cross-language vs the Python-generated vector', () => {
  it('verifies the published statement incl. artifact hash', () => {
    const v = verifyProvenanceStatement(load(), { wheelSha256: fixtureWheelSha });
    expect(v.valid).toBe(true);
    expect(v.checks.artifact_hash).toBe(true);
    expect(v.checks.publisher_identity).toBe(true);
  });

  it('wrong artifact hash fails artifact_hash only', () => {
    const v = verifyProvenanceStatement(load(), { wheelSha256: 'ab'.repeat(32) });
    expect(v.valid).toBe(false);
    expect(v.checks.artifact_hash).toBe(false);
    expect(v.checks.signature).toBe(true);
  });

  it('relabeled version breaks the signature', () => {
    const t = load();
    t.version = '9.9.9';
    const v = verifyProvenanceStatement(t);
    expect(v.checks.signature).toBe(false);
  });

  it('unexpected publisher key is rejected', () => {
    const v = verifyProvenanceStatement(load(), { expectedKeyId: 'deadbeefdeadbeef' });
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/unexpected key/);
  });
});
