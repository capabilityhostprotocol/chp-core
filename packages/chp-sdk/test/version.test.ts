import { describe, it, expect } from 'vitest';
import {
  SUPPORTED_VERSIONS,
  PROTOCOL_VERSION,
  versionsUpto,
  negotiateVersion,
} from '../src/version.js';

// Wire-version negotiation (spec §1.1, proposal 0016) — must match the Python
// chp_core.types helpers byte-for-byte.
describe('negotiateVersion', () => {
  it('picks the highest mutual version', () => {
    expect(negotiateVersion(['0.1', '0.2'], ['0.1', '0.2'])).toBe('0.2');
    expect(negotiateVersion(['0.1'], ['0.1', '0.2'])).toBe('0.1'); // client floor
    expect(negotiateVersion(['0.1', '0.2'], ['0.1'])).toBe('0.1'); // host floor
  });

  it('returns null on disjoint sets', () => {
    expect(negotiateVersion(['0.1', '0.2'], ['9.9'])).toBeNull();
    expect(negotiateVersion([], ['0.2'])).toBeNull();
  });

  it('compares by (major, minor), not lexicographically', () => {
    expect(negotiateVersion(['0.2', '0.10'], ['0.2', '0.10'])).toBe('0.10');
  });
});

describe('versionsUpto', () => {
  it('is the additive prefix of the lineage', () => {
    expect(versionsUpto('0.2')).toEqual(['0.1', '0.2']);
    expect(versionsUpto('0.1')).toEqual(['0.1']);
    expect(versionsUpto('9.9')).toEqual(['9.9']); // outside the lineage → itself
  });

  it('PROTOCOL_VERSION is the highest supported', () => {
    expect(PROTOCOL_VERSION).toBe('0.2');
    expect(SUPPORTED_VERSIONS[SUPPORTED_VERSIONS.length - 1]).toBe('0.2');
  });
});
