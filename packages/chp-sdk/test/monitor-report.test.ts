import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyStoreHeadMonitorReport } from '../src/verify.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));

// Log monitor / fork detection (§12, proposal 0023), byte-parity with Python
// chp_core.signing.verify_store_head_monitor_report.
describe('store-head-monitor-report', () => {
  const vec = load('store-head-monitor-report.json');

  it('cross-verifies the Python consistent report (monitor signature over the header)', () => {
    const v = verifyStoreHeadMonitorReport(vec.report as Record<string, JsonValue>);
    expect(v.valid).toBe(true);
    expect((vec.report as Record<string, JsonValue>).verdict).toBe('consistent');
  });

  it('cross-verifies the forked report and requires a real divergence', () => {
    const v = verifyStoreHeadMonitorReport(vec.forked as Record<string, JsonValue>);
    expect(v.valid).toBe(true);
    expect(v.checks.divergence_present).toBe(true);
    expect((vec.forked as Record<string, JsonValue>).verdict).toBe('forked');
  });

  it('a flipped verdict breaks the header signature', () => {
    const tampered = { ...(vec.report as Record<string, JsonValue>), verdict: 'forked' };
    expect(verifyStoreHeadMonitorReport(tampered).valid).toBe(false);
  });

  it('pins the monitored host and monitor key', () => {
    const report = vec.report as Record<string, JsonValue>;
    const keyId = (report.signature as Record<string, JsonValue>).key_id as string;
    expect(verifyStoreHeadMonitorReport(report, {
      expectedHostId: String(report.host_id), expectedMonitorKey: keyId,
    }).valid).toBe(true);
    expect(verifyStoreHeadMonitorReport(report, { expectedHostId: 'other' }).valid).toBe(false);
    expect(verifyStoreHeadMonitorReport(report, { expectedMonitorKey: 'wrong' }).valid).toBe(false);
  });
});
