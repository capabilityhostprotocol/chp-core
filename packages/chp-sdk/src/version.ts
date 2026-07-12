/**
 * Wire-version negotiation (spec chp-v0.2.md §1.1, proposal 0016). The single
 * source of truth for the protocol versions a host may speak; `0.2` is an
 * additive superset of `0.1` (the spec's minor feature versions 0.3.x/0.4.x
 * still speak wire `0.2`). Byte-for-byte parity with the Python `chp_core.types`
 * helpers so a client and host in either language negotiate identically.
 */

export const SUPPORTED_VERSIONS = ['0.1', '0.2'] as const;
export const PROTOCOL_VERSION: string = SUPPORTED_VERSIONS[SUPPORTED_VERSIONS.length - 1];

function verTuple(v: string): [number, number] {
  const p = v.split('.');
  return [parseInt(p[0] ?? '0', 10), parseInt(p[1] ?? '0', 10)];
}

/**
 * The wire lineage a host advertising `protocolVersion` speaks: every version in
 * SUPPORTED_VERSIONS up to and including it (an additive superset). Falls back to
 * `[protocolVersion]` for a version outside the known lineage.
 */
export function versionsUpto(protocolVersion: string): string[] {
  const idx = (SUPPORTED_VERSIONS as readonly string[]).indexOf(protocolVersion);
  return idx >= 0 ? SUPPORTED_VERSIONS.slice(0, idx + 1) : [protocolVersion];
}

/**
 * The highest wire version present in BOTH sets (spec §1.1), compared as
 * `(major, minor)`; `null` when they are disjoint.
 */
export function negotiateVersion(
  clientVersions: readonly string[],
  hostVersions: readonly string[],
): string | null {
  const hostSet = new Set(hostVersions);
  const common = clientVersions.filter((v) => hostSet.has(v));
  if (common.length === 0) return null;
  return common.reduce((best, v) => {
    const [bm, bn] = verTuple(best);
    const [vm, vn] = verTuple(v);
    return vm > bm || (vm === bm && vn > bn) ? v : best;
  });
}
