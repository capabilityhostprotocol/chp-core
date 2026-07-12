/**
 * A practical semver-range subset for capability-version negotiation (chp-v0.2.md
 * §1.1, proposal 0028). A byte-parity port of Python `chp_core.semver` — a caller's
 * `requested_capability_version` resolves identically in both implementations.
 *
 * Supported: exact `1.0.0`; caret `^1.2.0`; tilde `~1.2.3`; comparators `>= > <= < =`;
 * x-ranges `1.x` / `1` / `1.2.x`; `*` (any); space = AND. Versions compare as
 * `[major, minor, patch]` (pre-release / build tags stripped).
 */

type Version = [number, number, number];

export function parseVersion(v: string): Version {
  const core = String(v).trim().split('+')[0].split('-')[0];
  const parts = core.split('.');
  const out: Version = [0, 0, 0];
  for (let i = 0; i < 3; i++) {
    if (i < parts.length && /^\d+$/.test(parts[i])) out[i] = parseInt(parts[i], 10);
  }
  return out;
}

function cmp(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return 0;
}

function bump(v: Version, idx: number): Version {
  const p: Version = [v[0], v[1], v[2]];
  p[idx] += 1;
  for (let j = idx + 1; j < 3; j++) p[j] = 0;
  return p;
}

function satisfiesOne(version: Version, compRaw: string): boolean {
  const comp = compRaw.trim();
  if (comp === '' || comp === '*' || comp === 'x' || comp === 'X') return true;
  if (comp.startsWith('^')) {
    const base = parseVersion(comp.slice(1));
    let upper: Version;
    if (base[0] > 0) upper = bump([base[0], 0, 0], 0);
    else if (base[1] > 0) upper = bump([0, base[1], 0], 1);
    else upper = bump([0, 0, base[2]], 2);
    return cmp(version, base) >= 0 && cmp(version, upper) < 0;
  }
  if (comp.startsWith('~')) {
    const base = parseVersion(comp.slice(1));
    return cmp(version, base) >= 0 && cmp(version, bump([base[0], base[1], 0], 1)) < 0;
  }
  for (const op of ['>=', '<=', '>', '<', '=']) {
    if (comp.startsWith(op)) {
      const base = parseVersion(comp.slice(op.length));
      const c = cmp(version, base);
      return op === '>=' ? c >= 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : op === '<' ? c < 0 : c === 0;
    }
  }
  const tokens = comp.replace(/[*X]/g, 'x').split('.');
  if (tokens.includes('x')) {
    const i = tokens.indexOf('x');
    const prefix = tokens.slice(0, i).map((t) => parseInt(t, 10));
    if (prefix.length === 0) return true;
    const pad = [...prefix, 0, 0, 0];
    const lower: Version = [pad[0], pad[1], pad[2]];
    const upper = bump(lower, prefix.length - 1);
    return cmp(version, lower) >= 0 && cmp(version, upper) < 0;
  }
  if (tokens.length < 3) {
    const prefix = tokens.filter((t) => /^\d+$/.test(t)).map((t) => parseInt(t, 10));
    const pad = [...prefix, 0, 0, 0];
    const lower: Version = [pad[0], pad[1], pad[2]];
    const upper = bump(lower, prefix.length - 1);
    return cmp(version, lower) >= 0 && cmp(version, upper) < 0;
  }
  return cmp(version, parseVersion(comp)) === 0;
}

/** True iff `version` satisfies the range `spec` (space-separated ANDs). */
export function versionSatisfies(version: string, spec: string): boolean {
  const v = parseVersion(version);
  return String(spec).split(/\s+/).filter(Boolean).every((c) => satisfiesOne(v, c));
}

/** The highest of `versions` satisfying `spec`, or null. */
export function bestSatisfying(versions: string[], spec: string): string | null {
  const ok = versions.filter((v) => versionSatisfies(v, spec));
  if (ok.length === 0) return null;
  return ok.reduce((a, b) => (cmp(parseVersion(a), parseVersion(b)) >= 0 ? a : b));
}
