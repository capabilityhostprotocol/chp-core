/**
 * Temporal-truth kernel (CHP-TEMP) — the TS twin of `chp_core/temporal.py`. Pure date logic, no
 * canon/crypto dependency: policy-derived freshness SEPARATE from validity (TEMP-002), grant temporal
 * bounds (TEMP-003), and clock-uncertainty concurrency (TEMP-004). Cross-verified against
 * spec/test-vectors/temporal-negative.json so a second implementation agrees on the temporal
 * negatives byte-for-byte.
 */

export const FRESH = 'fresh';
export const STALE = 'stale';
export const UNKNOWN = 'unknown';

const parse = (ts: string): number => Date.parse(ts.replace(/Z$/, '+00:00'));

/**
 * Policy-derived freshness (CHP-TEMP-002): FRESH iff the evidence is no older than the policy max-age
 * at `atTime`. The max-age is a POLICY input, deliberately SEPARATE from the issuer validity interval.
 * Missing any input → UNKNOWN, never silently FRESH.
 */
export function assessFreshness(
  issuedAt: string | null | undefined,
  atTime: string | null | undefined,
  maxAgeSeconds: number | null | undefined,
): string {
  if (!issuedAt || !atTime || maxAgeSeconds == null) return UNKNOWN;
  const ageS = (parse(atTime) - parse(issuedAt)) / 1000;
  return ageS >= 0 && ageS <= maxAgeSeconds ? FRESH : STALE;
}

/**
 * Return the first depended-on validity bound the grant OUTLIVES (grant strictly after it), else null
 * (CHP-TEMP-003). A grant MUST NOT outlive any evidence/authority validity bound its admission rests on.
 */
export function grantOutlivesBound(grantValidUntil: string, dependedBounds: string[]): string | null {
  const g = parse(grantValidUntil);
  for (const b of dependedBounds) if (b && g > parse(b)) return b;
  return null;
}

/** The largest valid_until a grant may carry: min(requested, ...depended bounds) (CHP-TEMP-003). */
export function clampGrantValidity(requestedValidUntil: string, dependedBounds: string[]): string {
  const candidates = [requestedValidUntil, ...dependedBounds.filter(Boolean)];
  return candidates.reduce((lo, t) => (parse(t) < parse(lo) ? t : lo));
}

export interface ClockReading {
  time: string;
  source?: string;
  uncertainty_s?: number;
}

/**
 * True when a and b CANNOT be strictly ordered — their uncertainty windows overlap (CHP-TEMP-004).
 * Callers preserve both / mark concurrent rather than forcing a false order.
 */
export function concurrent(a: ClockReading, b: ClockReading): boolean {
  const wa = (a.uncertainty_s ?? 0) * 1000;
  const wb = (b.uncertainty_s ?? 0) * 1000;
  const ta = parse(a.time), tb = parse(b.time);
  return ta - wa <= tb + wb && tb - wb <= ta + wa;
}
