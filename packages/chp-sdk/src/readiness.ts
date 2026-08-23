/**
 * Readiness derivation — the TS twin of `ReadinessAssessment.derive_result` (chp_core/readiness.py).
 * Readiness is DERIVED from per-requirement four-states and is NEVER 'eligible' unless EVERY
 * requirement is satisfied (CHP-RDY-007); an unknown/error requirement → incomplete, never silently
 * eligible; suspended (entity status) and stale (past validity) dominate. Function-level parity.
 */

export type ReadinessResult = 'eligible' | 'ineligible' | 'incomplete' | 'stale' | 'suspended';

export function deriveReadiness(
  requirements: Array<{ result?: string }>,
  opts: { suspended?: boolean; stale?: boolean } = {},
): ReadinessResult {
  if (opts.suspended) return 'suspended';
  if (opts.stale) return 'stale';
  const vals = new Set(requirements.map((r) => r.result));
  if (vals.has('unsatisfied')) return 'ineligible';
  if (vals.has('unknown') || vals.has('error') || requirements.length === 0) return 'incomplete';
  return 'eligible';
}
