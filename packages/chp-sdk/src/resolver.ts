/**
 * Capability resolution — the hard-filter (CHP-RES-002) TS twin of `chp_core/resolver.resolve()`.
 *
 * The keystone: eligible = candidates satisfying EVERY hard constraint; rank the eligible by score
 * (deterministic, binding-id tiebreak, CHP-RES-016); NO score compensates a missing hard constraint;
 * an empty eligible set yields an unresolved resolution, never a silent pick (CHP-RES-002). Resolution
 * is NOT admission (CHP-RES-008). Computed functional/evidence fit (CHP-RES-003/005) is deferred (it
 * needs the contract port); this covers the satisfied_hard eligibility keystone. Function-level parity
 * with Python (no shipped resolver vector).
 */

export interface CandidateLike {
  binding: { id?: string } & Record<string, unknown>;
  satisfied_hard?: string[];
  score?: number;
  source_market?: unknown;
}

export interface RequirementLike {
  id?: string;
  capability: Record<string, unknown>;
  hard?: string[];
}

export interface Resolution {
  requirement_id: string | undefined;
  selected: Record<string, unknown> | null;
  candidates: Array<Record<string, unknown>>;
  result: 'resolved' | 'unresolved';
}

export function resolve(requirement: RequirementLike, candidates: CandidateLike[]): Resolution {
  const required = requirement.hard ?? [];
  // hard-filter (CHP-RES-002): a candidate is eligible only if it satisfies EVERY hard constraint.
  const eligible = candidates.filter((c) => {
    const sat = new Set(c.satisfied_hard ?? []);
    return required.every((h) => sat.has(h));
  });
  // rank the ELIGIBLE by score desc, deterministic binding-id tiebreak (CHP-RES-016).
  const ranked = [...eligible].sort(
    (a, b) =>
      (b.score ?? 0) - (a.score ?? 0) ||
      String(a.binding.id ?? '').localeCompare(String(b.binding.id ?? '')),
  );
  const selected = ranked.length ? ranked[0].binding : null;
  const record = (c: CandidateLike): Record<string, unknown> => {
    const rec: Record<string, unknown> = {
      binding: c.binding,
      score: c.score ?? 0,
      satisfied_hard: [...(c.satisfied_hard ?? [])].sort(),
    };
    if (c.source_market != null) rec.source_market = c.source_market; // preserve source (CHP-FED-003)
    return rec;
  };
  return {
    requirement_id: requirement.id,
    selected,
    candidates: ranked.map(record),
    result: selected != null ? 'resolved' : 'unresolved',
  };
}
