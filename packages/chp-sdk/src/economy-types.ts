/**
 * Economy wire TYPES + guards — the TS twin of the chp_core economy dataclasses/schemas, so a second
 * implementation agrees on the shapes AND on what is valid. The guards reproduce the shipped JSON
 * Schemas' key constraints in TS and are cross-verified against spec/test-vectors/core-schema-vectors.json
 * (positives accepted, negatives rejected) — proving the type contract, not just the shape.
 */

// CHP-CORE-019: the eight subject kinds evidence can be about (no invocation required).
export const EVIDENCE_SUBJECT_KINDS = [
  'entity', 'capability', 'binding', 'invocation', 'execution', 'artifact', 'effect', 'external',
] as const;
export type EvidenceSubjectKind = (typeof EVIDENCE_SUBJECT_KINDS)[number];

export interface EvidenceSubject {
  kind: EvidenceSubjectKind;
  id: string;
  ref?: Record<string, unknown>;
}

// CHP-CORE-016/047: EffectEvidence four-state determination.
export const EFFECT_DETERMINATIONS = ['confirmed', 'indeterminate', 'unobserved', 'refuted'] as const;
export type EffectDetermination = (typeof EFFECT_DETERMINATIONS)[number];

export interface EffectEvidence {
  id: string;
  invocation_id: string;
  subject: { id: string; kind?: string };
  determination: EffectDetermination;
  observer: { id: string };
  observed_at: string;
  execution_id?: string;
}

const _KINDS = new Set<string>(EVIDENCE_SUBJECT_KINDS);
const _DET = new Set<string>(EFFECT_DETERMINATIONS);
const _str = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const _obj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;

/** CHP-CORE-019: a valid EvidenceSubject — kind in the eight-kind enum + a non-empty id. */
export function isEvidenceSubject(v: unknown): v is EvidenceSubject {
  return _obj(v) && typeof v.kind === 'string' && _KINDS.has(v.kind) && _str(v.id);
}

/** CHP-CORE-027: a valid EffectEvidence — required observer + four-state determination + subject id. */
export function isEffectEvidence(v: unknown): v is EffectEvidence {
  return (
    _obj(v) && _str(v.id) && _str(v.invocation_id) &&
    _obj(v.subject) && _str((v.subject as Record<string, unknown>).id) &&
    typeof v.determination === 'string' && _DET.has(v.determination) &&
    _obj(v.observer) && _str((v.observer as Record<string, unknown>).id) &&
    _str(v.observed_at)
  );
}
