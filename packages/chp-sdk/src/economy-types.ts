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

// ---- Core candidate machine-contract guards (CHP-CORE-026/027) — TS-side parity with core-schema-vectors ----

const _INVOCATION_MODES = new Set(['sync', 'async', 'stream', 'fire_and_forget']);
const _INVOCATION_KEYS = new Set([
  'invocation_id', 'capability_id', 'version', 'mode', 'correlation', 'subject', 'payload',
  'requested_at', 'metadata', 'mandate', 'actor', 'binding', 'action_digest', 'invocation_digest',
]);

/** CHP-CORE-026: a valid invocation envelope — required routing fields, a known mode, and NO unknown key
 * (the schema is additionalProperties:false, so the type contract is strict here to reject a rogue field). */
export function isInvocationEnvelope(v: unknown): boolean {
  if (!_obj(v)) return false;
  for (const k of Object.keys(v)) if (!_INVOCATION_KEYS.has(k)) return false;   // additionalProperties:false
  return (
    _str(v.invocation_id) && _str(v.capability_id) &&
    typeof v.mode === 'string' && _INVOCATION_MODES.has(v.mode) &&
    _obj(v.correlation) && _obj(v.subject) && _obj(v.payload) && _str(v.requested_at)
  );
}

/** An approval grant — required fields, kind === 'approval-grant', decision === 'granted', signed. */
export function isApprovalGrant(v: unknown): boolean {
  return (
    _obj(v) && v.kind === 'approval-grant' && _str(v.approval_id) && _str(v.invocation_id) &&
    v.decision === 'granted' && _str(v.approver) && _str(v.valid_until) &&
    _str(v.payload_commitment) && _str(v.canonicalization) &&
    _obj(v.approver_identity) && _str((v.approver_identity as Record<string, unknown>).host_id) &&
    _obj(v.signature) && _str((v.signature as Record<string, unknown>).signature)
  );
}

const _ASSURANCE_LEVELS = new Set(['S1', 'S2', 'S3']);

/** An execution/evidence event — required fields incl an assurance level (S1/S2/S3). */
export function isEvidenceEvent(v: unknown): boolean {
  return (
    _obj(v) && _str(v.event_id) && _str(v.event_type) && _str(v.invocation_id) && _str(v.capability_id) &&
    _str(v.host_id) && _obj(v.correlation) && _str(v.timestamp) && typeof v.sequence === 'number' &&
    _obj(v.payload) && typeof v.redacted === 'boolean' &&
    _obj(v.assurance) && _ASSURANCE_LEVELS.has(String((v.assurance as Record<string, unknown>).level))
  );
}
