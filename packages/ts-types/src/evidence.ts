/**
 * Evidence Types
 *
 * Evidence is the immutable record of capability execution.
 * Every capability execution produces one or more Evidence records.
 * These form the basis of the capability graph and audit trail.
 *
 * @module evidence
 */

import type { AssuranceTier } from "./assurance.js";

/**
 * Evidence types for capability execution tracking.
 *
 * Every capability execution produces evidence. The type indicates
 * what kind of execution event occurred.
 */
export type EvidenceType =
  // Core Execution
  | "execution_started"
  | "execution_completed"
  | "execution_failed"
  | "execution_denied"
  | "execution_aborted"
  // Invocation Boundary
  | "invocation_received"
  | "invocation_validated"
  | "invocation_rejected"
  // Authorization
  | "entitlement_checked"
  | "entitlement_granted"
  | "entitlement_denied"
  // Invariants
  | "invariant_checked"
  | "invariant_passed"
  | "invariant_failed"
  // Resilience Primitives
  | "retry_attempted"
  | "retry_exhausted"
  | "timeout_exceeded"
  | "circuit_opened"
  | "circuit_closed"
  | "rate_limited"
  // Assurance
  | "assurance_derived"
  | "assurance_degraded"
  // Lineage
  | "lineage_traced"
  | "causal_link_created";

/**
 * All evidence types as a const array for iteration.
 */
export const EVIDENCE_TYPES = [
  // Core Execution
  "execution_started",
  "execution_completed",
  "execution_failed",
  "execution_denied",
  "execution_aborted",
  // Invocation Boundary
  "invocation_received",
  "invocation_validated",
  "invocation_rejected",
  // Authorization
  "entitlement_checked",
  "entitlement_granted",
  "entitlement_denied",
  // Invariants
  "invariant_checked",
  "invariant_passed",
  "invariant_failed",
  // Resilience Primitives
  "retry_attempted",
  "retry_exhausted",
  "timeout_exceeded",
  "circuit_opened",
  "circuit_closed",
  "rate_limited",
  // Assurance
  "assurance_derived",
  "assurance_degraded",
  // Lineage
  "lineage_traced",
  "causal_link_created",
] as const;

/**
 * Immutable evidence record for capability execution.
 *
 * This is the canonical CHP evidence structure that must be
 * faithfully serialized/deserialized across language boundaries.
 */
export interface Evidence {
  /** Unique identifier for this evidence */
  evidence_id: string;

  /** Type of evidence (from EvidenceType) */
  evidence_type: EvidenceType;

  /** The capability that produced this evidence */
  capability_id: string;

  /** ISO-8601 timestamp when the evidence was created */
  timestamp: string;

  /** The subject (user/agent) that triggered execution */
  subject_id?: string | null;

  /** Links related evidence across executions */
  correlation_id?: string | null;

  /** Trust level of this evidence */
  assurance_tier: AssuranceTier;

  /** Additional context-specific data */
  payload: Record<string, unknown>;

  /** W3C Trace Context trace ID for distributed tracing */
  trace_id?: string | null;
}

/**
 * Create a new evidence record.
 *
 * @param params - Evidence creation parameters
 * @returns A new Evidence object
 */
export function createEvidence(params: {
  evidence_type: EvidenceType;
  capability_id: string;
  subject_id?: string | null;
  correlation_id?: string | null;
  assurance_tier?: AssuranceTier;
  payload?: Record<string, unknown>;
  trace_id?: string | null;
}): Evidence {
  return {
    evidence_id: crypto.randomUUID(),
    evidence_type: params.evidence_type,
    capability_id: params.capability_id,
    timestamp: new Date().toISOString(),
    subject_id: params.subject_id ?? null,
    correlation_id: params.correlation_id ?? null,
    assurance_tier: params.assurance_tier ?? "S1",
    payload: params.payload ?? {},
    trace_id: params.trace_id ?? null,
  };
}

/**
 * Validate that an object conforms to the Evidence interface.
 */
export function isEvidence(obj: unknown): obj is Evidence {
  if (typeof obj !== "object" || obj === null) return false;

  const e = obj as Record<string, unknown>;
  return (
    typeof e.evidence_id === "string" &&
    typeof e.evidence_type === "string" &&
    typeof e.capability_id === "string" &&
    typeof e.timestamp === "string" &&
    typeof e.assurance_tier === "string" &&
    typeof e.payload === "object"
  );
}
