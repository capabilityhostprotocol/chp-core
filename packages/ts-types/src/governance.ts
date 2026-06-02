/**
 * Governance Types
 *
 * Governance layer types for capability execution control.
 * These determine how governance violations are handled.
 *
 * @module governance
 */

import type { AssuranceTier } from "./assurance.js";
import type { RiskClass } from "./risk.js";
import type { DeclaredInvariant } from "./invariants.js";
import type { SubjectContext } from "./context.js";
import type { Evidence, EvidenceType } from "./evidence.js";
import { createEvidence } from "./evidence.js";

/**
 * Mode of governance enforcement.
 *
 * Determines how governance violations are handled.
 *
 * - ENFORCE: Violations block execution (production)
 * - AUDIT: Violations are logged but allowed (testing)
 * - DISABLED: No governance checks (development only)
 * - SHADOW: Parallel check without blocking (migration)
 */
export type GovernanceMode = "enforce" | "audit" | "disabled" | "shadow";

/**
 * Governance modes as a const array.
 */
export const GOVERNANCE_MODES = [
  "enforce",
  "audit",
  "disabled",
  "shadow",
] as const;

/**
 * Check if a governance mode blocks execution on violations.
 */
export function blocksExecution(mode: GovernanceMode): boolean {
  return mode === "enforce";
}

/**
 * Check if a governance mode emits evidence.
 */
export function emitsEvidence(mode: GovernanceMode): boolean {
  return mode !== "disabled";
}

/**
 * Execution context for governed capabilities.
 *
 * Provides access to subject information, governance state, evidence emission,
 * and execution metadata during capability execution.
 */
export interface GovernedContext {
  /** Unique ID for this invocation */
  invocation_id: string;

  /** The capability being invoked */
  capability_id: string;

  /** The subject (user/agent) invoking */
  subject: SubjectContext;

  /** For linking related invocations */
  correlation_id: string;

  /** W3C Trace Context trace ID */
  trace_id: string | null;

  /** Active enforcement mode */
  governance_mode: GovernanceMode;

  /** Risk classification of the capability */
  risk_class: RiskClass;

  /** Required assurance tier */
  minimum_tier: AssuranceTier;

  /** Active invariants */
  invariants: DeclaredInvariant[];

  /** Evidence emitted during execution */
  evidence: Evidence[];

  /** Additional context data */
  metadata: Record<string, unknown>;

  /** ISO-8601 timestamp when context was created */
  started_at: string;
}

/**
 * Create a new governed context.
 */
export function createGovernedContext(params: {
  capability_id: string;
  subject: SubjectContext;
  governance_mode?: GovernanceMode;
  risk_class?: RiskClass;
  minimum_tier?: AssuranceTier;
  correlation_id?: string | null;
  trace_id?: string | null;
  invariants?: DeclaredInvariant[];
  metadata?: Record<string, unknown>;
}): GovernedContext {
  return {
    invocation_id: crypto.randomUUID(),
    capability_id: params.capability_id,
    subject: params.subject,
    correlation_id: params.correlation_id ?? crypto.randomUUID(),
    trace_id: params.trace_id ?? null,
    governance_mode: params.governance_mode ?? "enforce",
    risk_class: params.risk_class ?? "medium",
    minimum_tier: params.minimum_tier ?? "S1",
    invariants: params.invariants ?? [],
    evidence: [],
    metadata: params.metadata ?? {},
    started_at: new Date().toISOString(),
  };
}

/**
 * Emit evidence within a governed context.
 * Mutates the context by appending to evidence array.
 */
export function emitEvidence(
  ctx: GovernedContext,
  evidence_type: EvidenceType,
  payload?: Record<string, unknown>,
  assurance_tier?: AssuranceTier
): Evidence {
  const evidence = createEvidence({
    evidence_type,
    capability_id: ctx.capability_id,
    subject_id: ctx.subject.subject_id,
    correlation_id: ctx.correlation_id,
    assurance_tier: assurance_tier ?? ctx.minimum_tier,
    payload: payload ?? {},
    trace_id: ctx.trace_id,
  });
  ctx.evidence.push(evidence);
  return evidence;
}

/**
 * Create a child context for invoking another capability.
 * Maintains correlation and trace context.
 */
export function createChildContext(
  parent: GovernedContext,
  capability_id: string
): GovernedContext {
  return {
    invocation_id: crypto.randomUUID(),
    capability_id,
    subject: parent.subject,
    correlation_id: parent.correlation_id,
    trace_id: parent.trace_id,
    governance_mode: parent.governance_mode,
    risk_class: parent.risk_class,
    minimum_tier: parent.minimum_tier,
    invariants: [],
    evidence: [],
    metadata: {
      ...parent.metadata,
      parent_invocation_id: parent.invocation_id,
    },
    started_at: new Date().toISOString(),
  };
}

/**
 * Calculate elapsed time in milliseconds.
 */
export function elapsedMs(ctx: GovernedContext): number {
  const started = new Date(ctx.started_at).getTime();
  return Date.now() - started;
}

/**
 * Configuration for governance behavior.
 */
export interface GovernanceConfig {
  /** Default enforcement mode */
  default_mode: GovernanceMode;

  /** Whether a subject is always required */
  require_subject: boolean;

  /** Whether to emit evidence */
  emit_evidence: boolean;

  /** Whether to emit evidence for denials */
  audit_denials: boolean;

  /** Default assurance tier */
  default_tier: AssuranceTier;
}

/**
 * Create default governance configuration.
 */
export function createGovernanceConfig(
  overrides?: Partial<GovernanceConfig>
): GovernanceConfig {
  return {
    default_mode: "enforce",
    require_subject: true,
    emit_evidence: true,
    audit_denials: true,
    default_tier: "S1",
    ...overrides,
  };
}

/**
 * Development environment configuration.
 */
export const DEVELOPMENT_CONFIG: GovernanceConfig = {
  default_mode: "audit",
  require_subject: false,
  emit_evidence: true,
  audit_denials: true,
  default_tier: "S1",
};

/**
 * Production environment configuration.
 */
export const PRODUCTION_CONFIG: GovernanceConfig = {
  default_mode: "enforce",
  require_subject: true,
  emit_evidence: true,
  audit_denials: true,
  default_tier: "S2",
};

/**
 * Testing environment configuration.
 */
export const TESTING_CONFIG: GovernanceConfig = {
  default_mode: "disabled",
  require_subject: false,
  emit_evidence: false,
  audit_denials: false,
  default_tier: "S1",
};
