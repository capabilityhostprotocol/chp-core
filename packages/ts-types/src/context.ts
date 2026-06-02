/**
 * Context Types
 *
 * Context types for subject (user/agent) and invocation tracking.
 * These provide the "who" and "what" for capability execution.
 *
 * @module context
 */

/**
 * Context about the subject (user/agent) invoking a capability.
 *
 * Subjects are the actors in the system - they invoke capabilities
 * and are tracked for authorization and audit purposes.
 */
export interface SubjectContext {
  /** Unique identifier for the subject */
  subject_id: string;

  /** Type of subject (user, agent, service) */
  subject_type: string;

  /** List of entitlements the subject holds */
  entitlements: string[];

  /** Additional subject-specific data */
  metadata: Record<string, unknown>;
}

/**
 * Create a new subject context.
 */
export function createSubjectContext(params: {
  subject_id: string;
  subject_type?: string;
  entitlements?: string[];
  metadata?: Record<string, unknown>;
}): SubjectContext {
  return {
    subject_id: params.subject_id,
    subject_type: params.subject_type ?? "user",
    entitlements: params.entitlements ?? [],
    metadata: params.metadata ?? {},
  };
}

/**
 * Check if a subject has a specific entitlement.
 */
export function hasEntitlement(
  subject: SubjectContext,
  entitlement: string
): boolean {
  return subject.entitlements.includes(entitlement);
}

/**
 * Context for a capability invocation.
 *
 * Provides access to subject information, correlation tracking,
 * and execution metadata during capability execution.
 */
export interface InvocationContext {
  /** Unique ID for this invocation */
  invocation_id: string;

  /** The capability being invoked */
  capability_id: string;

  /** The subject invoking the capability */
  subject: SubjectContext;

  /** For linking related invocations */
  correlation_id: string | null;

  /** W3C Trace Context trace ID */
  trace_id: string | null;

  /** If this is a child invocation */
  parent_invocation_id: string | null;

  /** ISO-8601 timestamp when the invocation started */
  timestamp: string;

  /** Additional context data */
  metadata: Record<string, unknown>;
}

/**
 * Create a new invocation context.
 */
export function createInvocationContext(params: {
  capability_id: string;
  subject: SubjectContext;
  correlation_id?: string | null;
  trace_id?: string | null;
  parent_invocation_id?: string | null;
  metadata?: Record<string, unknown>;
}): InvocationContext {
  return {
    invocation_id: crypto.randomUUID(),
    capability_id: params.capability_id,
    subject: params.subject,
    correlation_id: params.correlation_id ?? crypto.randomUUID(),
    trace_id: params.trace_id ?? null,
    parent_invocation_id: params.parent_invocation_id ?? null,
    timestamp: new Date().toISOString(),
    metadata: params.metadata ?? {},
  };
}

/**
 * Outcome of a capability execution.
 *
 * - SUCCESS: Execution completed successfully
 * - FAILURE: Execution failed with an error
 * - DENIED: Execution was denied (entitlement/invariant)
 * - TIMEOUT: Execution exceeded time limit
 * - ABORTED: Execution was aborted (e.g., circuit breaker)
 */
export type ExecutionOutcome =
  | "success"
  | "failure"
  | "denied"
  | "timeout"
  | "aborted";

/**
 * Execution outcomes as a const array.
 */
export const EXECUTION_OUTCOMES = [
  "success",
  "failure",
  "denied",
  "timeout",
  "aborted",
] as const;
