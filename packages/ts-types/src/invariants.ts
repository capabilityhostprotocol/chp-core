/**
 * Invariant Types
 *
 * Invariants are constraints that must hold for a capability to execute.
 * They are checked at the invocation boundary or during execution.
 *
 * @module invariants
 */

/**
 * Classification of invariant constraints.
 *
 * Determines when and how invariants are checked and enforced.
 *
 * - STRUCTURAL: Code/schema correctness (compile-time checkable)
 * - ENVIRONMENTAL: Runtime environment constraints
 * - DATA: Input/output data validation
 * - TEMPORAL: Time-based constraints (deadlines, ordering)
 * - CAUSAL: Dependency and causality constraints
 */
export type InvariantClass =
  | "structural"
  | "environmental"
  | "data"
  | "temporal"
  | "causal";

/**
 * Invariant classes as a const array.
 */
export const INVARIANT_CLASSES = [
  "structural",
  "environmental",
  "data",
  "temporal",
  "causal",
] as const;

/**
 * Who is responsible for enforcing an invariant.
 *
 * - HOST: The capability host enforces at invocation boundary
 * - RUNTIME: Enforced during capability execution
 * - SUBSTRATE: Enforced by underlying infrastructure (e.g., Zenoh)
 * - DECLARATIVE: Declared but not actively enforced
 */
export type EnforcementResponsibility =
  | "host"
  | "runtime"
  | "substrate"
  | "declarative";

/**
 * What happens when an invariant fails.
 *
 * - DENY: Prevent execution entirely
 * - ABORT: Stop execution and rollback if possible
 * - WARN: Log warning but allow execution
 * - DEGRADE: Continue with reduced assurance
 */
export type FailureBehavior = "deny" | "abort" | "warn" | "degrade";

/**
 * A declared invariant constraint for a capability.
 *
 * This is the canonical CHP invariant structure that must be
 * faithfully serialized/deserialized across language boundaries.
 */
export interface DeclaredInvariant {
  /** Unique identifier for this invariant */
  invariant_id: string;

  /** Type of invariant (structural, temporal, etc.) */
  invariant_class: InvariantClass;

  /** Who enforces this invariant */
  enforcement: EnforcementResponsibility;

  /** What happens on failure */
  failure_behavior: FailureBehavior;

  /** Human-readable description */
  description: string;

  /** Invariant-specific configuration */
  parameters: Record<string, unknown>;
}

/**
 * Create a new declared invariant.
 */
export function createDeclaredInvariant(params: {
  invariant_id: string;
  invariant_class: InvariantClass;
  enforcement?: EnforcementResponsibility;
  failure_behavior?: FailureBehavior;
  description?: string;
  parameters?: Record<string, unknown>;
}): DeclaredInvariant {
  return {
    invariant_id: params.invariant_id,
    invariant_class: params.invariant_class,
    enforcement: params.enforcement ?? "runtime",
    failure_behavior: params.failure_behavior ?? "deny",
    description: params.description ?? "",
    parameters: params.parameters ?? {},
  };
}

/**
 * Validate that an object conforms to the DeclaredInvariant interface.
 */
export function isDeclaredInvariant(obj: unknown): obj is DeclaredInvariant {
  if (typeof obj !== "object" || obj === null) return false;

  const i = obj as Record<string, unknown>;
  return (
    typeof i.invariant_id === "string" &&
    typeof i.invariant_class === "string" &&
    typeof i.enforcement === "string" &&
    typeof i.failure_behavior === "string"
  );
}
