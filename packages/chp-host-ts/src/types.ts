/** Internal host types. Lean by design — the host is a conformance instrument. */

import type { JsonValue, EvidenceEvent } from '@capabilityhostprotocol/sdk';

export type { JsonValue, EvidenceEvent };
export type Outcome = 'success' | 'failure' | 'denied' | 'skipped';
export type RiskTier = 'low' | 'medium' | 'high' | 'critical';

export interface AutonomyProfile {
  tier?: string;
  action_limit?: number | null;
  spend_limit?: number | null;
  spend_units?: number;
  rollback_policy?: string;
}

export interface Invariant {
  id: string;
  kind: string;
  enforcement: string;
  parameters?: Record<string, JsonValue>;
  failure_behavior?: string;
}

export interface CapabilityDescriptor {
  id: string;
  version: string;
  description?: string;
  modes?: string[];
  risk?: RiskTier;
  autonomy?: AutonomyProfile | null;
  invariants?: Invariant[];
  input_schema?: JsonValue | null;
  output_schema?: JsonValue | null;
  enabled?: boolean;
  /** OPTIONAL policy surface (proposal 0034): `allowed_actors` restricts which
   * actors may invoke this capability. Mirrors the Python PolicyDescriptor. */
  policy?: { allowed_actors?: string[]; [k: string]: JsonValue | undefined } | null;
  /** Declared execution timeout in seconds — host-enforced (proposal 0038). */
  timeout_s?: number | null;
  /** Advisory retry policy a caller/gateway MAY honor (proposal 0038). */
  retry?: { max_attempts?: number; backoff_s?: number; retry_on?: string[] } | null;
}

export interface Correlation {
  correlation_id: string;
  causation_id?: string | null;
  [k: string]: JsonValue | undefined;
}

export interface InvocationEnvelope {
  capability_id: string;
  payload?: JsonValue;
  version?: string | null;
  /** OPTIONAL capability-version range (§1.1, proposal 0028): a semver range the
   * resolved capability's version must satisfy, else capability_version_unsupported. */
  requested_capability_version?: string | null;
  invocation_id?: string;
  mode?: string;
  correlation?: Correlation;
  subject?: JsonValue;
  /** OPTIONAL presented authority (chp-v0.2.md §10) — a principal-signed
   * mandate the host verifies before executing. Absent = today's behavior. */
  mandate?: Record<string, JsonValue> | null;
  /** OPTIONAL first-class actor (chp-application-contract.md §3.1, proposal 0034):
   * a structured, caller-asserted identity driving per-actor policy. Absent =
   * today's behavior (omit-when-absent → byte-identical). */
  actor?: Record<string, JsonValue> | null;
  /** OPTIONAL approver-signed grant (chp-v0.2.md §19, proposal 0037): a
   * chp-approval-grant-v1 authorizing this invocation to resume past an
   * approval_required gate. Absent = today's behavior. */
  approval_ref?: Record<string, JsonValue> | null;
  /** OPTIONAL output-shape requirement (chp-v0.2.md §1.1, proposal 0029): when
   * true, a result violating the capability's output_schema is DENIED
   * (output_schema_validation_failed) instead of the default validate-and-warn. */
  require_output_schema?: boolean;
}

export interface DenialReason {
  code: string;
  message: string;
  retryable?: boolean;
  invariant_id?: string | null;
  details?: JsonValue;
}

export interface InvocationResult {
  invocation_id: string;
  capability_id: string;
  capability_version?: string;
  correlation: Correlation;
  outcome: Outcome;
  success: boolean;
  data?: JsonValue;
  error?: JsonValue;
  denial?: DenialReason | null;
  evidence_ids: string[];
  started_at?: string;
  completed_at?: string;
  /** Idempotent replay marker (spec §13): present (true) only when this
   * result was served from the recorded-result cache. */
  replayed?: boolean;
}

export interface Ctx {
  envelope: InvocationEnvelope;
  emit(eventType: string, payload: JsonValue, outcome?: string | null): EvidenceEvent;
  /** Correlation for work caused by this invocation (causal edge across hosts). */
  childCorrelation(): Correlation;
}

/** Terminal sentinel a STREAMING handler yields last (async generators cannot
 * return values portably): its `data` becomes the InvocationResult's data.
 * Internal to the host — never a wire object (the terminal SSE frame carries
 * a standard InvocationResult). Python parity: `chp_core.types.StreamResult`. */
export class StreamResult {
  constructor(readonly data: JsonValue) {}
}

export type Handler = (ctx: Ctx, payload: JsonValue) =>
  JsonValue | Promise<JsonValue> | AsyncGenerator<JsonValue | StreamResult, void, unknown>;

/** The policy decision vocabulary (chp-governance-v0.2.md §2, proposal 0036). */
export type PolicyDecision =
  | 'allow'
  | 'deny'
  | 'requires_approval'
  | 'requires_escalation'
  | 'requires_more_evidence'
  | 'sandbox_only';

export interface PolicyBlockPattern {
  capability_id: string;
  field: string;
  pattern: string;
  reason?: string;
  /** The decision this rule renders when it matches (default 'deny'). */
  decision?: PolicyDecision;
}

export interface PolicyConfig {
  allowed_capability_ids?: string[];
  block_capability_ids?: string[];
  max_risk_tier?: RiskTier | null;
  audit_only?: boolean;
  /** Pattern rules that may render any decision in the vocabulary (proposal 0036). */
  block_patterns?: PolicyBlockPattern[];
  /** Policy version, threaded into every decision record (proposal 0036). */
  version?: string;
}
