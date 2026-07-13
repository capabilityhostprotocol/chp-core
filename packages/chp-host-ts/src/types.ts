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
  invocation_id?: string;
  mode?: string;
  correlation?: Correlation;
  subject?: JsonValue;
  /** OPTIONAL presented authority (chp-v0.2.md §10) — a principal-signed
   * mandate the host verifies before executing. Absent = today's behavior. */
  mandate?: Record<string, JsonValue> | null;
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

export interface PolicyConfig {
  allowed_capability_ids?: string[];
  block_capability_ids?: string[];
  max_risk_tier?: RiskTier | null;
  audit_only?: boolean;
}
