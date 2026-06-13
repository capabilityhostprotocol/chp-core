/**
 * CHP v0.1 protocol types.
 *
 * These interfaces mirror the JSON Schemas in the repository root `schemas/`
 * directory. They are intentionally transport-neutral and do not depend on the
 * older mesh/governance TypeScript model in this package.
 */

export const CHP_V0_1_VERSION = "0.1" as const;

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export type CapabilityRisk = "low" | "medium" | "high" | "critical";
export type ChpV01InvocationMode = "sync" | "async" | "stream" | "fire_and_forget";
export type ChpV01ExecutionOutcome = "success" | "failure" | "denied" | "skipped";
export type AssuranceLevel = "S1" | "S2" | "S3";
export type InvariantEnforcement = "declarative" | "host" | "runtime";
export type InvariantFailureBehavior = "deny" | "warn" | "degrade";

export const CHP_V0_1_OUTCOMES = [
  "success",
  "failure",
  "denied",
  "skipped",
] as const satisfies readonly ChpV01ExecutionOutcome[];

export const CHP_V0_1_CORE_EVIDENCE_TYPES = [
  "execution_started",
  "execution_completed",
  "execution_failed",
  "execution_denied",
  "execution_skipped",
] as const;

export interface AssuranceMetadata {
  level: AssuranceLevel;
  evidence_policy?: string;
  notes?: string[];
}

export interface InvariantDescriptor {
  id: string;
  kind: string;
  description?: string;
  enforcement?: InvariantEnforcement;
  failure_behavior?: InvariantFailureBehavior;
  parameters?: JsonObject;
}

export interface CapabilityDescriptor {
  id: string;
  version: string;
  capability_uri?: string;
  description: string;
  modes: ChpV01InvocationMode[];
  input_schema?: JsonObject;
  output_schema?: JsonObject;
  invariants?: InvariantDescriptor[];
  emits: string[];
  owner?: string | null;
  tags?: string[];
  risk?: CapabilityRisk;
  assurance?: AssuranceMetadata;
  metadata?: JsonObject;
}

export interface HostDescriptor {
  id: string;
  version: string;
  protocol_version: typeof CHP_V0_1_VERSION;
  kind: string;
  capabilities: CapabilityDescriptor[];
  evidence: {
    store: string;
    append_only: boolean;
    [key: string]: JsonValue;
  };
  metadata?: JsonObject;
}

export interface CorrelationContext {
  correlation_id: string;
  causation_id?: string | null;
  parent_correlation_id?: string | null;
  trace_id?: string | null;
  baggage?: Record<string, JsonPrimitive>;
}

export interface InvocationEnvelope {
  invocation_id: string;
  capability_id: string;
  version?: string | null;
  mode: ChpV01InvocationMode;
  correlation: CorrelationContext;
  subject: JsonObject;
  payload: JsonObject;
  requested_at: string;
  metadata?: JsonObject;
}

export interface DenialReason {
  code: string;
  message: string;
  invariant_id?: string | null;
  retryable: boolean;
  details?: JsonObject;
}

export interface InvocationResult {
  invocation_id: string;
  capability_id: string;
  capability_version?: string | null;
  correlation: CorrelationContext;
  outcome: ChpV01ExecutionOutcome;
  success: boolean;
  data?: JsonValue;
  error?: JsonObject | null;
  denial?: DenialReason | null;
  evidence_ids: string[];
  started_at?: string | null;
  completed_at: string;
}

export interface ExecutionEvidence {
  event_id: string;
  event_type: string;
  invocation_id: string;
  capability_id: string;
  capability_version?: string | null;
  host_id: string;
  correlation: CorrelationContext;
  timestamp: string;
  sequence: number;
  outcome?: ChpV01ExecutionOutcome | null;
  payload: JsonObject;
  redacted: boolean;
  error?: JsonObject | null;
  denial?: DenialReason | null;
  assurance: AssuranceMetadata;
}

export interface ReplayQuery {
  correlation_id: string;
  limit?: number | null;
  since_sequence?: number | null;
  include_payloads?: boolean;
}

export interface ReplayResult {
  correlation_id: string;
  events: ExecutionEvidence[];
  event_count: number;
  replayed_at: string;
}

export function capabilityUri(descriptor: Pick<CapabilityDescriptor, "id" | "version">): string {
  return `${descriptor.id}:${descriptor.version}`;
}

export function isChpV01Outcome(value: string): value is ChpV01ExecutionOutcome {
  return (CHP_V0_1_OUTCOMES as readonly string[]).includes(value);
}
