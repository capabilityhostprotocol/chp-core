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

// ---------------------------------------------------------------------------
// Core enumerations
// ---------------------------------------------------------------------------

export type CapabilityRisk = "low" | "medium" | "high" | "critical";
export type ChpV01InvocationMode = "sync" | "async" | "stream" | "fire_and_forget";
export type ChpV01ExecutionOutcome = "success" | "failure" | "denied" | "skipped";
export type AssuranceLevel = "S1" | "S2" | "S3";
export type InvariantEnforcement = "declarative" | "host" | "runtime";
export type InvariantFailureBehavior = "deny" | "warn" | "degrade";
export type CapabilityStatus = "draft" | "experimental" | "certified" | "deprecated";
export type CapabilityIdempotency = "required" | "optional" | "not_supported";
export type AutonomyTier = "automated" | "supervised" | "approval_required" | "human_driven";
export type MemoryScope = "session" | "project" | "user";
export type RollbackPolicy = "none" | "checkpoint" | "full";
export type PlanStepStatus = "pending" | "running" | "completed" | "failed" | "skipped";
export type RetrievalType = "keyword" | "vector" | "hybrid";
export type HostLocality = "local" | "edge" | "cloud" | "hybrid" | "any";

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

// ---------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------

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

/** Declared host-side compute, storage, inference, and locality requirements. */
export interface HostRequirements {
  compute?: string | null;
  storage?: string | null;
  inference?: string | null;
  runtime?: string | null;
  network?: string | null;
  isolation?: string | null;
  locality?: HostLocality;
}

/** Structured policy surface: risk tier, auth, approval, and data classification. */
export interface PolicyDescriptor {
  risk_tier?: CapabilityRisk;
  auth_required?: boolean;
  approval_required?: boolean;
  data_classification?: string | null;
  allowed_actors?: string[];
}

// ---------------------------------------------------------------------------
// Capability & host descriptors
// ---------------------------------------------------------------------------

export interface CapabilityDescriptor {
  id: string;
  version: string;
  capability_uri?: string;
  description: string;
  name?: string | null;
  category?: string | null;
  provider?: string | null;
  status?: CapabilityStatus;
  modes: ChpV01InvocationMode[];
  input_schema?: JsonObject;
  output_schema?: JsonObject;
  idempotency?: CapabilityIdempotency;
  side_effects?: string[];
  invariants?: InvariantDescriptor[];
  emits: string[];
  owner?: string | null;
  tags?: string[];
  risk?: CapabilityRisk;
  assurance?: AssuranceMetadata;
  metadata?: JsonObject;
  host_requirements?: HostRequirements;
  policy?: PolicyDescriptor;
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
  /** OPTIONAL presented authority (chp-v0.2.md §10, additive): a
   * principal-signed, expiring, capability-scoped mandate naming the caller
   * as delegate. Omitted on the wire when absent. */
  mandate?: JsonObject;
  /** OPTIONAL first-class actor (chp-application-contract.md §3.1, proposal
   * 0034, additive): a structured, caller-asserted identity. The verified
   * `subject` stays the accountability record; `actor` enriches it and drives
   * per-actor policy. Omitted on the wire when absent. */
  actor?: JsonObject;
}

/**
 * A first-class actor identity (chp-application-contract.md §3.1, proposal 0034).
 * OPTIONAL, structured, caller-asserted identity spanning the CHP actor breadth.
 * Every field but `id` is omit-when-empty on the wire.
 */
export interface Actor {
  id: string;
  type?: 'human' | 'agent' | 'service' | 'workflow' | 'device' | 'organization';
  owner?: string;
  organization?: string;
  trust_level?: string;
  status?: string;
  credentials_ref?: string;
  authority_refs?: string[];
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
  /** True when a federated replay could not reach every member host. */
  partial?: boolean;
  /** Member hosts unreachable during a federated replay — never silently partial. */
  missing_hosts?: string[];
}

export function capabilityUri(descriptor: Pick<CapabilityDescriptor, "id" | "version">): string {
  return `${descriptor.id}:${descriptor.version}`;
}

export function isChpV01Outcome(value: string): value is ChpV01ExecutionOutcome {
  return (CHP_V0_1_OUTCOMES as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// Agent session & planning types (schemas/v0.3)
// ---------------------------------------------------------------------------

export interface AgentSessionDescriptor {
  session_id: string;
  intent: string;
  model?: string | null;
  memory_scope?: MemoryScope;
  autonomy_tier?: AutonomyTier;
  tool_manifest?: string[];
  parent_session_id?: string | null;
  metadata?: JsonObject;
}

export interface PlanStep {
  step_id: string;
  description: string;
  capability_id?: string | null;
  status?: PlanStepStatus;
  metadata?: JsonObject;
}

export interface PlanDescriptor {
  plan_id: string;
  intent: string;
  steps?: PlanStep[];
  parent_correlation_id?: string | null;
  metadata?: JsonObject;
}

export interface DelegationEnvelope {
  delegation_id: string;
  from_session: string;
  to_agent: string;
  work_parcel: string;
  acceptance_criteria?: string[];
  context_ref?: string | null;
  metadata?: JsonObject;
}

/** Autonomy control surface for a CapabilityDescriptor. */
export interface AutonomyProfile {
  tier?: AutonomyTier;
  spend_limit?: number | null;
  spend_units?: number;
  action_limit?: number | null;
  rollback_policy?: RollbackPolicy;
}

// ---------------------------------------------------------------------------
// Governance & policy types (schemas/v0.3)
// ---------------------------------------------------------------------------

export interface ApprovalDecision {
  capability_uri: string;
  decided_by?: string | null;
  note?: string | null;
  reason?: string | null;
}

export interface EvaluationResult {
  score: number;
  rubric: string;
  evaluator: string;
  evidence_refs?: string[];
  notes?: string;
  passed?: boolean | null;
}

export interface CertificationRecord {
  capability_id: string;
  /** Maturity level certified (1–7). */
  level: number;
  granted_by: string;
  certified_at: string;
  notes?: string | null;
}

// ---------------------------------------------------------------------------
// Operations types
// ---------------------------------------------------------------------------

export interface InvocationMetrics {
  capability_id: string;
  invocations: number;
  successes: number;
  failures: number;
  denied?: number;
  avg_duration_ms?: number | null;
  p50_duration_ms?: number | null;
  p95_duration_ms?: number | null;
}

export interface MemoryEntry {
  id: string;
  key: string;
  scope: MemoryScope;
  scope_id: string;
  value: JsonValue;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Evidence event payload types (schemas/v0.4)
// ---------------------------------------------------------------------------

/** Payload of domain_event_emitted evidence events. */
export interface DomainEventEmitted {
  event_id: string;
  event_type: string;
  source: string;
  /** SHA-256 hash: "sha256:<hex64>" */
  data_hash: string;
}

/** Payload of graph_entity_added evidence events. */
export interface GraphEntityAdded {
  entity_id: string;
  entity_type: string;
  label?: string | null;
}

export interface IngestionRecord {
  source_id: string;
  /** SHA-256 hash: "sha256:<hex64>" */
  content_hash: string;
  byte_count: number;
  content_type?: string;
  title?: string | null;
  uri?: string | null;
}

/** Payload of ingestion_completed evidence events. */
export interface IngestionResult {
  source_uri?: string | null;
  record_count: number;
  total_bytes: number;
  latency_ms?: number | null;
  records: IngestionRecord[];
}

export interface SourceRef {
  source_id: string;
  title?: string | null;
  score?: number | null;
  excerpt?: string | null;
  uri?: string | null;
}

/** Payload of retrieval_completed evidence events. */
export interface RetrievalResult {
  query: string;
  retrieval_type: RetrievalType;
  result_count: number;
  latency_ms?: number | null;
  top_k?: number | null;
  source_refs: SourceRef[];
}

/** Payload of transformation_completed evidence events. */
export interface TransformationResult {
  transform_type: string;
  /** SHA-256 hash: "sha256:<hex64>" */
  input_hash: string;
  /** SHA-256 hash: "sha256:<hex64>" */
  output_hash: string;
  input_byte_count: number;
  output_byte_count: number;
  latency_ms?: number | null;
}

/** Payload of workflow_step_completed evidence events. */
export interface WorkflowStepCompleted {
  workflow_id: string;
  step_id: string;
  success: boolean;
  duration_ms: number;
}
