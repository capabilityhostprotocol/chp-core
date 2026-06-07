/**
 * CHP v0.2 protocol types.
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

export const CHP_AGENTIC_EVIDENCE_TYPES = [
  "tool_use",
  "tool_use_requested",
  "session_completed",
  "session_spawn",
] as const;

export const CHP_INCIDENT_EVIDENCE_TYPES = [
  "incident_opened",
  "incident_escalated",
  "incident_remediation_applied",
  "incident_resolved",
  "incident_closed",
  "incident_trigger_fired",
] as const;

export type IncidentSeverity = "P1" | "P2" | "P3" | "P4";
export type IncidentStatus = "open" | "investigating" | "escalated" | "resolved" | "closed";
export type RemediationActionType = "auto" | "manual" | "escalate";

export interface IncidentTrigger {
  pattern: string;
  threshold: number;
  window_seconds: number;
}

export interface Incident {
  incident_id: string;
  title: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  trigger?: IncidentTrigger | null;
  correlation_ids: string[];
  detected_at: string;
  resolved_at?: string | null;
  timeline: JsonObject[];
}

export interface RemediationAction {
  action_id: string;
  incident_id: string;
  action_type: RemediationActionType;
  description: string;
  executed_at: string;
  outcome?: string | null;
}

export const CHP_SAFETY_EVIDENCE_TYPES = [
  "safety_assessment_started",
  "safety_assessment_completed",
  "safety_guardrail_triggered",
  "safety_action_blocked",
  "safety_action_approved",
] as const;

export const CHP_COMPLIANCE_EVIDENCE_TYPES = [
  "retention_policy_applied",
  "evidence_purged",
  "evidence_redacted",
  "compliance_report_generated",
] as const;

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type SafetyRecommendation = "allow" | "warn" | "require_approval" | "block";

export interface RiskAssessment {
  level: RiskLevel;
  score: number;
  factors: string[];
  recommendation: SafetyRecommendation;
  assessed_at: string;
}

export interface GuardrailDefinition {
  id: string;
  capability_id_pattern: string;
  max_risk_level: RiskLevel;
  requires_human_for: string[];
}

export interface SafetyReport {
  report_id: string;
  capability_id: string;
  payload_hash: string;
  assessment: RiskAssessment;
  guardrails_evaluated: string[];
  approved: boolean;
  block_reason?: string | null;
  generated_at: string;
}

export interface RetentionPolicy {
  policy_id: string;
  retain_days: number;
  applies_to: string[];
  redact_payload_after_days?: number | null;
}

export interface ComplianceReport {
  report_id: string;
  policy_ids: string[];
  store_path: string;
  events_inspected: number;
  events_purged: number;
  events_redacted: number;
  generated_at: string;
}

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

export interface CostHint {
  token_estimate?: number | null;
  latency_ms_p50?: number | null;
  idempotent?: boolean;
}

export type BlastRadius = "local" | "session" | "user" | "system";

export interface SafetyHint {
  reversible?: boolean;
  destructive?: boolean;
  requires_human_review?: boolean;
  blast_radius?: BlastRadius;
}

export type StateMachineStatus = "queued" | "running" | "blocked" | "done" | "failed" | "cancelled";

export interface StateMachineDefinition {
  states: string[];
  transitions: Record<string, string[]>;
  initial_state: string;
  terminal_states: string[];
}

export interface StateMachineRecord {
  machine_id: string;
  name: string;
  definition: StateMachineDefinition;
  current_state: string;
  status: StateMachineStatus;
  context: JsonObject;
  created_at: string;
  updated_at: string;
  history: JsonObject[];
}

export interface StateMachineTransitionResult {
  machine_id: string;
  from_state: string;
  to_state: string;
  event: string;
  allowed: boolean;
  reason?: string | null;
  updated_at: string;
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
  depends_on?: string[] | null;
  cost_hint?: CostHint | null;
  safety_hint?: SafetyHint | null;
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

export interface ToolUseEvidence extends ExecutionEvidence {
  event_type: "tool_use";
  payload: {
    tool_name: string;
    cwd?: string;
    tool_input?: JsonObject;
    tool_output_preview?: string;
    exit_code?: number | null;
  };
}

export interface PreToolEvidence extends ExecutionEvidence {
  event_type: "tool_use_requested";
  payload: {
    tool_name: string;
    cwd?: string;
    tool_input?: JsonObject;
    blocked: boolean;
    block_reason?: string | null;
  };
}

export interface SessionEvidence extends ExecutionEvidence {
  event_type: "session_completed";
  payload: {
    tool_count: number;
    transcript_path?: string;
  };
}

export interface SessionSpawnEvidence extends ExecutionEvidence {
  event_type: "session_spawn";
  payload: {
    parent_session_id: string;
    child_session_id: string;
    tool_name: string;
  };
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
