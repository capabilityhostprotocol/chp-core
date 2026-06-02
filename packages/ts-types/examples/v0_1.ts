import {
  CHP_V0_1_CORE_EVIDENCE_TYPES,
  CHP_V0_1_OUTCOMES,
  capabilityUri,
  type CapabilityDescriptor,
  type ExecutionEvidence,
  type HostDescriptor,
  type InvocationEnvelope,
  type InvocationResult,
  type ReplayResult,
} from "../src/index.js";

const capability: CapabilityDescriptor = {
  id: "example.search_information",
  version: "0.1.0",
  description: "Search for information.",
  modes: ["sync"],
  emits: [...CHP_V0_1_CORE_EVIDENCE_TYPES],
  input_schema: {
    type: "object",
    properties: {
      query: { type: "string" },
    },
    required: ["query"],
  },
};

const host: HostDescriptor = {
  id: "ts-example-host",
  version: "0.1.0",
  protocol_version: "0.1",
  kind: "local",
  capabilities: [{ ...capability, capability_uri: capabilityUri(capability) }],
  evidence: { store: "memory", append_only: true },
};

const envelope: InvocationEnvelope = {
  invocation_id: "inv_example",
  capability_id: capability.id,
  version: capability.version,
  mode: "sync",
  correlation: { correlation_id: "corr_example" },
  subject: { id: "developer", type: "user" },
  payload: { query: "CHP vs MCP" },
  requested_at: new Date().toISOString(),
};

const started: ExecutionEvidence = {
  event_id: "evt_started",
  event_type: "execution_started",
  invocation_id: envelope.invocation_id,
  capability_id: capability.id,
  capability_version: capability.version,
  host_id: host.id,
  correlation: envelope.correlation,
  timestamp: new Date().toISOString(),
  sequence: 1,
  outcome: null,
  payload: {},
  redacted: true,
  assurance: { level: "S1", evidence_policy: "local-append-only", notes: [] },
};

const result: InvocationResult = {
  invocation_id: envelope.invocation_id,
  capability_id: capability.id,
  capability_version: capability.version,
  correlation: envelope.correlation,
  outcome: "success",
  success: true,
  data: { matches: [] },
  evidence_ids: [started.event_id],
  completed_at: new Date().toISOString(),
};

const replay: ReplayResult = {
  correlation_id: envelope.correlation.correlation_id,
  events: [started],
  event_count: 1,
  replayed_at: new Date().toISOString(),
};

if (!CHP_V0_1_OUTCOMES.includes(result.outcome)) {
  throw new Error(`Unexpected outcome: ${result.outcome}`);
}

console.log({
  capability_uri: capabilityUri(capability),
  host_id: host.id,
  replayed_events: replay.event_count,
});
