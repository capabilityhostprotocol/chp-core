import type { JsonObject } from "@capabilityhostprotocol/types";
import { SQLiteEvidenceStore, type EvidenceEvent } from "./store.js";
import { newId, utcNow } from "./session.js";

export type CapabilityRisk = "low" | "medium" | "high" | "critical";

export interface RuntimeCapabilityDescriptor {
  id: string;
  version: string;
  description?: string;
  risk?: CapabilityRisk;
  modes?: string[];
}

export type CapabilityHandler = (
  ctx: CapabilityExecutionContext,
  payload: JsonObject
) => Promise<JsonObject | void> | JsonObject | void;

interface RegisteredCapability {
  descriptor: RuntimeCapabilityDescriptor;
  handler: CapabilityHandler;
  enabled: boolean;
}

export interface InvokeOptions {
  correlationId?: string;
  version?: string;
  mode?: string;
}

export interface InvocationResult {
  invocation_id: string;
  capability_id: string;
  capability_version: string | null;
  correlation_id: string;
  outcome: "success" | "failure" | "denied" | "skipped";
  success: boolean;
  data: JsonObject | null;
  error: JsonObject | null;
  denial: JsonObject | null;
  evidence_ids: string[];
  started_at: string;
  completed_at: string;
}

export class CapabilityExecutionContext {
  private _evidenceIds: string[] = [];

  constructor(
    private _host: LocalCapabilityHost,
    private _envelope: {
      invocation_id: string;
      capability_id: string;
      capability_version: string | null;
      correlation_id: string;
    }
  ) {}

  get correlationId(): string {
    return this._envelope.correlation_id;
  }

  emit(
    eventType: string,
    payload: JsonObject = {},
    opts: { outcome?: string; redacted?: boolean } = {}
  ): EvidenceEvent {
    const event = this._host.emitEvidence(eventType, this._envelope, payload, opts);
    this._evidenceIds.push(event.event_id);
    return event;
  }

  replay(correlationId?: string): JsonObject[] {
    return this._host.replay(correlationId ?? this.correlationId);
  }

  get evidenceIds(): string[] {
    return [...this._evidenceIds];
  }
}

export class LocalCapabilityHost {
  private _capabilities = new Map<string, RegisteredCapability>();

  constructor(
    public readonly hostId: string = "local-chp-host",
    private store: SQLiteEvidenceStore = new SQLiteEvidenceStore()
  ) {}

  register(descriptor: RuntimeCapabilityDescriptor, handler: CapabilityHandler): void {
    const uri = `${descriptor.id}:${descriptor.version}`;
    this._capabilities.set(uri, {
      descriptor: { modes: ["sync"], ...descriptor },
      handler,
      enabled: true,
    });
  }

  disable(capabilityId: string): void {
    for (const [uri, entry] of this._capabilities) {
      if (uri.startsWith(`${capabilityId}:`)) {
        entry.enabled = false;
      }
    }
  }

  async invoke(
    capabilityId: string,
    payload: JsonObject = {},
    opts: InvokeOptions = {}
  ): Promise<InvocationResult> {
    const invocationId = newId("inv");
    const correlationId = opts.correlationId ?? newId("corr");
    const envelope = {
      invocation_id: invocationId,
      capability_id: capabilityId,
      capability_version: opts.version ?? null,
      correlation_id: correlationId,
    };

    const entry = this._resolve(capabilityId, opts.version);
    if (!entry) {
      return this._deny(envelope, {
        code: "capability_not_found",
        message: `Capability not found: ${capabilityId}`,
        retryable: false,
      });
    }

    if (!entry.enabled) {
      return this._skip(envelope, {
        code: "capability_disabled",
        message: `Capability disabled: ${capabilityId}`,
      });
    }

    const started = this.emitEvidence("execution_started", envelope, {
      capability_uri: `${entry.descriptor.id}:${entry.descriptor.version}`,
    });
    const ctx = new CapabilityExecutionContext(this, {
      ...envelope,
      capability_version: entry.descriptor.version,
    });

    try {
      const raw = entry.handler(ctx, payload);
      const data = raw instanceof Promise ? await raw : raw;
      const completed = this.emitEvidence(
        "execution_completed",
        envelope,
        { capability_uri: `${entry.descriptor.id}:${entry.descriptor.version}` },
        { outcome: "success" }
      );
      return {
        invocation_id: invocationId,
        capability_id: entry.descriptor.id,
        capability_version: entry.descriptor.version,
        correlation_id: correlationId,
        outcome: "success",
        success: true,
        data: (data as JsonObject | null | undefined) ?? null,
        error: null,
        denial: null,
        evidence_ids: [started.event_id, ...ctx.evidenceIds, completed.event_id],
        started_at: started.timestamp,
        completed_at: utcNow(),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const failed = this.emitEvidence(
        "execution_failed",
        envelope,
        { capability_uri: `${entry.descriptor.id}:${entry.descriptor.version}` },
        { outcome: "failure" }
      );
      return {
        invocation_id: invocationId,
        capability_id: entry.descriptor.id,
        capability_version: entry.descriptor.version,
        correlation_id: correlationId,
        outcome: "failure",
        success: false,
        data: null,
        error: { type: err instanceof Error ? err.constructor.name : "Error", message },
        denial: null,
        evidence_ids: [started.event_id, ...ctx.evidenceIds, failed.event_id],
        started_at: started.timestamp,
        completed_at: utcNow(),
      };
    }
  }

  replay(correlationId: string): JsonObject[] {
    return this.store.byCorrelation(correlationId);
  }

  verifyChain(correlationId: string) {
    return this.store.verifyChain(correlationId);
  }

  evidenceCount(correlationId: string): number {
    return this.store.countByCorrelation(correlationId);
  }

  listCorrelations(limit = 50): string[] {
    return this.store.listCorrelations(limit);
  }

  close(): void {
    this.store.close();
  }

  emitEvidence(
    eventType: string,
    envelope: {
      invocation_id: string;
      capability_id: string;
      capability_version?: string | null;
      correlation_id: string;
    },
    payload: JsonObject = {},
    opts: { outcome?: string; redacted?: boolean } = {}
  ): EvidenceEvent {
    const event: EvidenceEvent = {
      event_id: newId("evt"),
      event_type: eventType,
      invocation_id: envelope.invocation_id,
      capability_id: envelope.capability_id,
      capability_version: envelope.capability_version ?? null,
      host_id: this.hostId,
      correlation: { correlation_id: envelope.correlation_id },
      timestamp: utcNow(),
      sequence: 0,
      outcome: opts.outcome ?? null,
      payload,
      redacted: opts.redacted ?? false,
      error: null,
      denial: null,
      assurance: { level: "S1", evidence_policy: "local-append-only", notes: [] },
    };
    return this.store.append(event);
  }

  private _resolve(capabilityId: string, version?: string): RegisteredCapability | null {
    if (version) {
      return this._capabilities.get(`${capabilityId}:${version}`) ?? null;
    }
    const matches = [...this._capabilities.entries()].filter(([uri]) =>
      uri.startsWith(`${capabilityId}:`)
    );
    return matches.length === 1 ? matches[0][1] : null;
  }

  private _deny(
    envelope: { invocation_id: string; capability_id: string; correlation_id: string },
    denial: { code: string; message: string; retryable: boolean }
  ): InvocationResult {
    const denied = this.emitEvidence(
      "execution_denied",
      { ...envelope, capability_version: null },
      { reason: denial.code },
      { outcome: "denied" }
    );
    return {
      invocation_id: envelope.invocation_id,
      capability_id: envelope.capability_id,
      capability_version: null,
      correlation_id: envelope.correlation_id,
      outcome: "denied",
      success: false,
      data: null,
      error: null,
      denial,
      evidence_ids: [denied.event_id],
      started_at: denied.timestamp,
      completed_at: utcNow(),
    };
  }

  private _skip(
    envelope: { invocation_id: string; capability_id: string; correlation_id: string },
    reason: { code: string; message: string }
  ): InvocationResult {
    const skipped = this.emitEvidence(
      "execution_skipped",
      { ...envelope, capability_version: null },
      { reason: reason.code },
      { outcome: "skipped" }
    );
    return {
      invocation_id: envelope.invocation_id,
      capability_id: envelope.capability_id,
      capability_version: null,
      correlation_id: envelope.correlation_id,
      outcome: "skipped",
      success: false,
      data: null,
      error: reason as JsonObject,
      denial: null,
      evidence_ids: [skipped.event_id],
      started_at: skipped.timestamp,
      completed_at: utcNow(),
    };
  }
}
