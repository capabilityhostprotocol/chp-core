/**
 * LocalCapabilityHost — the governed invocation pipeline (spec/chp-invocation-pipeline.md).
 * Gates are applied in the exact normative order; the first that fires decides the
 * outcome and stops. This is the TS peer of chp_core/host.py:ainvoke_envelope.
 */

import { randomBytes } from 'node:crypto';
import { buildAttestation, buildBundle, signBundle, verifyMandate, scopeAllows, mandateRootPrincipal, EVENT_HASH_V2, payloadCommitment, chunkSeqDigest, PROTOCOL_VERSION, versionsUpto, type EvidenceEvent, type HostKey } from '@capabilityhostprotocol/sdk';
import { InMemoryEvidenceStore } from './store.js';
import { RuleBasedSafetyEvaluator } from './safety.js';
import { StreamResult } from './types.js';
import type {
  CapabilityDescriptor, Correlation, Ctx, DenialReason, Handler,
  InvocationEnvelope, InvocationResult, JsonValue, PolicyConfig, RiskTier,
} from './types.js';

const RISK_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function isAsyncGenerator(v: unknown): v is AsyncGenerator<JsonValue | StreamResult, void, unknown> {
  return !!v && typeof (v as AsyncGenerator<unknown>)[Symbol.asyncIterator] === 'function';
}
const newId = (p: string): string => `${p}_${randomBytes(8).toString('hex')}`;
const nowIso = (): string => new Date().toISOString().replace(/\.\d+Z$/, 'Z');

/** chp-stable-v1 forbids floats in canonicalized content — string-encode at emit. */
function stringifyFloats(v: JsonValue): JsonValue {
  if (typeof v === 'number') return Number.isInteger(v) ? v : String(v);
  if (Array.isArray(v)) return v.map(stringifyFloats);
  if (v && typeof v === 'object') {
    const o: Record<string, JsonValue> = {};
    for (const [k, x] of Object.entries(v)) o[k] = stringifyFloats(x as JsonValue);
    return o;
  }
  return v;
}

interface Registered { descriptor: CapabilityDescriptor; handler: Handler; enabled: boolean; }

export class LocalCapabilityHost {
  readonly store = new InMemoryEvidenceStore();
  private readonly caps = new Map<string, Registered>();
  private readonly attestation: JsonValue | null;
  /** Received mandate revocations (§10 Revocation) — in-memory for this
   * conformance host; gate 5 consults them under the issuer-only rule. */
  readonly mandateRevocations: Record<string, JsonValue>[] = [];
  /** Recorded results for idempotent replay (§13) — serving state, never
   * evidence; in-memory for this conformance host. */
  private readonly invocationResults = new Map<string, InvocationResult>();
  /** Recorded stream chunk deltas for §13.1 replay/resume — serving state. */
  private readonly invocationChunks = new Map<string, JsonValue[]>();

  constructor(
    readonly hostId = 'ts-chp-host',
    private readonly opts: {
      policy?: PolicyConfig;
      safetyEvaluator?: RuleBasedSafetyEvaluator;
      signingKey?: HostKey;
      /** Domain anchor (spec §3 Anchors) — the trust root a never-met verifier resolves. */
      domain?: string;
    } = {},
  ) {
    // Built once — stable valid_from + anchors (never rebuilt per request).
    this.attestation = opts.signingKey
      ? buildAttestation(
          hostId, opts.signingKey, nowIso(), null,
          opts.domain ? [{ type: 'domain', domain: opts.domain }] : null,
        )
      : null;
  }

  /** Declared evidence assurance tier (chp-v0.2.md §1). */
  private assurance(): Record<string, JsonValue> {
    const k = this.opts.signingKey;
    return k
      ? {
          assurance: 'signed', key_id: k.keyId, public_key: k.publicKeyB64,
          ...(this.attestation ? { host_identity: this.attestation } : {}),
        }
      : { assurance: 'hash-chain' };
  }

  /** The public identity document served on /.well-known/chp-identity. */
  identityDoc(): Record<string, JsonValue> {
    return this.assurance();
  }

  /** Export a correlation as a bundle — signed when the host holds a key (M3). */
  exportBundle(correlationId: string): Record<string, JsonValue> {
    const events = this.store.byCorrelation(correlationId);
    const bundle = buildBundle(this.hostId, events, nowIso());
    if (!this.opts.signingKey) return bundle;
    return signBundle(bundle, this.opts.signingKey, {
      anchors: this.opts.domain ? [{ type: 'domain', domain: this.opts.domain }] : null,
    });
  }

  register(descriptor: CapabilityDescriptor, handler: Handler): void {
    this.caps.set(descriptor.id, { descriptor, handler, enabled: descriptor.enabled !== false });
  }

  discover(): Record<string, JsonValue> {
    return {
      id: this.hostId,
      version: '0.1.0',
      // This host always hash-chains (and signs when keyed) — the v0.2 surface.
      protocol_version: PROTOCOL_VERSION,
      // Wire versions this host speaks, for negotiation (§1.1, proposal 0016).
      supported_versions: versionsUpto(PROTOCOL_VERSION),
      kind: 'local',
      capabilities: [...this.caps.values()].map((c) => ({
        id: c.descriptor.id,
        version: c.descriptor.version,
        description: c.descriptor.description ?? '',
        modes: c.descriptor.modes ?? ['sync'],
        ...(c.descriptor.risk ? { risk: c.descriptor.risk } : {}),
      })),
      evidence: { store: 'memory', append_only: true },
      metadata: {},
      ...this.assurance(),
    };
  }

  replay(correlationId: string): EvidenceEvent[] {
    return this.store.byCorrelation(correlationId);
  }

  verify(correlationId: string): JsonValue {
    const r = this.store.verifyChainFor(correlationId);
    const events = this.store.byCorrelation(correlationId);
    return {
      correlation_id: correlationId,
      valid: r.valid,
      event_count: events.length,
      first_broken_sequence: r.firstBrokenSequence,
    };
  }

  private emit(
    eventType: string,
    env: InvocationEnvelope,
    payload: JsonValue,
    outcome: string | null = null,
    extra: { denial?: DenialReason; error?: JsonValue } = {},
  ): EvidenceEvent {
    // Selective disclosure (§14): new events are born under chp-event-hash-v2 —
    // the content_hash commits to sha256(payload), so this payload can later be
    // withheld from a bundle without breaking verification.
    const finalPayload = stringifyFloats(payload);
    const ev: EvidenceEvent = {
      event_id: newId('evt'),
      event_type: eventType,
      invocation_id: env.invocation_id!,
      capability_id: env.capability_id,
      host_id: this.hostId,
      correlation: env.correlation as EvidenceEvent['correlation'],
      timestamp: nowIso(),
      outcome,
      payload: finalPayload,
      hash_scheme: EVENT_HASH_V2,
      payload_commitment: payloadCommitment(finalPayload),
      ...(extra.denial ? { denial: extra.denial as unknown as JsonValue } : {}),
      ...(extra.error ? { error: extra.error } : {}),
      subject: env.subject ?? { id: 'local', type: 'user' },
    };
    return this.store.append(ev);
  }

  private result(env: InvocationEnvelope, o: Partial<InvocationResult>): InvocationResult {
    return {
      invocation_id: env.invocation_id!,
      capability_id: env.capability_id,
      correlation: env.correlation!,
      outcome: 'failure',
      success: false,
      evidence_ids: [],
      ...o,
    } as InvocationResult;
  }

  private deny(env: InvocationEnvelope, denial: DenialReason): InvocationResult {
    const e = this.emit('execution_denied', env, { reason: denial.code }, 'denied', { denial });
    return this.result(env, { outcome: 'denied', success: false, denial, evidence_ids: [e.event_id] });
  }

  /** A PROCESSED denial from outside the pipeline (e.g. a caller-key scope
   * decision at the transport layer — binding §2): normalizes the envelope,
   * emits execution_denied evidence, returns the denied result. */
  denyEnvelope(input: InvocationEnvelope, denial: DenialReason): InvocationResult {
    const env: InvocationEnvelope = {
      mode: 'sync',
      payload: {},
      subject: { id: 'local', type: 'user' },
      ...input,
      invocation_id: input.invocation_id ?? newId('inv'),
      correlation: (input.correlation as Correlation) ?? { correlation_id: newId('corr') },
    };
    return this.deny(env, denial);
  }

  private skip(env: InvocationEnvelope, code: string, message: string): InvocationResult {
    const e = this.emit('execution_skipped', env, { code, message }, 'skipped');
    return this.result(env, { outcome: 'skipped', success: false, evidence_ids: [e.event_id] });
  }

  /** Gates 1–10 shared by the sync and stream paths (Python `_prepare`
   * parity — ONE gate pipeline, no drift). Returns the normalized envelope,
   * the resolved capability, and the early result when a gate decided. */
  private prepare(input: InvocationEnvelope): {
    env: InvocationEnvelope; entry: Registered | null; early: InvocationResult | null;
  } {
    const env: InvocationEnvelope = {
      mode: 'sync',
      payload: {},
      subject: { id: 'local', type: 'user' },
      ...input,
      invocation_id: input.invocation_id ?? newId('inv'),
      correlation: (input.correlation as Correlation) ?? { correlation_id: newId('corr') },
    };
    const decided = (early: InvocationResult) => ({ env, entry: null, early });

    // Gate 0 — idempotent replay (spec §13, proposal 0008): an already-
    // recorded invocation_id replays its recorded result; nothing below runs
    // and no events are emitted. Streams replay too (§13.1, proposal 0012) —
    // ainvokeStream re-streams the recorded chunks before yielding this result.
    const recorded = this.invocationResults.get(env.invocation_id!);
    if (recorded) {
      return { env, entry: null, early: { ...recorded, replayed: true } as InvocationResult };
    }

    // Gate 1: non-empty id
    if (!env.capability_id || !env.capability_id.trim()) {
      return decided(this.deny(env, { code: 'capability_not_found', message: 'capability_id must be non-empty', retryable: false }));
    }
    // Gate 2: resolution
    const entry = this.caps.get(env.capability_id);
    if (!entry || (env.version && env.version !== entry.descriptor.version)) {
      // Teach, don't just deny: closest registered ids ride in details
      // (wire-safe — conformance asserts the code, not details).
      const wanted = env.capability_id.toLowerCase();
      const score = (id: string): number => {
        const c = id.toLowerCase();
        if (c.includes(wanted) || wanted.includes(c)) return 1000;
        let p = 0;
        while (p < c.length && p < wanted.length && c[p] === wanted[p]) p++;
        return p;
      };
      const suggestions = [...this.caps.keys()]
        .map((id) => [id, score(id)] as const)
        .filter(([, s]) => s >= 3)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([id]) => id);
      return decided(this.deny(env, {
        code: 'capability_not_found',
        message: `Capability not found: ${env.capability_id}`,
        retryable: false,
        details: { suggestions, hint: 'GET /capabilities lists every registered capability' },
      }));
    }
    const d = entry.descriptor;
    env.version = d.version;
    // Gate 3: enabled → SKIP (not deny)
    if (!entry.enabled) {
      return decided(this.skip(env, 'capability_disabled', `Capability disabled: ${d.id}:${d.version}`));
    }
    // Gate 4: mode
    const modes = d.modes ?? ['sync'];
    if (!modes.includes(env.mode!)) {
      return decided(this.deny(env, { code: 'unsupported_mode', message: `mode ${env.mode} unsupported`, retryable: false }));
    }
    // Gate 5: mandate (§10) — verify at HOST time, bind delegate to any
    // transport-verified caller, narrow to scope, rebind the subject.
    if (env.mandate) {
      const subj = (env.subject ?? {}) as Record<string, JsonValue>;
      const verifiedCaller = subj.verified ? String(subj.id ?? '') : undefined;
      const mv = verifyMandate(env.mandate, {
        atTime: nowIso(),
        revocations: this.mandateRevocations,
        ...(verifiedCaller !== undefined ? { delegateId: verifiedCaller } : {}),
      });
      if (!mv.valid) {
        return decided(this.deny(env, {
          code: 'mandate_invalid',
          message: mv.reason ?? 'mandate failed verification',
          retryable: false,
          details: { checks: mv.checks, mandate_id: env.mandate.mandate_id ?? null },
        }));
      }
      if (!scopeAllows((env.mandate.scope as JsonValue[]) ?? [], d.id)) {
        return decided(this.deny(env, {
          code: 'policy_blocked',
          message: `capability '${d.id}' is outside mandate '${String(env.mandate.mandate_id)}'s scope`,
          retryable: false,
        }));
      }
      const principal = (env.mandate.principal ?? {}) as Record<string, JsonValue>;
      env.subject = {
        id: env.mandate.delegate_id ?? null,
        type: 'mandate',
        verified: true,
        mandate_id: env.mandate.mandate_id ?? null,
        principal: principal.host_id ?? null,
        // Sub-delegation (§10, proposal 0009): the chain's ultimate authority.
        root_principal: mandateRootPrincipal(env.mandate as Record<string, JsonValue>),
      };
    }
    // Gate 6: policy
    const pd = this.checkPolicy(d);
    if (pd) return decided(this.deny(env, pd));
    // Gate 7: invariants
    const inv = this.checkInvariants(d, env);
    if (inv) return decided(this.deny(env, inv));
    // Gate 8: autonomy budget / approval
    const auto = this.checkAutonomy(d, env);
    if (auto) return decided(this.deny(env, auto));
    // Gate 9: input schema (minimal required-fields check; full JSON Schema out of scope)
    const sch = this.checkInputSchema(d, env);
    if (sch) return decided(this.deny(env, sch));
    // Gate 10: safety
    const saf = this.checkSafety(d, env);
    if (saf) return decided(this.deny(env, saf));

    return { env, entry, early: null };
  }

  private executionContext(env: InvocationEnvelope): Ctx {
    return {
      envelope: env,
      emit: (t, p, o = null) => this.emit(t, env, p, o),
      // Causal edge for work caused by this invocation — pass to remote calls
      // to extend the causal tree across hosts (chp-causal-order-v1).
      childCorrelation: () => ({ ...env.correlation!, causation_id: env.invocation_id! }),
    };
  }

  /** Record a processed result for idempotent replay (§13) — first wins. For a
   * stream (§13.1) the ordered chunk deltas are recorded too, so a retried id or
   * a Last-Event-ID reconnect can re-stream them. */
  private recordResult(result: InvocationResult, chunks?: JsonValue[]): InvocationResult {
    if (!result.replayed && !this.invocationResults.has(result.invocation_id)) {
      this.invocationResults.set(result.invocation_id, result);
      if (chunks) this.invocationChunks.set(result.invocation_id, chunks);
    }
    return result;
  }

  async ainvokeEnvelope(input: InvocationEnvelope): Promise<InvocationResult> {
    const { env, entry, early } = this.prepare(input);
    if (early) return this.recordResult(early);
    const d = entry!.descriptor;

    // Gate 11: execute
    const started = this.emit('execution_started', env, { capability_uri: `${d.id}:${d.version}` }, null);
    const ctx = this.executionContext(env);
    try {
      let data = await entry!.handler(ctx, env.payload ?? {});
      if (isAsyncGenerator(data)) {
        // A STREAMING handler invoked in sync mode: collect and return the
        // terminal StreamResult's data (graceful degrade — proposal 0006).
        let terminal: JsonValue = null;
        for await (const item of data) {
          if (item instanceof StreamResult) terminal = item.data;
        }
        data = terminal;
      }
      const done = this.emit('execution_completed', env, { capability_uri: `${d.id}:${d.version}` }, 'success');
      return this.recordResult(this.result(env, {
        outcome: 'success', success: true, capability_version: d.version,
        data: data as JsonValue, evidence_ids: [started.event_id, done.event_id], started_at: started.timestamp,
      }));
    } catch (err) {
      const failed = this.emit('execution_failed', env, { capability_uri: `${d.id}:${d.version}` }, 'failure',
        { error: { type: (err as Error).name, message: (err as Error).message } });
      return this.recordResult(this.result(env, {
        outcome: 'failure', success: false, capability_version: d.version,
        error: { type: (err as Error).name, message: (err as Error).message },
        evidence_ids: [started.event_id, failed.event_id], started_at: started.timestamp,
      }));
    }
  }

  /** Streaming invocation (proposal 0006, Python `ainvoke_stream` parity):
   * yields `{chunk}` items then finally `{result}`. The SAME gate pipeline
   * runs first (via `prepare`); a denial/skip yields the result IMMEDIATELY
   * with no prior chunks — the binding uses that to answer plain JSON
   * without committing to SSE. Evidence brackets the stream. A non-generator
   * handler degrades to a single terminal result. */
  async *ainvokeStream(input: InvocationEnvelope, resumeFrom = -1): AsyncGenerator<
    { chunk: JsonValue } | { result: InvocationResult }, void, unknown
  > {
    const { env, entry, early } = this.prepare(input);
    if (early) {
      // Streaming replay (§13.1): re-stream the recorded chunks from the resume
      // offset, then the recorded terminal result (replayed=true).
      const recorded = this.invocationChunks.get(env.invocation_id!) ?? [];
      for (const chunk of recorded.slice(resumeFrom + 1)) yield { chunk };
      yield { result: early };
      return;
    }
    const d = entry!.descriptor;

    const started = this.emit('execution_started', env, { capability_uri: `${d.id}:${d.version}` }, null);
    const ctx = this.executionContext(env);
    try {
      const raw = await entry!.handler(ctx, env.payload ?? {});
      let data: JsonValue = null;
      const chunks: JsonValue[] = [];
      if (isAsyncGenerator(raw)) {
        for await (const item of raw) {
          if (item instanceof StreamResult) data = item.data;
          else { chunks.push(item as JsonValue); yield { chunk: item }; }
        }
      } else {
        data = raw as JsonValue;
      }
      // §13.1 chunk-sequence evidence: commit a digest of the delivered deltas
      // (omit-when-absent — a non-stream/zero-chunk completion is byte-identical).
      const donePayload: Record<string, JsonValue> = { capability_uri: `${d.id}:${d.version}` };
      if (chunks.length) {
        donePayload.chunk_count = chunks.length;
        donePayload.chunk_seq_digest = chunkSeqDigest(chunks);
      }
      const done = this.emit('execution_completed', env, donePayload, 'success');
      const result = this.result(env, {
        outcome: 'success', success: true, capability_version: d.version,
        data, evidence_ids: [started.event_id, done.event_id], started_at: started.timestamp,
      });
      // Record for idempotent streaming replay (§13.1) with the ordered chunks.
      this.recordResult(result, chunks.length ? chunks : undefined);
      yield { result };
    } catch (err) {
      const failed = this.emit('execution_failed', env, { capability_uri: `${d.id}:${d.version}` }, 'failure',
        { error: { type: (err as Error).name, message: (err as Error).message } });
      const failResult = this.result(env, {
        outcome: 'failure', success: false, capability_version: d.version,
        error: { type: (err as Error).name, message: (err as Error).message },
        evidence_ids: [started.event_id, failed.event_id], started_at: started.timestamp,
      });
      this.recordResult(failResult);
      yield { result: failResult };
    }
  }

  // ── gate helpers ──────────────────────────────────────────────────────────

  private checkPolicy(d: CapabilityDescriptor): DenialReason | null {
    const p = this.opts.policy;
    if (!p) return null;
    let blocked: string | null = null;
    if (p.allowed_capability_ids && !p.allowed_capability_ids.includes(d.id)) blocked = 'not in allowlist';
    else if (p.block_capability_ids?.includes(d.id)) blocked = 'blocked capability id';
    else if (p.max_risk_tier != null) {
      const eff = (d.risk && d.risk in RISK_ORDER ? d.risk : 'medium') as RiskTier;
      if (RISK_ORDER[eff] > RISK_ORDER[p.max_risk_tier]) blocked = `risk ${eff} exceeds max ${p.max_risk_tier}`;
    }
    if (blocked && !p.audit_only) {
      return { code: 'policy_blocked', message: blocked, retryable: false };
    }
    return null;
  }

  private checkInvariants(d: CapabilityDescriptor, env: InvocationEnvelope): DenialReason | null {
    const payload = (env.payload ?? {}) as Record<string, JsonValue>;
    for (const iv of d.invariants ?? []) {
      if (iv.enforcement !== 'host') continue;
      if (iv.kind === 'required_payload_fields') {
        const fields = (iv.parameters?.fields as string[]) ?? [];
        const missing = fields.filter((f) => !(f in payload));
        if (missing.length && iv.failure_behavior !== 'warn') {
          return { code: 'invariant_failed', message: `missing required fields: ${missing.join(', ')}`, invariant_id: iv.id, retryable: false };
        }
      }
    }
    return null;
  }

  private checkAutonomy(d: CapabilityDescriptor, env: InvocationEnvelope): DenialReason | null {
    const a = d.autonomy;
    if (!a) return null;
    const corr = env.correlation!.correlation_id;
    const started = this.store.countEventType(corr, 'execution_started');
    if (a.action_limit != null && started >= a.action_limit) {
      this.emit('budget_exceeded', env, { limit_type: 'action_limit', action_limit: a.action_limit, actions_taken: started }, 'denied');
      return { code: 'budget_exceeded', message: `action_limit ${a.action_limit} reached`, retryable: true };
    }
    if (a.spend_limit != null) {
      const spend = started * (a.spend_units ?? 1);
      if (spend >= a.spend_limit) {
        this.emit('budget_exceeded', env, { limit_type: 'spend_limit', spend_limit: a.spend_limit, spend_so_far: spend }, 'denied');
        return { code: 'budget_exceeded', message: `spend_limit ${a.spend_limit} reached`, retryable: true };
      }
    }
    if (a.tier === 'approval_required') {
      this.emit('approval_requested', env, { tier: a.tier }, 'denied');
      return { code: 'approval_required', message: `${d.id} requires approval`, retryable: true };
    }
    return null;
  }

  private checkInputSchema(d: CapabilityDescriptor, env: InvocationEnvelope): DenialReason | null {
    const s = d.input_schema as { required?: string[] } | null | undefined;
    if (!s || !Array.isArray(s.required)) return null;
    const payload = (env.payload ?? {}) as Record<string, JsonValue>;
    const missing = s.required.filter((f) => !(f in payload));
    if (missing.length) {
      return { code: 'input_schema_validation_failed', message: `missing: ${missing.join(', ')}`, retryable: false };
    }
    return null;
  }

  private checkSafety(d: CapabilityDescriptor, env: InvocationEnvelope): DenialReason | null {
    const evaluator = this.opts.safetyEvaluator;
    if (!evaluator) return null;
    const uri = `${d.id}:${d.version}`;
    this.emit('safety_assessment_started', env, { capability_uri: uri });
    const report = evaluator.report(d.id, env.payload ?? {});
    const a = report.assessment;
    this.emit('safety_assessment_completed', env, { capability_uri: uri, level: a.level, score: a.score, approved: report.approved });
    if (!report.approved) {
      this.emit('safety_guardrail_triggered', env, { capability_uri: uri, reason: report.blockReason });
      this.emit('safety_action_blocked', env, { capability_uri: uri, reason: report.blockReason }, 'denied');
      return { code: 'safety_blocked', message: report.blockReason ?? 'blocked by safety guardrail', retryable: false, details: { level: a.level } };
    }
    this.emit('safety_action_approved', env, { capability_uri: uri, level: a.level });
    return null;
  }
}
