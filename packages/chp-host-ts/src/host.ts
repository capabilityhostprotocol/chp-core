/**
 * LocalCapabilityHost — the governed invocation pipeline (spec/chp-invocation-pipeline.md).
 * Gates are applied in the exact normative order; the first that fires decides the
 * outcome and stops. This is the TS peer of chp_core/host.py:ainvoke_envelope.
 */

import { randomBytes } from 'node:crypto';
import { buildAttestation, buildBundle, signBundle, type EvidenceEvent, type HostKey } from '@capabilityhostprotocol/sdk';
import { InMemoryEvidenceStore } from './store.js';
import { RuleBasedSafetyEvaluator } from './safety.js';
import type {
  CapabilityDescriptor, Correlation, Ctx, DenialReason, Handler,
  InvocationEnvelope, InvocationResult, JsonValue, PolicyConfig, RiskTier,
} from './types.js';

const RISK_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
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
      protocol_version: '0.1',
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
    const ev: EvidenceEvent = {
      event_id: newId('evt'),
      event_type: eventType,
      invocation_id: env.invocation_id!,
      capability_id: env.capability_id,
      host_id: this.hostId,
      correlation: env.correlation as EvidenceEvent['correlation'],
      timestamp: nowIso(),
      outcome,
      payload: stringifyFloats(payload),
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

  private skip(env: InvocationEnvelope, code: string, message: string): InvocationResult {
    const e = this.emit('execution_skipped', env, { code, message }, 'skipped');
    return this.result(env, { outcome: 'skipped', success: false, evidence_ids: [e.event_id] });
  }

  async ainvokeEnvelope(input: InvocationEnvelope): Promise<InvocationResult> {
    const env: InvocationEnvelope = {
      mode: 'sync',
      payload: {},
      subject: { id: 'local', type: 'user' },
      ...input,
      invocation_id: input.invocation_id ?? newId('inv'),
      correlation: (input.correlation as Correlation) ?? { correlation_id: newId('corr') },
    };

    // Gate 1: non-empty id
    if (!env.capability_id || !env.capability_id.trim()) {
      return this.deny(env, { code: 'capability_not_found', message: 'capability_id must be non-empty', retryable: false });
    }
    // Gate 2: resolution
    const entry = this.caps.get(env.capability_id);
    if (!entry || (env.version && env.version !== entry.descriptor.version)) {
      return this.deny(env, { code: 'capability_not_found', message: `Capability not found: ${env.capability_id}`, retryable: false });
    }
    const d = entry.descriptor;
    env.version = d.version;
    // Gate 3: enabled → SKIP (not deny)
    if (!entry.enabled) {
      return this.skip(env, 'capability_disabled', `Capability disabled: ${d.id}:${d.version}`);
    }
    // Gate 4: mode
    const modes = d.modes ?? ['sync'];
    if (!modes.includes(env.mode!)) {
      return this.deny(env, { code: 'unsupported_mode', message: `mode ${env.mode} unsupported`, retryable: false });
    }
    // Gate 5: policy
    const pd = this.checkPolicy(d);
    if (pd) return this.deny(env, pd);
    // Gate 6: invariants
    const inv = this.checkInvariants(d, env);
    if (inv) return this.deny(env, inv);
    // Gate 7: autonomy budget / approval
    const auto = this.checkAutonomy(d, env);
    if (auto) return this.deny(env, auto);
    // Gate 8: input schema (minimal required-fields check; full JSON Schema out of scope)
    const sch = this.checkInputSchema(d, env);
    if (sch) return this.deny(env, sch);
    // Gate 9: safety
    const saf = this.checkSafety(d, env);
    if (saf) return this.deny(env, saf);

    // Gate 10: execute
    const started = this.emit('execution_started', env, { capability_uri: `${d.id}:${d.version}` }, null);
    const ctx: Ctx = {
      envelope: env,
      emit: (t, p, o = null) => this.emit(t, env, p, o),
    };
    try {
      const data = await entry.handler(ctx, env.payload ?? {});
      const done = this.emit('execution_completed', env, { capability_uri: `${d.id}:${d.version}` }, 'success');
      return this.result(env, {
        outcome: 'success', success: true, capability_version: d.version,
        data: data as JsonValue, evidence_ids: [started.event_id, done.event_id], started_at: started.timestamp,
      });
    } catch (err) {
      const failed = this.emit('execution_failed', env, { capability_uri: `${d.id}:${d.version}` }, 'failure',
        { error: { type: (err as Error).name, message: (err as Error).message } });
      return this.result(env, {
        outcome: 'failure', success: false, capability_version: d.version,
        error: { type: (err as Error).name, message: (err as Error).message },
        evidence_ids: [started.event_id, failed.event_id], started_at: started.timestamp,
      });
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
