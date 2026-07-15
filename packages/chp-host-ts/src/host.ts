/**
 * LocalCapabilityHost — the governed invocation pipeline (spec/chp-invocation-pipeline.md).
 * Gates are applied in the exact normative order; the first that fires decides the
 * outcome and stops. This is the TS peer of chp_core/host.py:ainvoke_envelope.
 */

import { randomBytes } from 'node:crypto';
import { buildAttestation, buildBundle, buildCompleteness, signBundle, verifyMandate, verifyApprovalGrant, scopeAllows, mandateRootPrincipal, EVENT_HASH_V2, payloadCommitment, chunkSeqDigest, PROTOCOL_VERSION, versionsUpto, bestSatisfying, type EvidenceEvent, type HostKey } from '@capabilityhostprotocol/sdk';
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
  // id → all registered versions of that capability (proposal 0028: a host may
  // run several versions of an id; the resolution gate picks the one satisfying
  // a requested semver range).
  private readonly caps = new Map<string, Registered[]>();
  private readonly attestation: JsonValue | null;
  /** Received mandate revocations (§10 Revocation) — in-memory for this
   * conformance host; gate 5 consults them under the issuer-only rule. */
  readonly mandateRevocations: Record<string, JsonValue>[] = [];
  /** Recorded results for idempotent replay (§13) — serving state, never
   * evidence; in-memory for this conformance host. */
  private readonly invocationResults = new Map<string, InvocationResult>();
  /** Recorded stream chunk deltas for §13.1 replay/resume — serving state. */
  private readonly invocationChunks = new Map<string, JsonValue[]>();
  /** Per-mandate use counting for the max_invocations cap (§10, proposal 0026):
   * mandate_id → the set of distinct invocation_ids charged to it. Keyed on
   * invocation_id (the replay key), so a re-run of the same invocation does not
   * consume a new use — the same replay-safe rule as the Python store. In-memory
   * for this conformance host (Python persists it in a mandate_usage table). */
  private readonly mandateUsage = new Map<string, Set<string>>();

  constructor(
    readonly hostId = 'ts-chp-host',
    private readonly opts: {
      policy?: PolicyConfig;
      safetyEvaluator?: RuleBasedSafetyEvaluator;
      signingKey?: HostKey;
      /** Domain anchor (spec §3 Anchors) — the trust root a never-met verifier resolves. */
      domain?: string;
      /** When true, a result violating output_schema is denied host-wide
       * (proposal 0029); default validate-and-warn. */
      strictOutputSchema?: boolean;
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
    // Non-omission (§12, proposal 0018): claim completeness as of the store's
    // current global sequence, so a witness can later prove the tail intact.
    const completeness = events.length > 0
      ? buildCompleteness(correlationId, events, this.store.getStoreHead().sequence)
      : null;
    const bundle = buildBundle(this.hostId, events, nowIso(), undefined, undefined, completeness);
    if (!this.opts.signingKey) return bundle;
    return signBundle(bundle, this.opts.signingKey, {
      anchors: this.opts.domain ? [{ type: 'domain', domain: this.opts.domain }] : null,
    });
  }

  register(descriptor: CapabilityDescriptor, handler: Handler): void {
    const reg: Registered = { descriptor, handler, enabled: descriptor.enabled !== false };
    const versions = this.caps.get(descriptor.id) ?? [];
    // Replace a same-version re-registration; otherwise add the new version.
    const at = versions.findIndex((r) => r.descriptor.version === descriptor.version);
    if (at >= 0) versions[at] = reg; else versions.push(reg);
    this.caps.set(descriptor.id, versions);
  }

  discover(caller?: string | null): Record<string, JsonValue> {
    // Authorized discovery (proposal 0035): when a verified caller is given, hide
    // capabilities whose policy.allowed_actors is non-empty and excludes it — a
    // caller sees only what it may invoke. Absent caller = unfiltered (today's
    // behavior). Hiding is least-disclosure; the invoke gate (policy_blocked) is
    // the security backstop. Parity with Python host.discover(caller=...).
    return {
      id: this.hostId,
      version: '0.1.0',
      // This host always hash-chains (and signs when keyed) — the v0.2 surface.
      protocol_version: PROTOCOL_VERSION,
      // Wire versions this host speaks, for negotiation (§1.1, proposal 0016).
      supported_versions: versionsUpto(PROTOCOL_VERSION),
      kind: 'local',
      capabilities: [...this.caps.values()]
        .flat()
        .filter((c) => {
          const allowed = c.descriptor.policy?.allowed_actors;
          return !caller || !allowed || allowed.length === 0 || allowed.includes(caller);
        })
        .map((c) => ({
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
      // First-class actor recorded alongside the subject; omit-when-absent so
      // pre-0034 events are byte-identical (proposal 0034).
      ...(env.actor ? { actor: env.actor } : {}),
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
      // Resume-aware replay (proposal 0037): a cached approval_required denial does
      // NOT replay if the caller now presents a valid grant — drop it and fall through
      // to execute exactly once. Any other cached result replays as usual.
      const resuming = recorded.outcome === 'denied' && recorded.denial?.retryable === true
        && recorded.denial?.code === 'approval_required' && this.validApprovalFor(env);
      if (resuming) {
        this.invocationResults.delete(env.invocation_id!);
      } else {
        return { env, entry: null, early: { ...recorded, replayed: true } as InvocationResult };
      }
    }

    // Gate 1: non-empty id
    if (!env.capability_id || !env.capability_id.trim()) {
      return decided(this.deny(env, { code: 'capability_not_found', message: 'capability_id must be non-empty', retryable: false }));
    }
    // Gate 2: resolution
    const notFound = (): { env: InvocationEnvelope; entry: null; early: InvocationResult } => {
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
    };
    const entries = this.caps.get(env.capability_id) ?? [];
    if (entries.length === 0) return notFound();  // id not registered at all
    let entry: Registered | undefined;
    const reqRange = env.requested_capability_version;
    if (reqRange != null && reqRange !== '') {
      // Capability-version negotiation (§1.1, proposal 0028): resolve the highest
      // registered version satisfying the range, else capability_version_unsupported
      // (the id EXISTS — distinct from capability_not_found).
      const available = entries.map((r) => r.descriptor.version);
      const best = bestSatisfying(available, String(reqRange));
      if (best === null) {
        return decided(this.deny(env, {
          code: 'capability_version_unsupported',
          message: `no registered version of '${env.capability_id}' satisfies '${String(reqRange)}'`,
          retryable: false,
          details: { requested: reqRange, available },
        }));
      }
      entry = entries.find((r) => r.descriptor.version === best);
    } else if (env.version) {
      entry = entries.find((r) => r.descriptor.version === env.version);  // exact
      if (!entry) return notFound();
    } else {
      // No range, no explicit version: a single registration resolves; an
      // ambiguous unversioned match does NOT (parity with Python).
      entry = entries.length === 1 ? entries[0] : undefined;
      if (!entry) return notFound();
    }
    if (!entry) return notFound();
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
      // Use-count cap (§10, proposal 0026): count the distinct invocations already
      // charged to this mandate_id and deny once the signed max_invocations is
      // reached. Keyed on invocation_id (the replay key), so a re-run of the same
      // invocation does not consume a new use. Parity with the Python store.
      const maxInv = env.mandate.max_invocations;
      if (maxInv !== undefined && maxInv !== null) {
        const mid = String(env.mandate.mandate_id ?? '');
        const invId = String(env.invocation_id ?? '');
        const uses = this.mandateUsage.get(mid) ?? new Set<string>();
        const already = uses.has(invId);
        const used = uses.size;
        if (!already && used >= Number(maxInv)) {
          return decided(this.deny(env, {
            code: 'mandate_exhausted',
            message: `mandate '${mid}' exhausted (${used}/${Number(maxInv)} invocations used)`,
            retryable: false,
            details: { used, max_invocations: Number(maxInv), mandate_id: mid },
          }));
        }
        uses.add(invId);
        this.mandateUsage.set(mid, uses);
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
    // Per-actor allowlist (proposal 0034): descriptor.policy.allowed_actors,
    // enforced after the mandate gate finalizes the subject. Effective actor =
    // verified subject id (accountability wins), else asserted actor.id, else
    // subject id. Empty/absent = open (today's behavior). Parity with Python.
    const allowed = d.policy?.allowed_actors;
    if (allowed && allowed.length > 0) {
      const subj = (env.subject ?? {}) as Record<string, JsonValue>;
      const actor = (env.actor ?? {}) as Record<string, JsonValue>;
      const effective = subj.verified
        ? String(subj.id ?? '')
        : String(actor.id ?? subj.id ?? '');
      if (!allowed.includes(effective)) {
        return decided(this.deny(env, {
          code: 'policy_blocked',
          message: `actor '${effective}' is not in allowed_actors for '${d.id}'`,
          retryable: false,
          details: { allowed_actors: allowed, actor: effective },
        }));
      }
    }
    // Gate 6: policy
    const pd = this.checkPolicy(d, env);
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
      const [oDeny, oMeta] = this.checkOutputSchema(d, data as JsonValue, env);
      if (oDeny) return this.recordResult(this.deny(env, oDeny));
      const done = this.emit('execution_completed', env,
        { capability_uri: `${d.id}:${d.version}`, ...oMeta }, 'success');
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
      const [oDeny, oMeta] = this.checkOutputSchema(d, data, env);
      if (oDeny) { yield { result: this.recordResult(this.deny(env, oDeny)) }; return; }
      // §13.1 chunk-sequence evidence: commit a digest of the delivered deltas
      // (omit-when-absent — a non-stream/zero-chunk completion is byte-identical).
      const donePayload: Record<string, JsonValue> = { capability_uri: `${d.id}:${d.version}`, ...oMeta };
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

  private checkPolicy(d: CapabilityDescriptor, env: InvocationEnvelope): DenialReason | null {
    const p = this.opts.policy;
    if (!p) return null;
    // Policy decision (proposal 0036): coarse rules render 'deny'; a block-pattern
    // may render any decision. Map to a reserved code + attach the decision record.
    // Parity with Python policy.py / host.py _POLICY_DECISION_CODE.
    const CODE: Record<string, string> = {
      deny: 'policy_blocked',
      requires_approval: 'approval_required',
      requires_escalation: 'escalation_required',
      requires_more_evidence: 'evidence_required',
      sandbox_only: 'policy_blocked', // fail-closed: no sandbox execution mode
    };
    const NEXT: Record<string, string> = {
      requires_approval: 'obtain human approval and retry',
      requires_escalation: 'escalate to a higher authority to decide',
      requires_more_evidence: 'provide the required additional evidence and retry',
      sandbox_only: 'run in a sandbox (no sandbox execution mode available — denied)',
    };
    let decision = 'allow';
    let reason: string | null = null;
    let matched: string | null = null;
    if (p.allowed_capability_ids && !p.allowed_capability_ids.includes(d.id)) {
      decision = 'deny'; reason = 'not in allowlist'; matched = 'allowed_capability_ids';
    } else if (p.block_capability_ids?.includes(d.id)) {
      decision = 'deny'; reason = 'blocked capability id'; matched = `block_capability_ids:${d.id}`;
    } else if (p.max_risk_tier != null) {
      const eff = (d.risk && d.risk in RISK_ORDER ? d.risk : 'medium') as RiskTier;
      if (RISK_ORDER[eff] > RISK_ORDER[p.max_risk_tier]) {
        decision = 'deny'; reason = `risk ${eff} exceeds max ${p.max_risk_tier}`;
        matched = `max_risk_tier:${p.max_risk_tier}`;
      }
    }
    if (decision === 'allow' && p.block_patterns) {
      const payload = (env.payload ?? {}) as Record<string, JsonValue>;
      for (const bp of p.block_patterns) {
        if (bp.capability_id !== d.id) continue;
        const value = String(payload[bp.field] ?? '');
        let m = false;
        try { m = new RegExp(bp.pattern, 'i').test(value); } catch { m = value.toLowerCase().includes(bp.pattern.toLowerCase()); }
        if (m) {
          decision = bp.decision ?? 'deny';
          reason = bp.reason ?? 'blocked by policy pattern';
          matched = `block_pattern:${bp.capability_id}.${bp.field}`;
          break;
        }
      }
    }
    if (decision === 'allow' || p.audit_only) return null; // audit_only records but never blocks
    return {
      code: CODE[decision] ?? 'policy_blocked',
      message: reason ?? 'blocked by policy',
      retryable: ['requires_approval', 'requires_escalation', 'requires_more_evidence'].includes(decision),
      details: {
        decision,
        matched_rule: matched,
        policy_version: p.version ?? null,
        explanation: reason,
        required_next_action: NEXT[decision] ?? null,
      },
    };
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
      // Resumable invocation (proposal 0037): a valid approver-signed grant for THIS
      // invocation + payload proceeds past the gate; else deny approval_required.
      if (this.validApprovalFor(env)) {
        const g = (env.approval_ref ?? {}) as Record<string, JsonValue>;
        this.emit('approval_grant_verified', env, { approval_id: g.approval_id ?? null, approver: g.approver ?? null }, null);
        return null;
      }
      this.emit('approval_requested', env, { tier: a.tier }, 'denied');
      return { code: 'approval_required', message: `${d.id} requires approval`, retryable: true };
    }
    return null;
  }

  /** A presented approval grant (proposal 0037) authorizes THIS invocation to
   * resume: verifies (approver signature, not expired), decision granted, and binds
   * this exact invocation_id + payload commitment. Parity with Python
   * `_valid_approval_for`. */
  private validApprovalFor(env: InvocationEnvelope): boolean {
    const grant = env.approval_ref;
    if (!grant || typeof grant !== 'object') return false;
    const g = grant as Record<string, JsonValue>;
    if (!verifyApprovalGrant(g, { atTime: nowIso() }).valid) return false;
    if (g.decision !== 'granted' || g.invocation_id !== env.invocation_id) return false;
    return g.payload_commitment === payloadCommitment((env.payload ?? {}) as JsonValue);
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

  /** Post-execution output validation (proposal 0029, gate 12). Mirror of
   * checkInputSchema but over the RESULT. Returns [denial, meta]: a denial iff
   * the result violates output_schema AND strict is requested (env.require_output_schema
   * or host strictOutputSchema); else meta carries warn markers to fold into the
   * completed evidence (default validate-and-warn). Narrow subset (required keys),
   * matching checkInputSchema. */
  private checkOutputSchema(
    d: CapabilityDescriptor, data: JsonValue, env: InvocationEnvelope,
  ): [DenialReason | null, Record<string, JsonValue>] {
    const s = d.output_schema as { required?: string[] } | null | undefined;
    if (!s || !Array.isArray(s.required)) return [null, {}];
    const obj = (data ?? {}) as Record<string, JsonValue>;
    const missing = (typeof data === 'object' && data !== null && !Array.isArray(data))
      ? s.required.filter((f) => !(f in obj))
      : s.required.slice();  // non-object result satisfies no required key
    if (!missing.length) return [null, {}];
    const msg = `missing: ${missing.join(', ')}`;
    if (env.require_output_schema || this.opts.strictOutputSchema) {
      return [{ code: 'output_schema_validation_failed', message: msg, retryable: false }, {}];
    }
    return [null, { output_schema_valid: false, output_schema_error: msg }];
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
