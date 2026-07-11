/**
 * RemoteCapabilityHost — a client for the CHP HTTP binding (spec/chp-http-binding.md).
 * Uses global `fetch` (Node ≥18). A *processed* invocation — including a denial —
 * returns HTTP 200 with the verdict in the body; only transport failures throw.
 */

import { randomUUID } from 'node:crypto';
import type { JsonValue } from './canon.js';

export interface InvocationResult {
  invocation_id: string;
  capability_id: string;
  outcome: 'success' | 'failure' | 'denied' | 'skipped';
  success: boolean;
  data?: JsonValue;
  denial?: { code: string; message: string; retryable?: boolean } | null;
  correlation?: JsonValue;
  evidence_ids?: string[];
  [k: string]: JsonValue | undefined;
}

/**
 * Correlation for work CAUSED BY an invocation: same correlation_id,
 * causation_id = the parent invocation's id. Pass to any remote `invoke` to
 * extend the causal tree across hosts (chp-causal-order-v1 orders by it).
 */
export function childCorrelation(
  correlation: Record<string, JsonValue>,
  parentInvocationId: string,
): Record<string, JsonValue> {
  return { ...correlation, causation_id: parentInvocationId };
}

export class RemoteCapabilityHost {
  private readonly base: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, opts: { apiKey?: string; timeoutMs?: number } = {}) {
    this.base = baseUrl.replace(/\/+$/, '');
    this.apiKey = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  private headers(json = false): Record<string, string> {
    const h: Record<string, string> = {};
    if (json) h['Content-Type'] = 'application/json';
    if (this.apiKey) h['X-CHP-Key'] = this.apiKey;
    return h;
  }

  private async req(path: string, init?: RequestInit): Promise<JsonValue> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const resp = await fetch(`${this.base}${path}`, { ...init, signal: ctrl.signal });
      const text = await resp.text();
      if (!resp.ok) {
        // non-2xx = transport-level (bad json / auth / route), NOT a CHP outcome
        throw new Error(`CHP remote ${resp.status} on ${path}: ${text.slice(0, 300)}`);
      }
      return text ? (JSON.parse(text) as JsonValue) : null;
    } finally {
      clearTimeout(t);
    }
  }

  async health(): Promise<JsonValue> {
    return this.req('/health');
  }

  /** The host's public identity document (unauth — spec §3 Anchors). */
  async identity(): Promise<Record<string, JsonValue>> {
    return this.req('/.well-known/chp-identity') as Promise<Record<string, JsonValue>>;
  }

  async discover(): Promise<Record<string, JsonValue>> {
    return this.req('/host', { headers: this.headers() }) as Promise<Record<string, JsonValue>>;
  }

  async capabilities(): Promise<JsonValue[]> {
    const r = (await this.req('/capabilities', { headers: this.headers() })) as { capabilities?: JsonValue[] };
    return r.capabilities ?? [];
  }

  async invoke(
    capabilityId: string,
    payload: JsonValue = {},
    opts: { correlation?: JsonValue; subject?: JsonValue; mode?: string; version?: string; mandate?: JsonValue } = {},
  ): Promise<InvocationResult> {
    const body: Record<string, JsonValue> = {
      capability_id: capabilityId,
      payload,
      mode: opts.mode ?? 'sync',
      correlation: opts.correlation ?? {},
      subject: opts.subject ?? { id: 'remote', type: 'user' },
    };
    if (opts.version) body.version = opts.version;
    // Presented authority (§10): the delegate host verifies it; the evidence
    // subject becomes "delegate under principal's mandate".
    if (opts.mandate) body.mandate = opts.mandate;
    return this.req('/invoke', {
      method: 'POST',
      headers: this.headers(true),
      body: JSON.stringify(body),
    }) as Promise<InvocationResult>;
  }

  /**
   * Streaming invocation (proposal 0006): POSTs `mode:"stream"` and yields
   * `{delta}` frames, then finally `{result}` with the standard
   * InvocationResult. If the host answers plain JSON (a denial, or a host
   * that processed synchronously — the Content-Type switch), the single
   * `{result}` is yielded with no deltas. NOTE the deliberate asymmetry with
   * Python's `invoke_stream` (terminal result = StopIteration.value): a
   * yielded terminal frame is the idiomatic JS shape for async generators.
   */
  async *invokeStream(
    capabilityId: string,
    payload: JsonValue = {},
    opts: { correlation?: JsonValue; subject?: JsonValue; version?: string; mandate?: JsonValue;
            invocationId?: string; resumeAttempts?: number } = {},
  ): AsyncGenerator<{ delta: JsonValue } | { result: InvocationResult }, void, unknown> {
    // Pin ONE invocation_id for the whole call (§13.1) so a dropped connection
    // resumes the SAME recorded stream via Last-Event-ID.
    const invocationId = opts.invocationId ?? `inv_${randomUUID()}`;
    const body: Record<string, JsonValue> = {
      capability_id: capabilityId,
      payload,
      mode: 'stream',
      correlation: opts.correlation ?? {},
      subject: opts.subject ?? { id: 'remote', type: 'user' },
      invocation_id: invocationId,
    };
    if (opts.version) body.version = opts.version;
    if (opts.mandate) body.mandate = opts.mandate;
    const rawBody = JSON.stringify(body);
    const resumeAttempts = opts.resumeAttempts ?? 5;

    let lastId = -1; // highest chunk index delivered to the caller so far
    for (let attempt = 0; attempt <= resumeAttempts; attempt++) {
      const headers = this.headers(true);
      if (lastId >= 0) headers['Last-Event-ID'] = String(lastId); // reconnect: resume
      try {
        const resp = await fetch(`${this.base}/invoke`, { method: 'POST', headers, body: rawBody });
        const ctype = resp.headers.get('content-type') ?? '';
        if (!ctype.includes('text/event-stream')) {
          const text = await resp.text();
          if (!resp.ok) throw new Error(`CHP remote ${resp.status} on /invoke: ${text.slice(0, 300)}`);
          yield { result: JSON.parse(text) as InvocationResult };
          return;
        }
        const reader = resp.body!.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        let event: string | null = null;
        let eid: number | null = null;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let nl: number;
          while ((nl = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, nl).trimEnd();
            buf = buf.slice(nl + 1);
            if (line.startsWith('id: ')) {
              const n = Number.parseInt(line.slice('id: '.length).trim(), 10);
              eid = Number.isFinite(n) ? n : null;
            } else if (line.startsWith('event: ')) {
              event = line.slice('event: '.length).trim();
            } else if (line.startsWith('data: ')) {
              const data = JSON.parse(line.slice('data: '.length)) as Record<string, JsonValue>;
              if (event === 'result') {
                yield { result: data as unknown as InvocationResult };
                return;
              }
              if (event === 'chunk') {
                if (eid !== null && eid <= lastId) continue; // dedupe after resume
                if (eid !== null) lastId = eid;
                yield { delta: data.delta ?? null };
              }
            }
          }
        }
        // Stream closed with no terminal result → mid-stream drop; reconnect.
        throw new Error('stream ended without a terminal result frame');
      } catch (err) {
        if (attempt >= resumeAttempts) throw err;
        // reconnect from lastId via Last-Event-ID
      }
    }
  }

  async replay(correlationId: string): Promise<JsonValue[]> {
    const r = (await this.req(`/replay/${encodeURIComponent(correlationId)}`, {
      headers: this.headers(),
    })) as { events?: JsonValue[] };
    return r.events ?? [];
  }

  async verify(correlationId: string): Promise<JsonValue> {
    return this.req(`/verify/${encodeURIComponent(correlationId)}`, { headers: this.headers() });
  }
}
