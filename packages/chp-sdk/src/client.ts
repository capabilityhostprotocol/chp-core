/**
 * RemoteCapabilityHost — a client for the CHP HTTP binding (spec/chp-http-binding.md).
 * Uses global `fetch` (Node ≥18). A *processed* invocation — including a denial —
 * returns HTTP 200 with the verdict in the body; only transport failures throw.
 */

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
    opts: { correlation?: JsonValue; subject?: JsonValue; mode?: string; version?: string } = {},
  ): Promise<InvocationResult> {
    const body: Record<string, JsonValue> = {
      capability_id: capabilityId,
      payload,
      mode: opts.mode ?? 'sync',
      correlation: opts.correlation ?? {},
      subject: opts.subject ?? { id: 'remote', type: 'user' },
    };
    if (opts.version) body.version = opts.version;
    return this.req('/invoke', {
      method: 'POST',
      headers: this.headers(true),
      body: JSON.stringify(body),
    }) as Promise<InvocationResult>;
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
