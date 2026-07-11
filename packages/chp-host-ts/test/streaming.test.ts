import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { RemoteCapabilityHost, buildMandate, buildMandateRevocation, keypairFromSeed } from '@capabilityhostprotocol/sdk';
import { buildFixtureHost } from '../src/fixtures.js';
import { createHostServer } from '../src/server.js';

let server: Server;
let base: string;
let client: RemoteCapabilityHost;

beforeAll(async () => {
  server = createHostServer(buildFixtureHost());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  client = new RemoteCapabilityHost(base);
});

afterAll(() => server.close());

describe('streaming over the wire (proposal 0006 parity)', () => {
  it('streams chunk frames then a terminal result via invokeStream', async () => {
    const deltas: unknown[] = [];
    let result: Record<string, unknown> | null = null;
    for await (const item of client.invokeStream('conformance.stream', {})) {
      if ('delta' in item) deltas.push(item.delta);
      else result = item.result as unknown as Record<string, unknown>;
    }
    expect(deltas).toEqual(['s1', 's2', 's3']);
    expect(result?.outcome).toBe('success');
    expect((result?.data as Record<string, unknown>).joined).toBe('s1s2s3');
  });

  it('a denial never commits to SSE — plain JSON result, no deltas', async () => {
    const items = [];
    for await (const item of client.invokeStream('conformance.unsafe', {})) items.push(item);
    expect(items).toHaveLength(1);
    const only = items[0] as { result: { outcome: string } };
    expect(only.result.outcome).toBe('denied');
  });

  it('sync-mode invocation of the streaming fixture degrades gracefully', async () => {
    const r = await client.invoke('conformance.stream', {});
    expect(r.outcome).toBe('success');
    expect((r.data as Record<string, unknown>).joined).toBe('s1s2s3');
  });
});

describe('streaming completion (proposal 0012)', () => {
  async function collect(id: string, opts: Record<string, unknown> = {}) {
    const deltas: unknown[] = [];
    let result: Record<string, unknown> | null = null;
    for await (const item of client.invokeStream('conformance.stream', {}, { invocationId: id, ...opts })) {
      if ('delta' in item) deltas.push(item.delta);
      else result = item.result as unknown as Record<string, unknown>;
    }
    return { deltas, result };
  }

  it('replays a retried streaming invocation_id — identical chunks, replayed=true', async () => {
    const id = 'inv-ts-replay-1';
    const first = await collect(id);
    expect(first.deltas).toEqual(['s1', 's2', 's3']);
    expect(first.result?.replayed).toBeFalsy();
    const second = await collect(id);
    expect(second.deltas).toEqual(first.deltas);       // recorded chunks re-streamed
    expect(second.result?.replayed).toBe(true);        // no re-execution
  });

  it('emits chunk-seq evidence in execution_completed', async () => {
    const corr = `corr-ts-cseq-${Date.now()}`;
    for await (const _ of client.invokeStream('conformance.stream', {},
      { invocationId: 'inv-ts-cseq', correlation: { correlation_id: corr } })) { /* drain */ }
    const events = (await (await fetch(`${base}/replay/${corr}`)).json()) as { events: Record<string, any>[] };
    const done = events.events.find((e) => e.event_type === 'execution_completed');
    expect(done?.payload.chunk_count).toBe(3);
    expect(done?.payload.chunk_seq_digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('resumes from Last-Event-ID off the recorded stream, with id: frames', async () => {
    const id = 'inv-ts-resume-1';
    for await (const _ of client.invokeStream('conformance.stream', {}, { invocationId: id })) { /* record */ }
    // Reconnect from chunk id 0 → resume from chunk 1 (s2, s3).
    const resp = await fetch(`${base}/invoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Last-Event-ID': '0' },
      body: JSON.stringify({ capability_id: 'conformance.stream', payload: {}, mode: 'stream',
        invocation_id: id, correlation: {}, subject: { id: 'x', type: 'user' }, metadata: {} }),
    });
    expect(resp.headers.get('content-type')).toContain('text/event-stream');
    const text = await resp.text();
    const ids = [...text.matchAll(/^id: (\d+)$/gm)].map((m) => m[1]);
    const deltas = [...text.matchAll(/^data: (.+)$/gm)].map((m) => JSON.parse(m[1]))
      .filter((d) => 'delta' in d).map((d) => d.delta);
    expect(deltas).toEqual(['s2', 's3']);
    expect(ids.slice(0, 2)).toEqual(['1', '2']);
  });
});

describe('revocation routes (proposal 0007)', () => {
  it('POST → GET → gate-5 denial round-trip', async () => {
    const key = keypairFromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 31)));
    const TS = '2026-01-01T00:00:00Z';
    const mandate = buildMandate('rt-principal', key, {
      delegateId: 'remote', scope: ['conformance.echo'],
      validFrom: TS, validUntil: '2099-01-01T00:00:00Z', createdAt: TS,
    });
    const ok = await client.invoke('conformance.echo', { value: 'hi' }, { mandate, subject: { id: 'remote', type: 'user' } });
    expect(ok.outcome).toBe('success');

    const rev = buildMandateRevocation(mandate, key, { revokedAt: TS });
    const resp = await fetch(`${base}/revocations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rev),
    });
    expect(((await resp.json()) as { accepted: boolean }).accepted).toBe(true);

    const served = (await (await fetch(`${base}/revocations`)).json()) as { mandates: { mandate_id: string }[] };
    expect(served.mandates.map((m) => m.mandate_id)).toContain(mandate.mandate_id);

    const denied = await client.invoke('conformance.echo', { value: 'hi' }, { mandate });
    expect(denied.outcome).toBe('denied');
    expect(denied.denial?.code).toBe('mandate_invalid');
  });
});
