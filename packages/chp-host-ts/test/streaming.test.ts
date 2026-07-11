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
