import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildFixtureHost } from '../src/fixtures.js';
import { createHostServer } from '../src/server.js';

// Mutual TLS for the HTTP transport (chp-v0.2.md §5, proposal 0031). Uses the same
// CA/server/client PEM fixtures the Python test uses — a verified client cert binds
// its identity to the evidence subject; an unknown-CA client is refused at the
// handshake. Node cannot author x509, hence shared static fixtures (valid to 2040).
const dir = fileURLToPath(new URL('./fixtures/mtls/', import.meta.url));
const f = (n: string) => readFileSync(dir + n);

let server: Server;
let port: number;

beforeAll(async () => {
  server = createHostServer(buildFixtureHost(), {
    tls: { cert: f('server.crt'), key: f('server.key'), ca: f('ca.crt') },
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(() => server.close());

// Minimal mTLS POST client (fetch can't present client certs cleanly).
function mtlsPost(
  path: string, body: unknown, cert: Buffer, key: Buffer,
): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = httpsRequest(
      { host: '127.0.0.1', port, path, method: 'POST', cert, key, ca: f('ca.crt'),
        headers: { 'Content-Type': 'application/json', 'Content-Length': data.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () => resolve({
          status: res.statusCode ?? 0,
          json: JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'),
        }));
      });
    req.on('error', reject);
    req.end(data);
  });
}

describe('mutual TLS (proposal 0031)', () => {
  it('a CA-verified client authenticates; its cert CN is the verified subject', async () => {
    const r = await mtlsPost('/invoke',
      { capability_id: 'conformance.echo', payload: { value: 'x' }, correlation_id: 'mtls-ts' },
      f('client.crt'), f('client.key'));
    expect(r.status).toBe(200);
    expect((r.json as { success?: boolean }).success).toBe(true);
    // GET /replay over mTLS to read the bound subject
    const got = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const req = httpsRequest(
        { host: '127.0.0.1', port, path: '/replay/mtls-ts', method: 'GET',
          cert: f('client.crt'), key: f('client.key'), ca: f('ca.crt') },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(c as Buffer));
          res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
        });
      req.on('error', reject);
      req.end();
    });
    const events = got.events as Array<Record<string, unknown>>;
    expect(events[0].subject).toEqual({ id: 'agent-a', type: 'mtls', verified: true });
  });

  it('an unknown-CA client is refused at the handshake', async () => {
    await expect(mtlsPost('/invoke',
      { capability_id: 'conformance.echo', payload: {}, correlation_id: 'rogue' },
      f('rogue-client.crt'), f('rogue-client.key'))).rejects.toThrow();
  });
});
