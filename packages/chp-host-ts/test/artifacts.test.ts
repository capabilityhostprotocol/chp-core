import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildFixtureHost } from '../src/fixtures.js';
import { createHostServer } from '../src/server.js';

// TS parity for the chp-server artifact data plane (/artifacts) — content-addressed, integrity-
// verified. Ground truth is chp_core/http.py _post_artifact/_get_artifact + ArtifactStore.
let server: Server;
let noStoreServer: Server;
let base: string;
let noStoreBase: string;
let root: string;

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'chp-ts-artifacts-'));
  server = createHostServer(buildFixtureHost(), { artifactsRoot: root });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  noStoreServer = createHostServer(buildFixtureHost());
  await new Promise<void>((r) => noStoreServer.listen(0, '127.0.0.1', r));
  noStoreBase = `http://127.0.0.1:${(noStoreServer.address() as AddressInfo).port}`;
});

afterAll(() => { server.close(); noStoreServer.close(); });

describe('artifact plane parity — /artifacts', () => {
  it('POST stores content-addressed → 201 ref; GET returns the exact bytes', async () => {
    const bytes = Buffer.from('conformance bytes');
    const post = await fetch(`${base}/artifacts`, {
      method: 'POST', body: bytes, headers: { 'Content-Type': 'text/plain' },
    });
    expect(post.status).toBe(201);
    const ref = (await post.json()) as { artifact_id: string; media_type: string; size_bytes: number; created_at: string };
    expect(ref.artifact_id).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(ref.media_type).toBe('text/plain');
    expect(ref.size_bytes).toBe(bytes.length);
    expect(typeof ref.created_at).toBe('string');

    const get = await fetch(`${base}/artifacts/${ref.artifact_id}`);
    expect(get.status).toBe(200);
    expect(get.headers.get('content-type')).toBe('text/plain');
    expect(Buffer.from(await get.arrayBuffer())).toEqual(bytes);
  });

  it('a tampered artifact is a REFUSAL (409), never wrong bytes', async () => {
    const ref = (await (await fetch(`${base}/artifacts`, { method: 'POST', body: Buffer.from('original') })).json()) as { artifact_id: string };
    // Corrupt the stored bytes under their content address (the store re-verifies on read).
    writeFileSync(join(root, ref.artifact_id.slice('sha256:'.length)), Buffer.from('TAMPERED'));
    const get = await fetch(`${base}/artifacts/${ref.artifact_id}`);
    expect(get.status).toBe(409);
    expect(((await get.json()) as { error: { code: string } }).error.code).toBe('artifact_integrity_failed');
  });

  it('unknown id → 404 artifact_not_found; malformed id → 400 artifact_id_invalid', async () => {
    const missing = 'sha256:' + '0'.repeat(64);
    const r404 = await fetch(`${base}/artifacts/${missing}`);
    expect(r404.status).toBe(404);
    expect(((await r404.json()) as { error: { code: string } }).error.code).toBe('artifact_not_found');

    const r400 = await fetch(`${base}/artifacts/not-an-id`);
    expect(r400.status).toBe(400);
    expect(((await r400.json()) as { error: { code: string } }).error.code).toBe('artifact_id_invalid');
  });

  it('with no store attached, /artifacts is artifact_plane_unsupported (404) both verbs', async () => {
    const get = await fetch(`${noStoreBase}/artifacts/sha256:${'a'.repeat(64)}`);
    expect(get.status).toBe(404);
    expect(((await get.json()) as { error: { code: string } }).error.code).toBe('artifact_plane_unsupported');

    const post = await fetch(`${noStoreBase}/artifacts`, { method: 'POST', body: Buffer.from('x') });
    expect(post.status).toBe(404);
    expect(((await post.json()) as { error: { code: string } }).error.code).toBe('artifact_plane_unsupported');
  });

  it('feature truth: artifact.transfer is ready WITH a store, unsupported without', async () => {
    const withStore = (await (await fetch(`${base}/server`)).json()) as { features: Array<{ feature: string; state: string }> };
    const without = (await (await fetch(`${noStoreBase}/server`)).json()) as { features: Array<{ feature: string; state: string }> };
    const state = (fs: Array<{ feature: string; state: string }>) => fs.find((f) => f.feature === 'artifact.transfer')?.state;
    expect(state(withStore.features)).toBe('ready');
    expect(state(without.features)).toBe('unsupported');
  });
});
