import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { keypairFromSeed, buildAttestation, buildBundle, signBundle } from '../src/signing.js';
import { verifyBundle, verifyBundleResolved, domainAnchor, resolveHostIdentity } from '../src/verify.js';
import type { EvidenceEvent } from '../src/hash.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const load = (f: string) => JSON.parse(readFileSync(dir + f, 'utf8'));
const SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i));

const stubFetch = (doc: JsonValue, status = 200): typeof fetch =>
  (async () => ({
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(doc),
  })) as unknown as typeof fetch;

describe('anchors (spec §3 Anchors)', () => {
  it('verifies the published anchored vector and reads its domain', () => {
    const bundle = load('signed-bundle-anchored.json') as Record<string, JsonValue>;
    expect(verifyBundle(bundle).valid).toBe(true);
    expect(domainAnchor(bundle.host_identity as Record<string, JsonValue>)).toBe('vector-host.example');
  });

  it('byte-identical signature to Python for the anchored attestation', () => {
    const original = load('signed-bundle-anchored.json') as Record<string, JsonValue>;
    const key = keypairFromSeed(SEED);
    const rebuilt = signBundle(
      buildBundle(original.host_id as string, original.events as EvidenceEvent[], original.created_at as string),
      key,
      { anchors: [{ type: 'domain', domain: 'vector-host.example' }] },
    );
    expect((rebuilt.host_identity as { signature: string }).signature).toBe(
      (original.host_identity as { signature: string }).signature,
    );
  });

  it('strip and staple both break the attestation', () => {
    const bundle = load('signed-bundle-anchored.json') as Record<string, JsonValue>;
    const att = { ...(bundle.host_identity as Record<string, JsonValue>) };
    delete (att as Record<string, unknown>).anchors; // STRIP (downgrade)
    expect(verifyBundle({ ...bundle, host_identity: att }).valid).toBe(false);
    const stapled = {
      ...(bundle.host_identity as Record<string, JsonValue>),
      anchors: [{ type: 'domain', domain: 'evil.example' }], // STAPLE (forgery)
    };
    expect(verifyBundle({ ...bundle, host_identity: stapled }).valid).toBe(false);
  });

  it('resolve mode confirms the anchor against the identity doc', async () => {
    const bundle = load('signed-bundle-anchored.json') as Record<string, JsonValue>;
    const good = await verifyBundleResolved(bundle, {
      fetchImpl: stubFetch({ assurance: 'signed', public_key: bundle.public_key }),
    });
    expect(good.valid).toBe(true);
    expect(good.checks.anchor).toBe(true);
    expect(good.anchoredDomain).toBe('vector-host.example');

    const bad = await verifyBundleResolved(bundle, {
      fetchImpl: stubFetch({ assurance: 'signed', public_key: 'SOMEONE-ELSES-KEY' }),
    });
    expect(bad.valid).toBe(false);
    expect(bad.checks.anchor).toBe(false);
    expect(bad.anchoredDomain).toBe(null);
  });

  it('no-anchor bundle under resolve is visibly TOFU-floor', async () => {
    const bundle = load('signed-bundle.json') as Record<string, JsonValue>;
    const v = await verifyBundleResolved(bundle, { fetchImpl: stubFetch({}) });
    expect(v.valid).toBe(true);
    expect('anchor' in v.checks).toBe(false);
    expect(v.anchoredDomain).toBe(null);
  });

  it('resolution requires https', async () => {
    await expect(resolveHostIdentity('http://acme.example')).rejects.toThrow(/https/);
  });

  it('omit-when-empty: no-anchor attestation bytes unchanged', () => {
    const key = keypairFromSeed(SEED);
    const a1 = buildAttestation('h', key, '2026-01-01T00:00:00Z');
    const a2 = buildAttestation('h', key, '2026-01-01T00:00:00Z', null, []);
    expect((a1 as { signature: string }).signature).toBe((a2 as { signature: string }).signature);
    expect('anchors' in (a1 as object)).toBe(false);
    expect('anchors' in (a2 as object)).toBe(false);
  });
});
