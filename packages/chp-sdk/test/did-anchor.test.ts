import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyBundle, verifyDidAnchor, didAnchor, didAnchorMessage } from '../src/verify.js';
import { didKeyToRaw, rawToDidKey, verifySshsig } from '../src/sshsig.js';
import type { JsonValue } from '../src/canon.js';

const dir = fileURLToPath(new URL('../../../spec/test-vectors/', import.meta.url));
const bundle = JSON.parse(readFileSync(dir + 'did-anchored-bundle.json', 'utf8')) as Record<string, JsonValue>;
const att = bundle.host_identity as Record<string, JsonValue>;
const anchor = didAnchor(att)!;

describe('did anchor (spec §3.1) — cross-language vs the Python-generated vector', () => {
  it('did:key codec round-trips', () => {
    const raw = didKeyToRaw(anchor.did as string);
    expect(raw.length).toBe(32);
    expect(rawToDidKey(raw)).toBe(anchor.did);
    // the Radicle fixture DID decodes too
    expect(didKeyToRaw('did:key:z6MkuyYxVQL4aRVpAKPbG4tc15FJ9E1ryZSSHjFyqsBBuxAn').length).toBe(32);
  });

  it('verifies the ssh-keygen-produced SSHSIG countersignature natively', () => {
    const msg = didAnchorMessage(bundle.public_key as string, bundle.host_id as string);
    const rawPub = didKeyToRaw(anchor.did as string);
    expect(verifySshsig(anchor.countersignature as string, msg, { expectedRawPubkey: rawPub })).toBe(true);
    expect(verifySshsig(anchor.countersignature as string, Buffer.from('other'), { expectedRawPubkey: rawPub })).toBe(false);
    expect(verifySshsig(anchor.countersignature as string, msg, { expectedRawPubkey: Buffer.alloc(32) })).toBe(false);
  });

  it('verifyBundle checks the did anchor offline and surfaces anchoredDid', () => {
    const v = verifyBundle(bundle);
    expect(v.valid).toBe(true);
    expect(v.checks.did_anchor).toBe(true);
    expect(v.anchoredDid).toMatch(/^did:key:z6Mk/);
  });

  it('a swapped DID fails both did_anchor and host_identity', () => {
    const forged = JSON.parse(JSON.stringify(bundle)) as Record<string, JsonValue>;
    ((forged.host_identity as Record<string, JsonValue>).anchors as Record<string, JsonValue>[])[0].did =
      'did:key:z6MkuyYxVQL4aRVpAKPbG4tc15FJ9E1ryZSSHjFyqsBBuxAn';
    const v = verifyBundle(forged);
    expect(v.valid).toBe(false);
    expect(v.checks.host_identity).toBe(false); // anchor is inside the signed claim
    expect(v.checks.did_anchor).toBe(false);
    expect(v.anchoredDid).toBe(null);
  });

  it('verifyDidAnchor rejects a countersignature for a different CHP key', () => {
    expect(verifyDidAnchor(anchor, 'DIFFERENT-KEY', bundle.host_id as string)).toBe(false);
    expect(verifyDidAnchor(anchor, bundle.public_key as string, 'different-host')).toBe(false);
  });
});
