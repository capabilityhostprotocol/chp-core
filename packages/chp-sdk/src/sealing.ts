/**
 * Sealed payloads — payload confidentiality over the evidence chain (chp-v0.2.md
 * §16, proposal 0025). The sibling of selective disclosure: a payload is encrypted
 * to a recipient's X25519 key and replaced with a `{chp_sealed}` marker, keeping
 * its `payload_commitment` so the chain/root/signature verify offline with no key.
 *
 * `chp-sealed-v1` = ephemeral X25519 ECDH → HKDF-SHA256 (info="chp-sealed-v1") →
 * ChaCha20-Poly1305 over canon(plaintext). Byte-compatible with Python
 * `chp_core.sealing`; `node:crypto` only (no new dependency). X25519 raw keys are
 * DER-wrapped exactly as ed25519 keys are in signing.ts (OID 1.3.101.110).
 */

import {
  createPublicKey, createPrivateKey, diffieHellman, hkdfSync, randomBytes,
  createCipheriv, createDecipheriv, generateKeyPairSync, type KeyObject,
} from 'node:crypto';
import { canon, type JsonValue } from './canon.js';

export const SEALED_SCHEME = 'chp-sealed-v1';
export const SEALED_SCHEME_V2 = 'chp-sealed-v2';  // multi-recipient (proposal 0030)
const HKDF_INFO = Buffer.from('chp-sealed-v1', 'utf8');
const X_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex'); // + 32-byte X25519 public
const X_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex'); // + 32-byte X25519 private

const x25519PublicFromRaw = (raw: Buffer): KeyObject =>
  createPublicKey({ key: Buffer.concat([X_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
const x25519PrivateFromRaw = (raw: Buffer): KeyObject =>
  createPrivateKey({ key: Buffer.concat([X_PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });

function canonBytes(payload: JsonValue): Buffer {
  // chp-stable-v1 for hashing = JSON.stringify with sorted keys — identical to the
  // form Python's payload commitment hashes (canon() here matches that).
  return Buffer.from(canon(payload ?? {}), 'utf8');
}

function deriveKey(shared: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), HKDF_INFO, 32));
}

export interface SealedEnvelope { scheme: string; epk: string; nonce: string; ct: string; }
export interface SealedWrap { epk: string; nonce: string; wrapped_key: string; }
export interface SealedEnvelopeV2 { scheme: string; nonce: string; ct: string; recipients: SealedWrap[]; }

/** Generate an X25519 keypair; returns raw 32-byte private + base64 public. */
export function generateEncKeypair(): { privateRaw: Buffer; publicB64: string } {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const pubDer = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const privDer = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
  return { privateRaw: privDer.subarray(privDer.length - 32), publicB64: pubDer.subarray(pubDer.length - 32).toString('base64') };
}

function sealBytes(recipientPubB64: string, plaintext: Buffer): SealedEnvelope {
  const recipient = x25519PublicFromRaw(Buffer.from(recipientPubB64, 'base64'));
  const eskRaw = generateEncKeypair();
  const esk = x25519PrivateFromRaw(eskRaw.privateRaw);
  const key = deriveKey(diffieHellman({ privateKey: esk, publicKey: recipient }));
  const nonce = randomBytes(12);
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const ct = Buffer.concat([enc, cipher.getAuthTag()]); // Python appends the tag to ct
  return {
    scheme: SEALED_SCHEME, epk: eskRaw.publicB64,
    nonce: nonce.toString('base64'), ct: ct.toString('base64'),
  };
}

/** ChaCha20-Poly1305 decrypt with a raw symmetric key (Python appends the tag to ct). */
function chachaDecrypt(key: Buffer, nonceB64: string, ctB64: string): Buffer {
  const ctFull = Buffer.from(ctB64, 'base64');
  const tag = ctFull.subarray(ctFull.length - 16);
  const enc = ctFull.subarray(0, ctFull.length - 16);
  const decipher = createDecipheriv('chacha20-poly1305', key, Buffer.from(nonceB64, 'base64'), { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}

/** Seal to N recipients → chp-sealed-v2 envelope encryption (proposal 0030): one
 * content key encrypts the payload once, wrapped per recipient via a v1 seal. */
function sealBytesMulti(recipientPubB64s: string[], plaintext: Buffer): SealedEnvelopeV2 {
  const cek = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('chacha20-poly1305', cek, nonce, { authTagLength: 16 });
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const ct = Buffer.concat([enc, cipher.getAuthTag()]);
  const recipients = recipientPubB64s.map((pub) => {
    const w = sealBytes(pub, cek);
    return { epk: w.epk, nonce: w.nonce, wrapped_key: w.ct };
  });
  return { scheme: SEALED_SCHEME_V2, nonce: nonce.toString('base64'), ct: ct.toString('base64'), recipients };
}

function unsealBytes(env: SealedEnvelope | SealedEnvelopeV2, encPrivateRaw: Buffer): Buffer {
  if (env.scheme === SEALED_SCHEME) {
    const e = env as SealedEnvelope;
    const priv = x25519PrivateFromRaw(encPrivateRaw);
    const epk = x25519PublicFromRaw(Buffer.from(e.epk, 'base64'));
    const key = deriveKey(diffieHellman({ privateKey: priv, publicKey: epk }));
    return chachaDecrypt(key, e.nonce, e.ct);
  }
  if (env.scheme === SEALED_SCHEME_V2) {
    const e = env as SealedEnvelopeV2;
    let cek: Buffer | null = null;
    for (const r of e.recipients ?? []) {
      try {  // trial-unwrap the content key from this recipient's v1 wrap
        cek = unsealBytes({ scheme: SEALED_SCHEME, epk: r.epk, nonce: r.nonce, ct: r.wrapped_key }, encPrivateRaw);
        break;
      } catch { /* not our wrap — try the next */ }
    }
    if (!cek) throw new Error('no recipient key unwraps this chp-sealed-v2 envelope');
    return chachaDecrypt(cek, e.nonce, e.ct);
  }
  throw new Error(`unknown sealing scheme: ${(env as { scheme?: string }).scheme}`);
}

/** Seal selected chp-event-hash-v2 payloads → `{chp_sealed}` markers (mirrors withholdPayloads). */
export function sealPayloads(
  bundle: Record<string, JsonValue>, recipientEncPubKey: string | string[],
  predicate?: (ev: Record<string, JsonValue>) => boolean,
): Record<string, JsonValue> {
  const multi = Array.isArray(recipientEncPubKey);
  const out = JSON.parse(JSON.stringify(bundle)) as Record<string, JsonValue>;
  for (const ev of (out.events as Array<Record<string, JsonValue>>) ?? []) {
    if (ev.hash_scheme !== 'chp-event-hash-v2' || !ev.payload_commitment) continue;
    const p = ev.payload as Record<string, unknown> | undefined;
    if (p && ('chp_withheld' in p || 'chp_sealed' in p)) continue;
    if (!predicate || predicate(ev)) {
      const pt = canonBytes(ev.payload);
      const env = multi ? sealBytesMulti(recipientEncPubKey, pt) : sealBytes(recipientEncPubKey, pt);
      ev.payload = { chp_sealed: env as unknown as JsonValue };
    }
  }
  return out;
}

/** Decrypt one `{chp_sealed}` marker (v1 or v2) to its plaintext payload. */
export function unsealPayload(marker: Record<string, JsonValue>, encPrivateRaw: Buffer): JsonValue {
  const env = marker?.chp_sealed as unknown as (SealedEnvelope | SealedEnvelopeV2) | undefined;
  if (!env || typeof env !== 'object') throw new Error('not a sealed payload marker');
  return JSON.parse(unsealBytes(env, encPrivateRaw).toString('utf8'));
}

/** Decrypt every `{chp_sealed}` payload back to plaintext (inverse of sealPayloads). */
export function unsealBundle(bundle: Record<string, JsonValue>, encPrivateRaw: Buffer): Record<string, JsonValue> {
  const out = JSON.parse(JSON.stringify(bundle)) as Record<string, JsonValue>;
  for (const ev of (out.events as Array<Record<string, JsonValue>>) ?? []) {
    const p = ev.payload as Record<string, JsonValue> | undefined;
    if (p && 'chp_sealed' in p) ev.payload = unsealPayload(p, encPrivateRaw);
  }
  return out;
}
