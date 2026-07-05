/**
 * SSHSIG verification + did:key codec — the `did` anchor primitives (spec §3.1).
 * TS twin of chp_core/sshsig.py: fully offline, node:crypto only, no shell-out.
 *
 * SSHSIG wire format (OpenSSH PROTOCOL.sshsig):
 *   blob = MAGIC "SSHSIG" || uint32 version || string publickey || string
 *          namespace || string reserved || string hash_alg || string signature
 *   signed payload = MAGIC || string namespace || string reserved
 *                  || string hash_alg || string H(message)
 */

import { createHash, verify as edVerify, createPublicKey } from 'node:crypto';

export const SSHSIG_MAGIC = Buffer.from('SSHSIG');
export const DID_ANCHOR_NAMESPACE = 'chp-host-anchor';
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function b58decode(s: string): Buffer {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new Error(`invalid base58 character ${ch}`);
    n = n * 58n + BigInt(i);
  }
  const hex = n.toString(16);
  let raw = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
  let pad = 0;
  for (const ch of s) { if (ch === B58[0]) pad++; else break; }
  return Buffer.concat([Buffer.alloc(pad), raw]);
}

function b58encode(raw: Buffer): string {
  let n = BigInt('0x' + (raw.toString('hex') || '0'));
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  let pad = 0;
  for (const b of raw) { if (b === 0) pad++; else break; }
  return B58[0].repeat(pad) + out;
}

/** `did:key:z6Mk…` → the raw 32-byte ed25519 public key. */
export function didKeyToRaw(did: string): Buffer {
  if (!did.startsWith('did:key:z')) throw new Error(`not a base58btc did:key: ${did}`);
  const decoded = b58decode(did.slice('did:key:z'.length));
  if (decoded.length !== 34 || !decoded.subarray(0, 2).equals(ED25519_MULTICODEC)) {
    throw new Error('did:key is not an ed25519 multicodec key');
  }
  return decoded.subarray(2);
}

/** Raw 32-byte ed25519 public key → `did:key:z6Mk…`. */
export function rawToDidKey(rawPubkey: Buffer): string {
  if (rawPubkey.length !== 32) throw new Error('ed25519 public key must be 32 bytes');
  return 'did:key:z' + b58encode(Buffer.concat([ED25519_MULTICODEC, rawPubkey]));
}

function readString(buf: Buffer, off: number): [Buffer, number] {
  if (off + 4 > buf.length) throw new Error('truncated SSHSIG blob');
  const n = buf.readUInt32BE(off);
  off += 4;
  if (off + n > buf.length) throw new Error('truncated SSHSIG string');
  return [buf.subarray(off, off + n), off + n];
}

const wireString = (b: Buffer): Buffer => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, b]);
};

export interface ParsedSshsig {
  rawPubkey: Buffer;
  namespace: string;
  hashAlg: string;
  rawSig: Buffer;
}

export function parseSshsig(armored: string): ParsedSshsig {
  const body = armored.trim();
  if (!body.startsWith('-----BEGIN SSH SIGNATURE-----') || !body.endsWith('-----END SSH SIGNATURE-----')) {
    throw new Error('not an armored SSH signature');
  }
  const blob = Buffer.from(body.split('\n').slice(1, -1).join(''), 'base64');
  if (!blob.subarray(0, 6).equals(SSHSIG_MAGIC)) throw new Error('missing SSHSIG magic');
  let off = 6;
  const version = blob.readUInt32BE(off);
  off += 4;
  if (version !== 1) throw new Error(`unsupported SSHSIG version ${version}`);
  let pubBlob: Buffer, namespace: Buffer, hashAlg: Buffer, sigBlob: Buffer;
  [pubBlob, off] = readString(blob, off);
  [namespace, off] = readString(blob, off);
  [, off] = readString(blob, off); // reserved
  [hashAlg, off] = readString(blob, off);
  [sigBlob, off] = readString(blob, off);

  let ktype: Buffer, rawPubkey: Buffer, koff = 0;
  [ktype, koff] = readString(pubBlob, 0);
  if (ktype.toString() !== 'ssh-ed25519') throw new Error(`unsupported key type ${ktype}`);
  [rawPubkey] = readString(pubBlob, koff);

  let stype: Buffer, rawSig: Buffer, soff = 0;
  [stype, soff] = readString(sigBlob, 0);
  if (stype.toString() !== 'ssh-ed25519') throw new Error(`unsupported signature type ${stype}`);
  [rawSig] = readString(sigBlob, soff);

  return { rawPubkey, namespace: namespace.toString(), hashAlg: hashAlg.toString(), rawSig };
}

/** Verify an SSHSIG over `message`: envelope, namespace, signer pin, ed25519. */
export function verifySshsig(
  armored: string,
  message: Buffer,
  opts: { namespace?: string; expectedRawPubkey?: Buffer } = {},
): boolean {
  let parsed: ParsedSshsig;
  try {
    parsed = parseSshsig(armored);
  } catch {
    return false;
  }
  if (parsed.namespace !== (opts.namespace ?? DID_ANCHOR_NAMESPACE)) return false;
  if (opts.expectedRawPubkey && !parsed.rawPubkey.equals(opts.expectedRawPubkey)) return false;
  if (parsed.hashAlg !== 'sha512' && parsed.hashAlg !== 'sha256') return false;
  const digest = createHash(parsed.hashAlg).update(message).digest();
  const payload = Buffer.concat([
    SSHSIG_MAGIC,
    wireString(Buffer.from(parsed.namespace)),
    wireString(Buffer.alloc(0)),
    wireString(Buffer.from(parsed.hashAlg)),
    wireString(digest),
  ]);
  const pub = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, parsed.rawPubkey]),
    format: 'der',
    type: 'spki',
  });
  return edVerify(null, payload, pub, parsed.rawSig);
}
