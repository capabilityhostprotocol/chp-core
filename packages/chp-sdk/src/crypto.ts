/**
 * Runtime-neutral crypto for the SDK — works in Node AND the browser, with no `node:crypto` and no
 * `Buffer`. Backed by @noble/hashes + @noble/curves. Byte-compatible with the previous node:crypto
 * path: RFC 8032 Ed25519 is deterministic and SHA-256 is SHA-256, so signatures and hashes are
 * identical. The 362-test suite (run in Node) gates that byte-compatibility; the browser bundle gates
 * that nothing here reaches for a Node built-in.
 */
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, utf8ToBytes, concatBytes };

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** SHA-256 of a UTF-8 string → lowercase hex (the SDK's most common shape). */
export function sha256hex(s: string): string {
  return bytesToHex(nobleSha256(utf8ToBytes(s)));
}

/** SHA-256 of raw bytes → lowercase hex. */
export function sha256hexBytes(data: Uint8Array): string {
  return bytesToHex(nobleSha256(data));
}

// base64 via the global atob/btoa (present in Node 18+ and every browser) — no Buffer.
export function bytesToBase64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

export function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** ed25519 verify — fail-closed (never throws; malformed input → false). */
export function edVerify(msg: Uint8Array, publicKeyRaw: Uint8Array, sig: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, msg, publicKeyRaw);
  } catch {
    return false;
  }
}

/** ed25519 sign over `msg` with a raw 32-byte seed (RFC 8032). */
export function edSign(msg: Uint8Array, seedRaw: Uint8Array): Uint8Array {
  return ed25519.sign(msg, seedRaw);
}

/** Raw 32-byte public key for a raw 32-byte seed. */
export function edPublicFromSeed(seedRaw: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seedRaw);
}

export function randomBytes(n: number): Uint8Array {
  return nobleRandomBytes(n);
}

/** ECDSA-P256 verify over SHA-256(msg) with an SPKI-PEM public key + DER signature (the Rekor SET).
 *  Fail-closed. Runtime-neutral — replaces node:crypto createPublicKey + verify('sha256', …). */
export function ecdsaP256VerifyPem(pem: string, msg: Uint8Array, derSig: Uint8Array): boolean {
  try {
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const spki = base64ToBytes(b64);
    // SPKI DER for an uncompressed P-256 key ends with 0x04‖X‖Y (65 bytes).
    const point = spki.subarray(spki.length - 65);
    return p256.verify(derSig, nobleSha256(msg), point, { format: 'der', prehash: false });
  } catch {
    return false;
  }
}
