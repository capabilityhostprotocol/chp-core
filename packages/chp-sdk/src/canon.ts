/**
 * chp-stable-v1 canonicalization — the byte-exact serialization CHP hashes and
 * signs over (spec/chp-v0.2.md §2). Lifted from spec/test-vectors/verify.mjs,
 * which is proven byte-compatible with Python `json.dumps(sort_keys=True)`.
 *
 * This is the single most bug-prone piece of a CHP implementation. Do NOT
 * replace it with `JSON.stringify` — that emits raw UTF-8, no inter-token
 * spaces, and unsorted keys, all of which diverge from chp-stable-v1.
 */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Escape a string exactly as Python `json.dumps(..., ensure_ascii=True)` does. */
export function encodeStr(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x09) out += '\\t';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0d) out += '\\r';
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else if (c < 0x7f) out += ch;
    else if (c <= 0xffff) out += '\\u' + c.toString(16).padStart(4, '0');
    else {
      // astral code point → UTF-16 surrogate pair, lowercase hex
      const cc = c - 0x10000;
      const hi = 0xd800 + (cc >> 10);
      const lo = 0xdc00 + (cc & 0x3ff);
      out += '\\u' + hi.toString(16).padStart(4, '0') + '\\u' + lo.toString(16).padStart(4, '0');
    }
  }
  return out + '"';
}

/**
 * Serialize a value to its chp-stable-v1 canonical string: recursively sorted
 * keys, `", "` / `": "` separators, ASCII-escaped strings, integers bare.
 *
 * Throws on a non-integer number — chp-stable-v1 forbids floats in canonicalized
 * content (§2 rule 6). Producers string-encode fractional values before hashing.
 */
export function canon(v: JsonValue): string {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) {
      throw new Error(
        `chp-stable-v1 forbids non-integer numbers in canonicalized content: ${v} ` +
          `(string-encode fractional values before hashing — spec §2 rule 6)`,
      );
    }
    return String(v);
  }
  if (typeof v === 'string') return encodeStr(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(', ') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map((k) => encodeStr(k) + ': ' + canon(v[k])).join(', ') + '}';
}

/**
 * Escape a string for chp-jcs-v1 (RFC 8785 §3.2.2.2): raw UTF-8 — only `"`, `\`,
 * and control chars (< 0x20) escape; everything else, including non-ASCII and
 * astral code points, is emitted literally (no `\uXXXX`).
 */
export function encodeStrJcs(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x09) out += '\\t';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0d) out += '\\r';
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += ch; // raw UTF-8 (incl. non-ASCII and astral)
  }
  return out + '"';
}

/**
 * chp-jcs-v1 canonical string (RFC 8785 JCS, proposal 0015): compact separators
 * (`,` / `:`), raw UTF-8 strings, keys sorted by UTF-16 code unit (JS `.sort()`
 * default — matches Python `_canon_jcs`). Over CHP's float-free content the RFC
 * 8785 number algorithm is never exercised: §2 rule 6 is retained, so a
 * non-integer throws just as in {@link canon}.
 */
export function canonJcs(v: JsonValue): string {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) {
      throw new Error(
        `chp-jcs-v1 forbids non-integer numbers in canonicalized content: ${v} (§2 rule 6)`,
      );
    }
    return String(v);
  }
  if (typeof v === 'string') return encodeStrJcs(v);
  if (Array.isArray(v)) return '[' + v.map(canonJcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => encodeStrJcs(k) + ':' + canonJcs(v[k])).join(',') + '}';
}

/** Named canonicalization schemes (the `canonicalization` field, §2). */
export const CANONICALIZATION = 'chp-stable-v1';
export const CANONICALIZATION_JCS = 'chp-jcs-v1';

/**
 * The dispatch seam (§2, proposal 0015): pick the header-signature serializer by
 * a bundle's `canonicalization`. Absent/legacy → chp-stable-v1; an unknown
 * scheme throws (a verifier turns that into a failed signature, never a crash).
 */
export function canonFor(scheme: string | null | undefined): (v: JsonValue) => string {
  if (scheme === CANONICALIZATION_JCS) return canonJcs;
  if (scheme == null || scheme === '' || scheme === CANONICALIZATION) return canon;
  throw new Error(`unknown canonicalization scheme: ${scheme}`);
}
