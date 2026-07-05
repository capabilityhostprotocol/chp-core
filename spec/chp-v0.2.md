# Capability Host Protocol — v0.2 (Evidence Integrity)

Status: draft. **Additive** over [v0.1](chp-v0.1.md); a v0.1-only host remains
conformant at the `none` assurance tier. v0.2 defines an *optional* tamper-
evident evidence layer without changing the v0.1 local-first experience.

Key words MUST, SHOULD, MAY per RFC 2119.

## 1. Assurance Tiers

A host declares one of three evidence assurance tiers:

- `none` — local append-only evidence (v0.1 baseline).
- `hash-chain` — each event carries `content_hash` + `prev_hash` forming a
  per-store SHA256 chain that detects mutation and reordering.
- `signed` — a `hash-chain` bundle whose root hash is signed with the host's
  ed25519 key, detecting tampering by any party without the private key.

A host MUST declare its tier in the `/host` descriptor as `assurance`. A signed
host MUST additionally expose `key_id` and `public_key`. A verifier MUST reject
a tier lower than the one it requires rather than silently degrading.

## 2. Hash Chain (`hash-chain` and above)

Each evidence event MUST carry:
- `content_hash` — SHA256 over the event's canonicalized stable fields
  (`event_id`, `event_type`, `invocation_id`, `capability_id`, `host_id`,
  `correlation_id`, `timestamp`, `outcome`, `payload`) plus the `prev_hash`.
- `prev_hash` — the `content_hash` of the preceding event in the same chain.

The canonicalization scheme MUST be named. This version defines **`chp-stable-v1`**
**byte-exact** so any implementation — in any language — computes the identical
`content_hash` and can verify a signature produced by another. The stable object is:

```
{event_id, event_type, invocation_id, capability_id, host_id,
 correlation_id, timestamp, outcome, payload, prev_hash}
```

where `correlation_id` is extracted from the event's `correlation` object and
`prev_hash` is a member key (null for the first event). It is serialized with
these exact rules (matching Python `json.dumps(obj, sort_keys=True)`):

1. **Object keys sorted** ascending by Unicode code point, **recursively**.
2. **Separators with spaces**: `", "` between members/items, `": "` between key
   and value. (Object `{"a": 1, "b": 2}`, not compact `{"a":1,"b":2}`.)
3. **ASCII-only strings**: every non-ASCII character is escaped as `\uXXXX`
   (lowercase hex; surrogate pairs for astral code points). `"café"` →
   `"café"`. (This supersedes any earlier "over UTF-8" wording.)
4. Standard JSON escapes for `"` `\` and control chars `\b \t \n \f \r`,
   `\u00XX` for other C0 controls.
5. `null`/`true`/`false` lowercase; integers bare; the resulting string is
   UTF-8-encoded (pure ASCII here) and SHA-256'd → lowercase hex `content_hash`.

The **root hash** = SHA-256 over each event's `content_hash`, in sequence order,
each **followed by a `\n`** (`0x0a`) — i.e. `sha256(h1 + "\n" + h2 + "\n" + …)`.
The **signature** (ed25519) is computed over the **ASCII-hex `root_hash` string**
(not the raw digest bytes).

`spec/test-vectors/` publishes fixed inputs → exact `content_hash`, `root_hash`,
and signature (with a fixed key seed), plus `verify.mjs` — a stdlib-only Node
verifier that validates a Python-signed bundle from these rules alone, proving
cross-language interoperability. A future `chp-jcs-v1` (RFC 8785 JCS: compact,
raw-UTF-8) MAY be added non-breakingly via the `canonicalization` field.

Strict verification MUST fail on any event lacking a `content_hash`. Lenient
verification MAY tolerate legacy unhashed events, but MUST NOT be the default
for a host declaring `hash-chain` or `signed`.

## 3. Signed Bundles (`signed`)

A host at the `signed` tier MUST support exporting a correlation as a bundle:

```json
{
  "host_id": "…", "protocol_version": "0.2", "created_at": "…",
  "canonicalization": "chp-stable-v1", "assurance": "signed",
  "events": [ … ], "root_hash": "hex…",
  "public_key": "base64…",
  "host_identity": {
    "host_id": "…", "public_key": "base64…", "key_id": "…",
    "valid_from": "…", "valid_until": null, "signature": "base64…"
  },
  "signature": { "algorithm": "ed25519", "key_id": "…", "signature": "base64…" }
}
```

- `root_hash` MUST be the SHA256 over each event's `content_hash` in sequence
  order. Signing the root (not each event) is REQUIRED.
- **The signature covers the canonical *header***, not just `root_hash`. The
  signed message is `chp-stable-v1(  {host_id, protocol_version, created_at,
  canonicalization, root_hash}  )`. This binds the claimed origin/time/scheme
  into the signature: a relabelled top-level `host_id` (or `created_at`, …)
  MUST fail verification. (Events are bound transitively via `root_hash`.)
- **Host-identity attestation** (`host_identity`): a self-signed statement
  binding `host_id` ↔ `public_key`. `key_id = sha256(pubkey)[:16]` only binds a
  key to *itself* and `host_id` is a free string, so a signed bundle otherwise
  proves *integrity*, not *provenance*. The attestation is
  `chp-stable-v1({host_id, public_key, key_id, valid_from, valid_until})` signed
  by the key. A verifier at the `signed` tier MUST, when `host_identity` is
  present, check that its `host_id`/`public_key` match the bundle and its
  signature verifies under `public_key`. This is the trust *floor* (the key
  self-asserts its host_id — TOFU/`mesh.py:pin_or_check_key` pins it on first
  contact); anchoring `public_key` to a resolvable external identity (e.g. a
  Radicle DID) is the ceiling and is OPTIONAL.
- A verifier MUST check: per-event hash recompute, chain continuity, root hash,
  the header signature, and (when present) the host-identity attestation. A
  verifier offered an `expected_key_id` MUST reject a bundle signed by any other
  key.

Key rotation uses `valid_from`/`valid_until` in the `host_identity` attestation;
a rotated key is a new identity. A verifier MUST reject a signed bundle whose
`created_at` falls outside the attestation's `[valid_from, valid_until]` window
(the key had expired when it signed) — enforced offline against `created_at`, so
no wall clock or revocation infrastructure is required at this tier. `null`
bounds are unbounded. Chained rotation (a new key countersigned by the old) and
a published key-transparency registry are deliberately out of scope until
cross-organization verification is a live requirement.

## 4. Retention (all tiers)

Retention MUST NOT break the verifiability of retained evidence. An
implementation MUST prune at whole-correlation granularity (or an equivalent
that never orphans a survivor's `prev_hash`). Payload redaction that rewrites a
stored event MUST clear that event's `content_hash` (rendering it `unverified`)
rather than leave a hash that no longer matches.

## 5. Transport / Auth (informative for v0.2)

HTTP hosts MUST compare authentication credentials in constant time. A host
SHOULD bind an authenticated caller to a verified `subject` on the evidence it
records. Network-layer confidentiality (e.g. a private mesh) MAY substitute for
transport TLS.

## 6. Conformance

v0.2 adds these checks to the runner (gated by declared tier):
`signed evidence bundle`, `strict verify rejects unhashed`,
`retention preserves chain`. A host declaring a tier MUST pass the checks for
that tier and below.
