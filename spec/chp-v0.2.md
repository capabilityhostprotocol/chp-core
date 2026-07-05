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
5. `null`/`true`/`false` lowercase; integers bare.
6. **No non-integer numbers.** Canonicalized content MUST NOT contain a JSON
   *float*. Float-to-string serialization is not portable — Python `json.dumps`
   emits `0.0` where an ECMAScript `Number.toString` emits `0`, so the same value
   would hash differently across languages. A value that is conceptually
   fractional (e.g. a safety `score`, an autonomy `spend`) MUST be represented in
   canonicalized fields as a **string** (fixed precision, e.g. `"0.000"`) or a
   scaled integer. Producers put the human/float form only in non-hashed surfaces
   (an `InvocationResult.data`, an OTel attribute), never in an evidence event
   payload. (This is the one place `chp-stable-v1` deliberately narrows JSON.)
7. The resulting string is UTF-8-encoded (pure ASCII here) and SHA-256'd →
   lowercase hex `content_hash`.

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
  contact); **Anchors** (§3.1) upgrade the floor by binding the key to an
  external trust root a never-met verifier can resolve.
- A verifier MUST check: per-event hash recompute, chain continuity, root hash,
  the header signature, and (when present) the host-identity attestation. A
  verifier offered an `expected_key_id` MUST reject a bundle signed by any other
  key.

A `signed` host SHOULD also serve its `host_identity` attestation on the `/host`
descriptor, so a mesh peer can verify the key self-attests this `host_id` (and is
within its validity window) **before** trust-on-first-use pinning it — rather than
pinning whatever `/host` self-reports. This is the same offline
`verify_attestation` check the bundle path uses.

Key rotation uses `valid_from`/`valid_until` in the `host_identity` attestation.
A verifier MUST reject a signed bundle whose `created_at` falls outside the
attestation's `[valid_from, valid_until]` window (the key had expired when it
signed) — enforced offline against `created_at`, so no wall clock is required.
`null` bounds are unbounded. Chained rotation and revocation are specified in
§3.2.

### 3.1 Anchors — cross-org trust

An **anchor** binds the signing key to an external trust root a never-met
verifier can resolve, upgrading a bundle from *integrity* (TOFU floor) to
*provenance* ("root R vouches for key P"). Anchors are an OPTIONAL list inside
the **signed attestation claim**:

```json
"host_identity": {
  "host_id": "…", "public_key": "…", "key_id": "…",
  "valid_from": "…", "valid_until": null,
  "anchors": [ {"type": "domain", "domain": "acme.example"} ],
  "signature": "base64…"
}
```

- **Omit-when-empty (byte rule).** The `anchors` key MUST be omitted from the
  claim entirely when there are no anchors — never emitted as `[]` or `null`.
  A no-anchor attestation is thus byte-identical to the pre-anchor format
  (`spec/test-vectors/signed-bundle.json` is the compatibility gate). A verifier
  reconstructs the claim with the same conditional: `anchors` participates in
  the signed bytes exactly when the attestation carries it. Because anchors are
  inside the signed claim, **stripping** one (downgrade) or **stapling** one on
  (forgery) breaks the self-signature. Anchor values MUST NOT contain
  non-integer numbers (§2 rule 6); array order is preserved as built.
- **The anchor is the trust root; `host_id` is a local label.** A verifier MUST
  surface *which root vouched* (e.g. the resolved domain) as the answer to
  "whose?", and MUST NOT treat `host_id` as trusted. An attacker-controlled
  anchor "verifies" — against *the attacker's root*; the trust decision belongs
  to the caller reading the surfaced root.
- **`domain` anchor.** Proves: "the entity in administrative control of the
  domain (DNS + TLS certificate + server) asserts key P is its CHP signing
  key" — the Web-PKI chain, the RFC 8615 / MTA-STS pattern. The host MUST serve
  its identity document at `GET /.well-known/chp-identity` **without
  authentication** (`{assurance, key_id, public_key, host_identity}` — key
  material only; capabilities stay behind auth). A resolving verifier MUST
  fetch over `https://` only and MUST NOT follow redirects; it confirms the
  bundle's `public_key` appears in the resolved document. Resolution proves
  *current* control of the anchor; the attestation window proves *validity at
  signing time* — the two are distinct and both recorded. Unknown anchor types
  MUST be skipped (forward compatibility); if resolution was requested and no
  anchor type is understood, the result is *unverifiable provenance*, never
  success. A no-anchor bundle under a resolving verifier remains valid at the
  visibly-TOFU floor.
- **`did` anchor.** Proves: "the holder of the ed25519 identity behind
  `did:key:z6Mk…` countersigned this CHP key" — fully **offline**, no CA/DNS.
  Shape: `{"type": "did", "did": "did:key:z6Mk…", "countersignature": "<armored
  SSHSIG>"}`. The countersignature is an OpenSSH **SSHSIG** (`ssh-keygen -Y
  sign`) with namespace **`chp-host-anchor`** over the message
  `chp-stable-v1({"chp_public_key": <base64 CHP key>, "host_id": <host_id>})`.
  The DID is multibase(base58btc) of multicodec(`0xed01`) + the raw 32-byte
  ed25519 public key (for a Radicle node, byte-identical to `"did:key:" + NID`).
  A verifier MUST decode the DID to the raw key, pin the SSHSIG signer to it,
  and verify the SSHSIG payload (`SSHSIG || namespace || reserved || hash_alg ||
  H(message)`). `spec/test-vectors/did-anchored-bundle.json` is the fixture
  (produced by a real `ssh-keygen -Y sign` with a fixed-seed key). Verification
  is offline and MUST run whenever a `did` anchor is present.
- A host MAY carry multiple anchors so verifiers choose their preferred root;
  further anchor types extend the same list.
- **Stated tradeoff:** the `domain` anchor deliberately leans on Web-PKI
  (CA + DNS) as the buildable, standards-aligned floor-above-TOFU; the `did`
  anchor is the decentralized ceiling that removes that dependency.

### 3.2 Key lifecycle — rotation with continuity, revocation

Rotation MUST NOT destroy the old key (archive it) and MUST NOT be
indistinguishable from impersonation. On rotation the **old** key signs a
self-contained **continuity statement**:

```json
{ "old_key_id": "…", "old_public_key": "…", "new_key_id": "…",
  "new_public_key": "…", "rotated_at": "…", "signature": "<by the OLD key>" }
```

The host publishes its lineage as `key_history` (an ordered list of continuity
statements) on the identity document / `/host`. A verifier holding a pinned key
that encounters a changed key MUST accept it **only** by walking the continuity
chain from its own pinned key — each hop verified under the key trusted *so
far*, starting from the verifier's pin, never from the remote's self-published
`old_public_key` — and re-pin with trust `rotated`. A change with no valid
chain remains a hard mismatch. (The remote's history cannot vouch for itself.)

**Revocation** is a self-signed statement by the revoked key
(`{revoked_key_id, revoked_public_key, revoked_at, reason, signature}`)
published as `revoked_keys` on the identity document. A resolving verifier
(`resolve=True`) MUST reject a bundle signed by a key the resolved document
revokes (`not_revoked` check). **Offline verifiers cannot see revocations** —
a stated limit of this tier; there is no global revocation infrastructure.

**Identity evidence.** The lifecycle is recorded on the host's **own**
hash-chained store via the reserved host-self event family
`IDENTITY_EVIDENCE_TYPES` = {`key_generated`, `key_rotated`, `key_revoked`,
`identity_anchored`} (governance §4.4) under the correlation
`host-identity-<host_id>`. The chain's append-only, tamper-evident ordering
makes it the host's **key-transparency log**, exportable and verifiable like
any evidence bundle. This is the first evidence family that describes the host
itself rather than a capability invocation.

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

## 7. Cross-host ordering — `chp-causal-order-v1`

A task's evidence may span multiple hosts sharing one `correlation_id` (the
gateway forwards the caller's correlation unchanged). v0.1 §10 left cross-host
ordering undefined; this section defines it. Given the events of ONE
correlation gathered from N hosts, a conforming implementation MUST produce
this total order:

- **Sort key** `K(e) = (timestamp, host_id, sequence, event_id)` — string
  components compared **byte-wise over UTF-8** (case-sensitive; a locale or
  case-folding comparator is non-conforming), missing strings as `""`, missing
  `sequence` as `0`.
- **Happens-before edges:** (1) events with equal `host_id` are ordered by
  `sequence`; (2) an event whose `correlation.causation_id` names invocation
  `C` is ordered after the K-minimal event carrying `invocation_id == C`
  (the *causal spawn* edge), when that event is present in the set.
- **Algorithm:** Kahn's topological sort whose ready set is ordered by K
  (pop-minimum). Because `(host_id, sequence)` is unique per event, K is a
  total order and the output is **deterministic** — independent of input
  order and identical across implementations. On cyclic input (possible only
  with tampered or malformed data) the remainder MUST be emitted in K order;
  the function is total, and cycle *detection* is a verification concern
  (task-bundle verification).

The K tiebreak orders **causally-unrelated** (concurrent) events only; it is
arbitrary-but-deterministic, not a claim about real time — wall clocks skew,
and a causal edge always overrides timestamps (a child spawned cross-host is
ordered after its cause even when the child host's clock reads earlier).
Known limit: only the spawn edge is causal; a synchronous parent's terminal
event is placed by K, not by an edge.

`spec/test-vectors/ordering.json` pins a shuffled 3-host input (with a skewed
clock and a byte-order tiebreak trap) and its exact expected order; both
reference implementations reproduce it (`chp_core/ordering.py`,
`chp-sdk/src/ordering.ts`).

Correlation-context notes: `trace_id` is OPTIONAL/reserved — when present, a
W3C trace-context trace id (the OTel exporter uses it and falls back to
`correlation_id`); `baggage` is reserved for forward compatibility;
`parent_correlation_id` is informative session-threading linking a spawned
task's correlation to its spawning session — it is NOT part of
chp-causal-order-v1, which operates within one `correlation_id`.

## 8. Task Bundles — cross-host verification

A **task bundle** makes a task spanning N hosts verifiable **as a unit**. It
aggregates one correlation's per-host bundles, byte-untouched:

```json
{
  "kind": "task-bundle",
  "correlation_id": "…", "created_at": "…",
  "protocol_version": "0.2", "canonicalization": "chp-stable-v1",
  "assurance": "signed",
  "bundles": [ { …signed per-host bundle… }, … ],
  "task_root_hash": "hex64"
}
```

- **Members are byte-untouched** signed bundles (§3) — their signatures remain
  independently verifiable. Members MUST be sorted by `(host_id, root_hash)`,
  byte-wise, so assembly order is irrelevant: two aggregators assembling the
  same members produce identical bytes.
- **`task_root_hash`** = SHA-256 over each member's `root_hash` in array order,
  each followed by `\n` — the §2 root-hash pattern one level up. It is the
  task's single tamper-evident fingerprint: swapping, adding, or dropping any
  member changes it.
- **`assurance`** MUST be the MINIMUM member tier — degradation is surfaced,
  never hidden. There is no aggregator signature at this tier (member
  signatures prove each part's origin); the format admits one later via the
  omit-when-empty pattern.

**Verification** (all MUST pass): structure; canonical member order;
`task_root_hash` recompute; every member verifies fully under §3 (chain, root,
header signature, attestation, anchors); every event carries the task's
`correlation_id`; member `host_id`s are pairwise distinct; **causal closure** —
every non-null `causation_id` in any member resolves to an `invocation_id`
present in the union of members (no dangling causal references); and the
chp-causal-order-v1 edge set over the union is **acyclic**. The verifier MUST
surface per-member identity (host_id, key_id, assurance, anchors) — who
contributed what, under which trust root.

**Completeness limit (normative):** task-bundle verification proves the
integrity of every included part, the cryptographic identity of every
contributor, and causal closure. It does NOT prove the absence of evidence: a
causal *ancestor* cannot be silently dropped (its children's `causation_id`s
would dangle), but a *leaf* contributor — a host whose invocations nothing else
references — can be omitted undetectably. Participation manifests /
absence-proofs are out of scope at this tier.

`spec/test-vectors/task-bundle.json` is the fixture (two fixed-seed hosts with
cross-host causation); `verify.mjs` verifies it from these rules alone.
