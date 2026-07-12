# CHP Protocol Changelog

Protocol- and schema-level changes only (implementation changes live in package
release notes). Format follows [Keep a Changelog](https://keepachangelog.com/).
Every entry that changes canonical bytes or wire behavior names its regression
gate.

## [0.6.3] — Remote log monitor over 0.6.2

### Added
- **Remote log monitor** (chp-v0.2.md §12,
  [proposals/0024](proposals/0024-remote-monitor.md)): a monitor holding only a
  host's immutable anchor history (no store copy) asks the host to serve a
  consistency proof between each anchored pair — `GET /head/consistency?first=&
  second=` (authed; reconstructs both heads via `get_store_head(fresh)` +
  `store_head_consistency_proof`) — and verifies it against the anchored roots. A
  host that rewrote history reconstructs a different head, so its proof carries
  `first_root ≠` the immutable anchor and is rejected: a rewrite is caught with no
  store copy. Emits the 0023 `store-head-monitor-report`. Scales independent
  oversight — an auditor tracks many hosts holding only kilobytes of anchors.

### Compatibility
- **Additive, no byte changes, no new schema/denial code.** The endpoint serves a
  `store-head-consistency` object (0022); the finding is a
  `store-head-monitor-report` (0023). Regression gate: a conformance wire check —
  a chp-store-head-v2 host serves `/head/consistency` between two sequences and a
  remote monitor verifies it against the anchors — passes against both reference
  hosts.

## [0.6.2] — Log monitor / fork detection over 0.6.1

### Added
- **Log monitor** (chp-v0.2.md §12,
  [proposals/0023](proposals/0023-log-monitor.md)): a monitor walks a host's
  external store-head-anchor history and, for each anchor `(sequence N, root R)`,
  reconstructs the head as-of N from the live store (`get_store_head(fresh)`) and
  checks it still equals R. A mismatch is a provable **rewrite** — an edited or
  dropped old event moves every root ≥ its sequence while the external anchor is
  immutable. The monitor emits a signed `store-head-monitor-report`
  (`verdict: consistent | forked`, a `divergence` block when forked), offline-
  verifiable and living with the monitor, not the monitored host. Operationalizes
  the transparency log (0019 inclusion + 0022 consistency gave the math).

### Compatibility
- **Additive, no byte changes, no new denial code.** The monitor reads existing
  anchors and reconstructs existing heads; the only new artifact is its own signed
  report. Regression gate: the `store-head-monitor-report` vector verifies byte-
  identically in Python, the TS SDK, and stdlib `verify.mjs` (a faithful history →
  `consistent`; a rewritten one → `forked` at the right sequence); the byte gate
  shows only that new vector.

## [0.6.1] — Merkle consistency proofs over 0.6.0

### Added
- **Merkle consistency proofs** (chp-v0.2.md §12,
  [proposals/0022](proposals/0022-merkle-consistency.md)): an RFC 6962 §2.1.2
  consistency proof over the `chp-store-head-v2` tree proves a later store head
  is an **append-only** extension of an earlier one — a third party holding two
  anchored roots + the proof verifies, witness-free and offline, that no old
  correlation was dropped, altered, or reordered between the heads. New
  `store-head-consistency` object; completes the transparency log from 0019
  (inclusion = a leaf is present; consistency = the tree only grew).

### Compatibility
- **Additive, no byte changes.** No leaf bytes, tree construction, head signing,
  witness header, or anchor message change — a consistency proof is computed over
  roots that already exist. `chp-store-head-v1` (the flat fold) stays the default
  and has no consistency proof. Regression gate: the new `store-head-consistency`
  test vector verifies byte-identically in Python, the TS SDK, and stdlib
  `verify.mjs`; the byte gate shows only that new vector.

## [0.6.0] — in-toto / DSSE attestation bridge over 0.5.1

### Added
- **in-toto / DSSE attestation export** (chp-v0.2.md §15,
  [proposals/0021](proposals/0021-intoto-dsse.md)): a signed CHP bundle → a
  standard **in-toto Statement** (`subject: [{name: correlation_id, digest:
  {sha256: root_hash}}]`, `predicateType:
  https://chp.dev/attestation/evidence-bundle/v1`, `predicate: <the bundle>`)
  wrapped in a **DSSE envelope** (`payload`/`payloadType:
  application/vnd.in-toto+json`/`signatures`), signed by the host ed25519 key
  over the DSSE **PAE**. Portable into the Sigstore/in-toto/SLSA ecosystem: any
  DSSE verifier checks the PAE signature; a CHP verifier additionally re-verifies
  the embedded bundle (`verify_bundle`) and the subject digest. Lossless
  round-trip. New `dsse-envelope` + `in-toto-statement` schemas; `chp bundle
  attest` / `chp attest verify`.

### Compatibility
- **Additive, no bytes move.** A CHP bundle is *wrapped, not modified* — every
  existing bundle, vector, and signature is byte-identical (byte gate holds). No
  new denial code or evidence type; the output conforms to the upstream
  in-toto/DSSE specs (like the OTel/PROV exports). **Minor** bump (v0.6.0) — a
  new signed-artifact family + standards interop surface, though no existing
  bytes move.

### Regression gate
- The byte gate: every `spec/test-vectors/` fixture verifies unchanged; the new
  `dsse-attestation.json` is the only addition, its PAE signature + embedded
  bundle verified by Python, the TS SDK, and the stdlib `verify.mjs`.
  `spec_defines_dsse_bridge` + `attestation_vector_verifies` guards.

## [0.5.1] — security model over 0.5.0

### Added
- **Security model** (spec/chp-security-model.md,
  [proposals/0020](proposals/0020-security-model.md)): a new normative doc — a
  **properties matrix** (guarantee × adversary × residual-risk) consolidating the
  guarantee and honest-boundary language scattered across chp-v0.2.md §1–§14 and
  every proposal. Adversary classes: honest-verifier, malicious host/operator,
  network adversary, colluding peers, external relying-party. Each mechanism cell
  states its guarantee and its residual risk in the spec's own words. Supersedes
  the v0.1-only `docs/security/threat-model-v0.1.md`; linked from SECURITY.md and
  indexed in spec/README.md. Three `protocol_checks` guards keep it in sync:
  `spec_defines_security_model`, `security_model_names_denial_codes` (every
  reserved denial code referenced), `security_model_names_schemes` (every scheme
  referenced) — a new code/scheme cannot ship without appearing in the matrix.

### Compatibility
- **Non-wire, additive.** No schema, canonicalization, hashing, or signing change
  — every `spec/test-vectors/` fixture verifies unchanged (byte gate trivially
  clean). A consolidation doc + three alignment guards. **Patch** bump (v0.5.1).
  No TypeScript change (SDK/host unaffected).

### Regression gate
- The three security-model guards (alignment 87 → 90); the byte gate is
  trivially clean (no signed object touched).

## [0.5.0] — Merkle store head + inclusion proofs over 0.4.3

### Added
- **`chp-store-head-v2` — a transparency-log store head** (chp-v0.2.md §12,
  [proposals/0019](proposals/0019-transparency-log.md)): the flat SHA-256 fold
  becomes an **RFC 6962** (Certificate Transparency) Merkle tree over the same
  sorted per-correlation leaves (domain-separated: leaf `SHA256(0x00‖…)`, node
  `SHA256(0x01‖L‖R)`, split at the largest power of two). An **inclusion proof**
  (`{leaf_index, tree_size, audit_path}`) lets a party holding only the signed/
  anchored root + one correlation's `(id, head_hash)` verify inclusion **with no
  leaves snapshot and no witness** — the third-party, witness-free verification
  deferred in 0018/0013. A `store_head_root(scheme, leaves)` dispatcher (the §2
  canonicalization pattern) folds v1 or builds the v2 root; `get_store_head`
  defaults to v1. The store-head-anchor carries it (self-describing
  `store_head_scheme`, omit-when-absent), and `audit_completeness` gains a
  non-witness anchor+proof path. New schema `store-head-inclusion`.

### Compatibility
- **Additive, no bytes move.** `chp-store-head-v1` stays the default and
  byte-identical; the chain-witness header, store-head-anchor, and quorum compare
  sign/compare `store_head` **opaquely**, so a v2 root slots in with no signing
  change — every existing head, receipt, anchor, and vector is byte-identical.
  New optional `store_head_scheme` (omit-when-absent). **Minor** bump (v0.5.0) —
  a second store-head scheme + third-party inclusion is a headline capability
  (like `chp-event-hash-v2` = v0.3.0, `chp-jcs-v1` = v0.4.0), though no existing
  bytes move.

### Regression gate
- The byte gate: every `spec/test-vectors/` fixture verifies unchanged; new
  `store-head-v2.json` + `store-head-inclusion.json` are the only additions,
  verified byte-identically by Python, the TS SDK, and the stdlib `verify.mjs`
  (RFC 6962 pinned). `spec_defines_store_head_v2` + `store_head_v2_root_recomputes`
  + `inclusion_vector_verifies` guards; a `check_store_head_inclusion` wire check.

## [0.4.3] — non-omission / completeness over 0.4.2

### Added
- **Non-omission / completeness proofs** (chp-v0.2.md §12,
  [proposals/0018](proposals/0018-non-omission.md)): the answer to *"what stops a
  host hiding events?"* `verify` already rejects leading/interior/suffix drops
  (genesis + link continuity), so **`chp-completeness-v1`** closes the last two —
  tail-truncation and whole-correlation omission. A signed bundle MAY carry a
  `completeness` block — `{scheme, correlation_id, as_of_sequence, head_hash}`,
  bound into the signed bundle header **omit-when-absent**. A verifier self-checks
  it against the bundle (head_hash = the tail, genesis contiguity already
  enforced), then `audit_completeness` compares it to witnessed store-head receipts:
  a witnessed `leaves[correlation_id]` that advanced past `head_hash` is a provable
  dropped tail (**incomplete**); a matching leaf is **complete**; a correlation no
  witness saw is **unwitnessed** (the honest boundary — recording can't be forced).
  The store head already commits per-correlation tails, so no head/chain-witness
  change. `evidence-bundle` schema gains an optional `completeness` block.

### Compatibility
- **Additive, no bytes move.** The `completeness` block is optional and
  omit-when-absent — no canonicalization/hashing/signing change, every published
  vector + signed bundle byte-identical. No new denial code or evidence type; the
  `hash_scheme` axis is orthogonal. **Patch** bump (v0.4.3) — a new commitment +
  a witness-side audit, no wire surface added (consistent with 0010's v0.2.9).

### Regression gate
- The byte gate: every `spec/test-vectors/` fixture verifies unchanged; the new
  `signed-bundle-complete.json` is the only addition. A completeness bundle
  verifies + audits `complete` against a matching witnessed head, and `incomplete`
  against a fresher one; `spec_defines_completeness` + `completeness_vector_verifies`
  guards; a `check_completeness` wire check runs against both reference hosts.

## [0.4.2] — key custody at rest over 0.4.1

### Added
- **Encrypted-at-rest host keys** (chp-v0.2.md §3,
  [proposals/0017](proposals/0017-key-custody.md)): a signed host MAY hold its
  ed25519 key **passphrase-encrypted** (PKCS#8 under `BestAvailableEncryption`),
  unlocked from `$CHP_KEY_PASSPHRASE`, an OS keychain, or a prompt at load.
  Opt-in — `generate_keypair(…, passphrase=…)` encrypts; the default keygen and
  every existing key file stay Raw+base64. `load_host_key` auto-detects the
  format (PEM header → decrypt; else legacy). A custody concern only: the
  unlocked key produces byte-identical signatures/attestations/bundles.
- **Schema `$id` consistency**: the two off-domain `$id`s
  (`certification-record`, `invocation-metrics`) normalized onto the canonical
  `https://chp.dev/schemas/v0.X/…` base; new `schema_ids_consistent` alignment
  guard asserts the single base + `$ref`↔`$id` integrity.

### Compatibility
- **Additive, no wire bytes move.** Encryption is at-rest only — no signature,
  attestation, bundle, or test vector changes (the byte gate holds). The default
  key format is unchanged. The schema change rewrites two `$id` strings nothing
  references; all 35 schemas still validate. **Patch** bump (v0.4.2) — a custody
  recommendation + a schema-hygiene fix, no wire surface added.

### Regression gate
- The byte gate: every `spec/test-vectors/` fixture verifies unchanged (no
  signed object touched). A key round-trip test signs a bundle from an
  encrypted key and verifies it byte-identically to an unencrypted one;
  `schema_ids_consistent` + the schema-registry test hold.

## [0.4.1] — wire-version negotiation over 0.4.0

### Added
- **Wire-version negotiation** (chp-v0.2.md §1.1, chp-http-binding.md §2,
  [proposals/0016](proposals/0016-wire-version-negotiation.md)): the path a
  non-additive change would travel, specified before it is needed. A host
  declares **`supported_versions`** on `/host` (the ordered wire lineage it
  speaks; **absent → `[protocol_version]`**). A client selects the highest
  mutually-supported version — `negotiate_version(client, host)`, `(major,minor)`
  compare, `None` on disjoint — and MAY declare it via the optional
  **`X-CHP-Version`** request header. A host receiving an explicit unsupported
  version MUST reject with HTTP `400` + the new reserved denial code
  **`version_unsupported`** rather than silently degrading (the tier-rejection
  rule extended to the wire version). `host-descriptor` schema gains
  `supported_versions`; the reserved denial-code registry gains
  `version_unsupported`.

### Compatibility
- **Additive, no bytes move.** `supported_versions` defaults to
  `[protocol_version]` when absent (existing descriptors unchanged);
  `X-CHP-Version` absent → today's behavior; `version_unsupported` is a new
  reserved code. No canonicalization/hashing/signing change — the bundle-header
  `protocol_version` stays `"0.2"`, byte-identical to every vector. Also collapses
  the three disconnected version literals onto `SUPPORTED_VERSIONS`/
  `PROTOCOL_VERSION` and fixes the `/host` descriptor reporting `"0.1"` in-process
  vs `"0.2"` over HTTP. **Patch** bump (v0.4.1) — adds a field, a header, and a
  code; moves no existing bytes.

### Regression gate
- The byte gate: every `spec/test-vectors/` fixture verifies unchanged (no
  signed object gained a field). Behavioral, exercised over the wire — the
  conformance `wire` suite gains a version-negotiation check (declare → select →
  reject) run against both reference hosts; a `protocol_checks` alignment guard
  asserts the spec defines the mechanism and the descriptor declares
  `supported_versions`.

## [0.4.0] — second canonicalization over 0.3.3

### Added
- **chp-jcs-v1 — the second canonicalization** (chp-v0.2.md §2,
  [proposals/0015](proposals/0015-chp-jcs.md)): the `canonicalization` field
  becomes a real **dispatch seam**. A verifier selects the header-signature
  serializer by the bundle's `canonicalization` value (absent/legacy →
  `chp-stable-v1`). **`chp-jcs-v1`** is RFC 8785 JCS — compact separators
  (`,`/`:`), raw-UTF-8 strings (no `\uXXXX`), keys sorted by UTF-16 code unit.
  §2 rule 6 (no floats in hashed content) is retained across all schemes, so RFC
  8785's number-formatting algorithm is never exercised (deferred). Governs the
  bundle-header signature only (the per-event content-hash is the orthogonal
  `hash_scheme` axis). `evidence-bundle` schema `canonicalization` enum widens to
  `["chp-stable-v1", "chp-jcs-v1"]`.

### Compatibility
- **Additive, chp-stable-v1 byte-identical.** chp-stable-v1 is the default; a
  bundle that omits `canonicalization` or names it is unchanged, and every
  published vector + signed bundle is byte-identical. Statement schemas stay
  `const chp-stable-v1` (statement-level JCS deferred). No new denial code or
  evidence type; the `hash_scheme` axis is untouched. **Minor** bump (v0.4.0) —
  a second canonicalization is the 1.0-readiness milestone, though no existing
  bytes move.

### Regression gate
- New vectors `canon/cases-jcs.json` (JCS byte-exact over the §2 golden inputs)
  + `signed-bundle-jcs.json` (a chp-jcs-v1-signed bundle); `git diff
  spec/test-vectors/` shows only those. Guards `spec_defines_chp_jcs` +
  `jcs_canon_cases_verify` + `jcs_bundle_verifies`. Three implementations
  (Python `_canon_jcs`, TS `canonJcs`, stdlib `verify.mjs`) agree byte-for-byte;
  both reference hosts verify a chp-jcs-v1 bundle.

### Deferred
- RFC 8785 ES double-to-shortest number canonicalization (unexercised — rule 6
  retained); JCS event-content-hashes / a JCS-native store; statement-level JCS
  dispatch (mandate/witness/anchor/provenance/task headers).

## [0.3.3] — additive over 0.3.2 — **released 2026-07-11**

### Added
- **Gateway exactly-once** (chp-v0.2.md **§13.2**,
  [proposals/0014](proposals/0014-gateway-exactly-once.md)): idempotent replay
  (§13) extended across a routing gateway's owner set. A gateway maintains a
  **result cache keyed by the client's `invocation_id`** — it preserves the id
  end-to-end (client → gateway → owner), checks the cache **before routing**
  (a hit returns `"replayed": true` and routes to no owner), and records a
  **definitive** processed outcome (a retryable `host_unreachable` is NOT
  cached). Spanning owners AND gateway restarts, this makes a client retry
  exactly-once across owner selection, failover, and restart — closing the
  cross-owner double-execution the per-host §13 cache could not.

### Compatibility
- **Behavioral, no byte changes.** The gateway result cache is serving state
  (never chained); the `replayed:true` marker already exists. No new canonical
  object, denial code, evidence type, schema, or test vector — every published
  vector is byte-identical. Python-gateway-only (the TS host is a mesh member,
  not a gateway). A gateway with no store skips the cache (best-effort).

### Regression gate
- Guard `spec_defines_gateway_exactly_once`. New mesh conformance check
  `check_mesh_exactly_once` (a retried client `invocation_id` replays at the
  gateway with no owner re-execution; it STILL replays after the serving owner
  is killed). `git diff spec/test-vectors/` is empty.

### Deferred
- The lost-response-before-gateway residual (owner executed, gateway never saw
  the result → cross-owner failover still double-executes); owner-pinned /
  shared caches; multi-gateway distributed dedupe + cache replication.

## [0.3.2] — additive over 0.3.1 — **released 2026-07-11**

### Added
- **Witness quorum + external anchoring** (chp-v0.2.md §12,
  [proposals/0013](proposals/0013-witness-quorum.md)). **`chp-witness-quorum-v1`**:
  an auditor aggregates the `chain-witness` statements over a host's head,
  verifies each, keeps only those over the exact `(host_id, sequence,
  store_head)`, **dedupes by the witness's `key_id`**, optionally restricts to a
  trusted witness set, and counts → verdict **`quorum_met`** (distinct ≥ k) /
  **`quorum_short`**. Policy (`witness_quorum_k`, optional `witness_set`) is host
  config; the witness loop is unchanged. **`chp-store-head-anchor-v1`**: a new
  optional `store-head-anchor` statement where an external `did:key` **SSHSIG-
  countersigns** `chp-stable-v1({kind, host_id, sequence, store_head,
  anchored_at})` (namespace `chp-store-head-anchor`), verified offline — an
  independent, out-of-mesh record of a head. New `store-head-anchor` schema.

### Compatibility
- **Additive, no byte changes.** Quorum introduces NO canonical object — it
  counts existing `chain-witness` statements, so `chain-witness.json` /
  `chain-witness-revfresh.json` and every other vector are byte-identical. The
  `store-head-anchor` statement is a new optional standalone object. No new
  denial code, no new evidence type, no store-head change. `quorum_short` is an
  audit verdict, never a gate denial.

### Regression gate
- New vectors `witness-quorum.json` + `store-head-anchor.json`; `git diff
  spec/test-vectors/` shows only those. Guards `spec_defines_witness_quorum` +
  `witness_quorum_vector_verifies` + `store_head_anchor_vector_verifies`. Both
  reference hosts pass the new wire check (k distinct witnesses → `quorum_met`;
  k-1 → `quorum_short`; an anchored head verifies).

### Deferred
- Real Rekor/Sigstore transparency-log Merkle-inclusion proofs + gossip;
  federated cross-witness collection to defeat receipt-hiding; quorum-gated
  serving; weighted/stake quorum; anchor key rotation/revocation.

## [0.3.1] — additive over 0.3.0 — **released 2026-07-11**

### Added
- **Streaming completion — chunk-sequence evidence, resume & replay**
  (chp-v0.2.md **§13.1** + chp-http-binding.md streaming section,
  [proposals/0012](proposals/0012-streaming-completion.md)): idempotent replay
  (§13) extends to `mode:"stream"` invocations. A stream records its ordered
  chunk deltas as window-bounded serving state (never hashed) and commits a
  **`chp-chunk-seq-v1`** digest — `sha256(Σ chp-stable-v1(delta_i) + "\n")` —
  plus `chunk_count` into its `execution_completed` payload
  (**omit-when-absent**, so non-stream events are byte-identical). A retried
  streaming `invocation_id` re-streams the recorded chunks + terminal result
  (`replayed:true`); each `event: chunk` SSE frame gains an `id: <n>` line and a
  client reconnecting with `Last-Event-ID: <n>` resumes from chunk n+1 (resume =
  replay-from-offset). Wire conformance grows by one check.

### Compatibility
- **Additive, no byte changes.** The chunk fields ride in the freeform
  `execution_completed` payload (like usage tokens) — **no schema change**, and
  every published vector is byte-identical. SSE `id:` is standard SSE a pre-0012
  client ignores; a host without resume answers a reconnect as a fresh stream.
  No new denial code or evidence type (a stream stays the `execution_*` bracket).

### Regression gate
- New vector `chunk-seq.json`; `git diff spec/test-vectors/` shows only it.
  Guards `spec_defines_streaming_replay` + `chunk_seq_vector_verifies`. Both
  reference hosts pass the new wire check (stream → drop → `Last-Event-ID`
  resume; retried id → replayed stream with identical chunks).

### Deferred
- Live mid-flight resume (reconnecting to a still-producing generator);
  per-chunk hashed events; SSE keep-alive pings; backpressure; durable
  cross-restart chunk storage; cross-host resume.

## [0.3.0] — first canon evolution over 0.2.9 — **released 2026-07-11**

### Added
- **Selective disclosure — withholdable payloads** (chp-v0.2.md §2 +
  new **§14 "Selective disclosure"**, [proposals/0011](proposals/0011-selective-disclosure.md)):
  a second, opt-in per-event content-hash scheme **`chp-event-hash-v2`**. Its
  `content_hash` stable object replaces the inline `payload` with
  `payload_commitment = sha256(chp-stable-v1(payload))`, so a signed bundle can
  **withhold** a payload (marker `{"chp_withheld": true}`, commitment retained)
  and still verify against the same signed root — the signature is untouched
  (root builds only on `content_hash`). A disclosed payload is bound by
  `sha256(chp-stable-v1(payload)) == payload_commitment`. Events self-describe
  via a new `hash_scheme` field; a verifier recomputes each event under the
  scheme it declares, so a chain MAY mix v1 and v2. `evidence-event` schema
  gains optional `hash_scheme` (`const chp-event-hash-v2`) + `payload_commitment`
  (`^[0-9a-f]{64}$`). Wire conformance grows by one check.

### Compatibility
- **v1 events byte-identical.** `hash_scheme` is absent on every pre-0011 event,
  so existing chains, store heads, witnessed receipts, signed bundles, and the
  published `event.json` / `signed-bundle.json` vectors are unchanged. This is a
  **minor** bump (not a patch) because it introduces a new *canon rule*, even
  though no existing bytes move. Bundle `protocol_version` becomes `"0.3"` on
  0.19 hosts, but verification branches on the per-event `hash_scheme`.
- **Not retention redaction.** Selective disclosure never NULLs, deletes, or
  forges a hash; it is disjoint from §4/§12 redaction/purge in both mechanism
  and vocabulary (withhold/minimize vs redact/purge). No new denial code or
  evidence type — a stale/forged disclosure is the existing `tampered` verdict.

### Regression gate
- New vectors `event-hash-v2.json` + `bundle-withheld.json`; `git diff
  spec/test-vectors/` shows ONLY the new files. Guards
  `spec_defines_selective_disclosure` + `event_hash_v2_vector_verifies`. Both
  reference hosts pass the new wire check; a withheld export verifies, a
  disclosed event is commitment-checked, a tampered-disclosed payload is refused.

### Deferred
- Per-field / sub-payload Merkle commitments; retroactive v1→v2; withholding
  non-payload fields; encrypting (vs dropping) withheld payloads; disclosure
  receipts.

## [0.2.9] — additive over 0.2.8 — **released 2026-07-11**

### Added
- **Revocation freshness — witnessed revocation heads** (chp-v0.2.md §12
  "Revocation freshness", [proposals/0010](proposals/0010-revocation-freshness.md)):
  a **`chp-revocation-head-v1`** digest of the held revocation *identifiers*
  (sorted `m\x00{mandate_id}\x00{principal_key}` / `k\x00{revoked_key_id}`,
  SHA-256) is bound into the witnessed store head. `GET /head` gains
  `revocation_head`; the `chain-witness` signed header gains it
  **omit-when-absent** (the §10 byte rule — the published `chain-witness.json`
  vector and every pre-0010 statement are byte-identical). `POST /witness`
  recomputes the host's own `revocation_head` before persisting
  (`revocation_head_mismatch`, 409) and snapshots the revocation-identifier
  set beside the receipt. Because the held set is append-only, an identifier
  present in an earlier witnessed snapshot but absent later is a **`dropped`
  revocation — a provable denial of revocation** (`chp revocation verify`).
  The witness signs only the digest; no revocation id leaks. Discharges the
  0005/0007 "witnessed heads as a revocation-freshness channel" deferral.
  Wire suite **23→24** ("revocation freshness"); both reference hosts pass.
  *Vector: `test-vectors/chain-witness-revfresh.json` (only new file);
  guards `spec_defines_revocation_freshness` + `revocation_head_vector_verifies`.*

## [0.2.8] — additive over 0.2.7 — **released 2026-07-11**

### Added
- **Sub-delegation — attenuation-only mandate chains** (chp-v0.2.md §10
  "Sub-delegation", [proposals/0009](proposals/0009-sub-delegation.md)): a
  delegate may re-delegate a **narrowed** slice of its authority, forming a
  chain verified offline link-by-link to the root principal. A sub-mandate
  adds `parent_id` + `depth` (signed header, present only when `parent_id`
  is set — a root mandate is **byte-identical** to a single-hop one) and
  `parent` (the full parent embedded inline, carried as transport, verified
  on its own signature). The load-bearing invariant is **monotone
  attenuation**: a child can only narrow scope and shorten the window. The
  **delegate join** (`parent.delegate_id == child.principal.host_id`) binds
  each link; the sub-principal signs with its own key (no key sharing).
  Revoking any link kills the suffix for free (each link's `not_revoked`
  runs against its own principal key). Gate 5 records the **root principal**
  in the evidence subject. A bad chain (attenuation violation, broken join,
  over-depth, revoked ancestor) is the existing `mandate_invalid` denial —
  **no new denial code, evidence type, schema kind, or canonical-byte
  change**. Wire suite **22→23** ("sub-delegation"); both reference hosts
  pass. *Vector: `test-vectors/mandate-chain.json` (only new file; mandate
  + mandate-revocation vectors byte-identical); guards
  `spec_defines_subdelegation` + `sub_mandate_vector_verifies`.*

## [0.2.7] — additive over 0.2.6 — **released 2026-07-11**

### Added
- **Idempotent invocation replay — making retries safe** (chp-v0.2.md §13,
  pipeline gate 0, [proposals/0008](proposals/0008-idempotent-replay.md)):
  a host that has already RECORDED an `invocation_id` MUST NOT re-execute it
  — it returns the recorded result with **`"replayed": true`** (omitted when
  false; every existing result byte-identical). The idempotency key is the
  envelope's existing `invocation_id` (no new header/field); replay covers
  every processed outcome incl. denials (gates do not re-run); scope is the
  single serving host; the result cache is SERVING state, never evidence
  (window-bounded, default 24h; purge cascades). Streaming excluded (named
  deferral). **No new denial codes, evidence types, schemas, or vectors.**
  Reference: client retry + gateway failover now thread ONE stable
  `invocation_id` across attempts — §11's "may have executed" retry caveat
  is neutralized against replay-conformant hosts. Wire suite **21→22**
  ("idempotent replay"); both reference hosts 22/22. *Guard:
  `spec_defines_idempotency`.*

## [0.2.6] — additive over 0.2.5 — **released 2026-07-10**

### Added
- **Revocation distribution — withdrawing authority before expiry**
  (chp-v0.2.md §10 "Revocation",
  [proposals/0007](proposals/0007-revocation-distribution.md)): new statement
  kind **`mandate-revocation`** (fifth statement-family member) — the
  principal's signed withdrawal of a mandate. **Issuer-only rule**: a
  revocation binds by `mandate_id` AND principal-key match; verifiers check
  the revocation signature against the MANDATE's principal key, never the
  statement's self-declared key, so a statement signed by any other key
  revokes nothing. Gate 5 consults the host's local set — a revoked mandate
  is the existing `mandate_invalid` denial (**no new denial code**). Routes
  `POST /revocations` (verify before persisting; 400 `invalid_revocation`)
  and `GET /revocations` (`{keys, mandates}` — §3.2 key revocations gain a
  standalone wire surface). Received statements live in sidecar storage,
  never the identity-doc key-revocation file. Propagation is best-effort;
  expiry stays the conformance floor. Reference: `chp mandate revoke
  [--push]`, `~/.chp/revocations/`. Wire suite **19→20** ("mandate
  revocation"); both reference hosts pass. *Vector:
  `test-vectors/mandate-revocation.json` (only new file — all published
  vectors byte-identical); guards `mandate_revocation_vector_verifies` +
  `spec_defines_revocation`.*
- **Streaming conformance** (completes
  [proposals/0006](proposals/0006-governed-streaming.md) named deferrals —
  no spec change): fixture capability **`conformance.stream`** (both
  reference hosts) and wire check **#21 "streaming invocation"** — SSE chunk
  frames + terminal result, and the denial-never-commits-to-SSE rule,
  asserted on the wire. TS reference implementation gains full streaming
  (host `ainvokeStream`, server SSE, SDK client `invokeStream`), closing the
  0006 parity gap. Wire suite **20→21**; both reference hosts 21/21.

## [0.2.5] — additive over 0.2.4 — **released 2026-07-10**

### Added
- **Mesh witnessing — tamper-proof against the operator** (chp-v0.2.md §12,
  [proposals/0005](proposals/0005-mesh-witnessing.md) → shipped): peers
  countersign each other's store heads. New derived digest
  **`chp-store-head-v1`** (per-correlation chain heads at global sequence ≤ N,
  sha256 over sorted `correlation_id\x00head_hash\n` lines — recomputable
  as-of any witnessed N); new statement kind **`chain-witness`** (fourth
  statement-family member; the witness signs only the root); routes
  `GET /head`, `POST /witness` (verify + recompute before persisting),
  `GET /witnesses`. Receipts persist with leaves snapshots; auditing
  (`chp witness verify`) judges per leaf — verified / **purged** (legal) /
  **redacted** (legal) / **TAMPERED** — so lawful retention and rewriting are
  distinguishable. Issued statements live with the WITNESS (the record the
  operator cannot delete). Witness records never enter the evidence store.
  Reference witnessing loop: `gateway.witness_interval_s`, default off.
  Wire suite **18→19** ("witness round-trip"); both reference hosts 19/19.
  *Vector: `test-vectors/chain-witness.json`; guards
  `chain_witness_vector_verifies` + `spec_defines_witnessing`.*
- **Governed streaming** (binding "Streaming invocations",
  [proposals/0006](proposals/0006-governed-streaming.md) → shipped):
  `mode:"stream"` on `/invoke` = SSE (`chunk` frames + terminal `result`
  frame carrying the standard InvocationResult). Gates run BEFORE the stream;
  pre-chunk outcomes answer plain JSON (never commit to SSE on a denial).
  Evidence brackets the stream; `execution_completed` lifts usage for token
  accounting. Reference: shared `_prepare` gate pipeline (one implementation,
  both paths), async-generator handlers with the `StreamResult` terminal
  sentinel, `RemoteCapabilityHost.invoke_stream`. **Cloud-spill is now
  governed**: `chp.spill.chat` (risk `high`) replaces the raw proxy byte
  pump — spill and its silent local-failure fallback run the pipeline with
  `http_response` usage evidence. *No canonical-byte changes; SSE frames are
  transport. TS streaming + a streaming wire check are named deferrals.*

## [0.2.4] — additive over 0.2.3 — **released 2026-07-10**

### Added
- **Reachability is governed evidence** (chp-v0.2.md §11,
  [proposals/0003](proposals/0003-reachability.md) → shipped): the binding's
  load-bearing rule extended to routing intermediaries. New reserved denial
  code **`host_unreachable`** (the 11th; `retryable: true`, the first
  transport code — governance §2's retryable rule widened to "governance OR
  reachability"), emitted only by an intermediary when no owner is reachable:
  PROCESSED denial, HTTP 200, `details` carries
  `attempted_hosts`/`last_error`/`retry_after_s`. New reserved family
  **`ROUTING_EVIDENCE_TYPES`** `{host_marked_unhealthy, host_marked_healthy}` —
  transition-gated intermediary self-events that ride the routed invocation's
  correlation, so a failover is replayable in-context. Intermediaries SHOULD
  maintain an evidence store (MUST record when they do); reference gateway
  wires one and merges its chain into stitched replays; `chp_router_*`
  Prometheus metrics. Reference router returns denials instead of raising
  (`UnknownCapabilityError`/`NoHealthyHostError` stay exported, no longer
  raised from `ainvoke`). *Guards: `spec_defines_routing` + the four
  denial-code registries; no wire-suite change (gateway fixture = named
  deferral); proven live: kill-member failover → denial → recovery →
  stitched replay.*
- **Mandate passthrough** (chp-v0.2.md §10 "Forwarding",
  [proposals/0004](proposals/0004-mandate-forwarding.md) → shipped): an
  intermediary forwarding an invocation MUST forward a presented `mandate`
  unchanged — the executing host's gate 5 verifies and rebinds the subject, so
  authority survives per-hop subject rebinding end to end. Reference router
  threads `envelope.mandate` (was silently dropped). *Proven live: steward
  fleet now mints per-run mandates; every evidence event on the mesh's chains
  carries the delegate-under-principal subject.*

## [0.2.3] — additive over 0.2.2 — **released 2026-07-09**

### Added
- **Signed mandates — delegated authority on the wire** (chp-v0.2.md §10,
  [proposals/0002](proposals/0002-mandates.md) → shipped): a principal's
  signed, expiring, capability-scoped grant to a named delegate — the third
  member of the statement family. `InvocationEnvelope` gains optional
  `mandate` (omit-when-absent, additive); the pipeline gains normative
  **gate 5 (Mandate)** — verify offline at host time, bind the delegate to any
  transport-verified caller, rebind the evidence subject to
  `{type: "mandate", id: delegate, principal, mandate_id, verified: true}`.
  New reserved denial code **`mandate_invalid`** (10 codes); out-of-scope is
  `policy_blocked` (binding §2 semantics). A mandate narrows and attributes —
  it never bypasses transport auth or later gates. Pipeline gates renumber
  10→11 (editorial; wire behavior additive). Wire suite **17→18** (the new
  check: never-met principal, valid/out-of-scope/expired/tampered).
  *Vector: `test-vectors/mandate.json` (both implementations + `verify.mjs`);
  guard `mandate_vector_verifies`; both reference hosts pass 18/18.*
- **DelegationContext correlation hygiene**: the handoff context defaults to
  the caller's correlation (`envelope.context_ref`) instead of minting an
  isolated one (§7 — evidence must stay reachable from its cause). The
  delegation *lifecycle* stays implementation-defined; mandates are its
  foundation.

## [0.2.2] — additive over 0.2.1 — **released 2026-07-09**

### Added
- **Adapter provenance** (chp-v0.2.md §9, [proposals/0001](proposals/0001-adapter-provenance.md)
  → shipped): publisher-signed `adapter-provenance` statements over
  `{kind, package, version, wheel_sha256, created_at, canonicalization}`;
  install-time verification gate (hash-before-execute, refusal as the reserved
  `host_adapter_install_rejected` event); publisher trust via explicit
  pin/domain-anchor or per-package TOFU. New reserved family
  `SUPPLY_CHAIN_EVIDENCE_TYPES`. *Vector: `test-vectors/adapter-provenance.json`
  (both implementations + `verify.mjs`); guard `provenance_vector_verifies`.
  Refinement vs the proposal: `record_sha256` stays evidence-side (pip rewrites
  RECORD at install).*

## [0.2.1] — additive over 0.2 — **released 2026-07-09**

### Added
- **Deferred execution rides the submitting correlation** (chp-v0.2.md §7,
  pipeline doc §1): a background job / queued task MUST propagate the
  submitting invocation's correlation with a causal edge (`causation_id` =
  submitting `invocation_id`) — the gates ran at submit, so the execution's
  evidence must remain reachable from it. *Gate: jobs-adapter continuity test.*
- **Federated replay is never silently partial** (chp-http-binding.md §4b):
  a gateway `/replay` that could not reach every member MUST set
  `partial: true` + `missing_hosts` on the `ReplayResult` (schema gains the
  two optional fields — additive; single-host results unchanged).
- `/metrics` MAY expose integrity counters (`chp_verify_requests_total{valid}`,
  `chp_chain_breaks_total`) — verification failures become alertable.
- **Key custody** (chp-v0.2.md §3): a deployment SHOULD provision a distinct
  signing key per `host_id` (shared custody collapses per-host attribution to
  the key holder). Reference impl: per-host key-dir resolution, legacy fallback.
- **Adapter namespace reserved** (governance §5, reserved-names): `chp.adapters.*`
  with the `chp.adapters.<adapter>.<capability>` structure, the `chp.adapters`
  entry-point group, and the `chp-adapter-<name>` package convention.
- **Declared emits is a contract** (governance §4.4): a capability MUST NOT
  emit an event type that is neither declared, lifecycle, nor reverse-DNS
  namespaced. *Gate: adapter-conformance `undeclared_emit` static check (found
  and fixed real drift in two reference adapters on first sweep).*
- **Capability version semantics** (chp-v0.1.md §3, clarification): semver;
  same-major = compatible.
- Adapter-install provenance floor: the reference install path fingerprints
  the installed distribution (`record_sha256`) and appends
  `host_adapter_installed` evidence under the SUBMITTING correlation (per the
  deferred-execution rule). Signed provenance: [proposals/0001](proposals/0001-adapter-provenance.md).
- **Aggregator signatures** (chp-v0.2.md §8, the `aggregated` layer): the
  assembling gateway MAY sign the canonical task-bundle header — re-assembly
  breaks the signature even with a recomputed `task_root_hash`. Omit-when-empty:
  unsigned task bundles byte-identical. *Vector:
  `test-vectors/task-bundle-aggregated.json` (both implementations +
  `verify.mjs`); guard `aggregated_task_bundle_vector_verifies`.*
- **Participation manifests** (chp-v0.2.md §8): reserved
  `task_participants_declared` event (`FEDERATION_EVIDENCE_TYPES`) — a declared
  member set makes leaf omission detectable; the completeness limit now covers
  only *undeclared* leaves. Verification gains the `participation` check
  (absent manifest → no check, visibly).
- **Caller-key rotation** (binding §2): a caller name MAY carry several keys
  simultaneously — rotation is add-new → drain → remove-old, no auth gap.
- **Capability-scoped caller keys** (binding §2): `name:key:scope1|scope2`
  (exact id or trailing-`*` prefix); an out-of-scope invocation is a PROCESSED
  `policy_blocked` denial — HTTP 200 with evidence, never a transport 403.
  *Wire conformance grows 16→17 (`capability-scoped caller key`); both
  reference implementations pass 17/17.*

## [0.2] — additive over 0.1 — **released 2026-07-06**

### Added
- **Cross-host ordering `chp-causal-order-v1`** (chp-v0.2.md §7): deterministic
  causal topological ordering for a correlation's events across N hosts —
  closes v0.1 §10's "does not define cross-host total ordering". Vector:
  `test-vectors/ordering.json`. *Behavioral note: the gateway's federated
  `/replay` output order changed from wall-clock sort to causal order.*
- **Task bundles** (chp-v0.2.md §8): the cross-host verification unit —
  per-host signed bundles aggregated byte-untouched with a canonical member
  order and a `task_root_hash` fingerprint; verification includes causal
  closure + acyclicity; completeness limit stated normatively. Vector:
  `test-vectors/task-bundle.json`; schema `task-bundle.schema.json`.
- **`GET /export/{correlation_id}`** (http-binding §4a): single-host signed
  bundle export; on a gateway, the assembled task bundle (503 on partial —
  never silently-partial evidence). Gateway `/verify` upgraded to federated
  task-bundle verification (`mode: "federated"`), note-fallback retained.
- Correlation-context clarifications (§7): `trace_id` optional/W3C-aligned,
  `baggage` reserved, `parent_correlation_id` informative session-threading.
- **Evidence integrity tiers** (`none` / `hash-chain` / `signed`) with per-event
  `content_hash`/`prev_hash` chains and ed25519-signed bundles; signature covers
  the canonical bundle *header*, not just `root_hash` (chp-v0.2.md §1–3).
- **`chp-stable-v1` canonicalization**, byte-specified with published test
  vectors and a stdlib Node reference verifier (`test-vectors/verify.mjs`) —
  cross-language interop is vector-proven.
- **Governance vocabulary** (chp-governance-v0.2.md): reserved denial-code
  registry, risk-tier semantics/ordering, autonomy/approval/safety/incident/
  compliance/identity event families, reverse-DNS extension namespacing.
- **Normative invocation pipeline** (chp-invocation-pipeline.md): the 10-gate
  ordering + per-code trigger predicates (`capability_disabled` → `skipped`;
  `action_limit` counts only `execution_started`).
- **HTTP wire binding** (chp-http-binding.md): route table, `X-CHP-Key`
  constant-time auth, the load-bearing "processed invocation → HTTP 200,
  outcome in body" rule, conformance fixture profile.
- **Host-identity attestation + authenticated subject**: self-signed
  `host_id ↔ public_key` binding with validity windows; verified callers
  override client-asserted subjects.
- **Anchors** (chp-v0.2.md §3.1): external trust roots inside the signed
  attestation claim — `domain` (Web-PKI via `/.well-known/chp-identity`) and
  `did` (Radicle did:key SSHSIG countersignature). Omit-when-empty byte rule
  keeps pre-anchor bundles byte-identical.
- **Key lifecycle** (chp-v0.2.md §3.2): archival, chained rotation with
  continuity statements, self-signed revocation, `IDENTITY_EVIDENCE_TYPES`
  host-self events (the host's chain as its key-transparency log).
- Wire conformance suite: 15 black-box checks incl. the four governance gates
  and the identity document.

### Changed
- **chp-stable-v1 forbids non-integer numbers in canonicalized content**
  (chp-v0.2.md §2 rule 6). Rationale: Python `json.dumps(0.0)` and ECMAScript
  `String(0.0)` produce different bytes — a latent cross-language verification
  break for any governed bundle carrying a safety score. Fractional values are
  string-encoded in hashed payloads. *Gate: all pre-existing vectors unchanged;
  `governance-bundle.json` added as the governed-chain proof.*
- Host descriptor may advertise `protocol_version "0.2"` when serving the v0.2
  surface (schema relaxed from `const "0.1"` to an enum; a bare v0.1 host still
  advertises `"0.1"`).

### Compatibility
- All v0.2 features are **additive**: a v0.1-only host remains conformant at
  the `none` tier. Byte-compat regression gate: `test-vectors/signed-bundle.json`
  must verify unchanged under `verify.mjs` after any canonicalization-adjacent
  change.

## [0.1] — 2026-05/06 — **stable 2026-07-06**

Initial draft: capability/host descriptors, invocation envelopes, execution
evidence, correlation requirements, replay semantics, outcome model
(`success`/`failure`/`denied`/`skipped`), denial semantics, the 9 conformance
MUSTs, and 28 JSON Schemas.
