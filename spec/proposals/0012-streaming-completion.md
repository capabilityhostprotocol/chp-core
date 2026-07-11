# 0012: Streaming Completion — Chunk-Sequence Evidence, Resume & Replay

- **Status:** shipped (2026-07-11, spec v0.3.1)
- **Issue:** rad:2170513
- **Affects:** chp-v0.2.md §13 (idempotent replay extends to streams; registers `chp-chunk-seq-v1`) + chp-http-binding.md (streaming section gains SSE `id:` / `Last-Event-ID` resume). Canonical bytes: **additive** — a stream's `execution_completed` payload gains `chunk_count` + `chunk_seq_digest` **omit-when-absent** (non-stream events and every published vector byte-identical); the payload is freeform so **no schema change**; no new denial code or evidence type. Spec **v0.3.1**.

## Problem

Streaming (proposal 0006) brackets a stream with `execution_started` /
`execution_completed` but the chunks pass through **unrecorded**, and §13
idempotent replay (proposal 0008) **excludes streams** — the guard is literally
`if envelope.mode != "stream"`. Three gaps follow:

1. **A mid-stream drop is unrecoverable.** When the client connection breaks,
   the reference host's `GeneratorExit` teardown emits *neither*
   `execution_completed` nor `execution_failed` — an interrupted stream leaves a
   dangling `execution_started`, and no chunks were retained, so there is
   nothing to resume from.
2. **A retried streaming `invocation_id` re-executes** (double-charges tokens,
   re-runs side effects) — the idempotency guarantee stops at sync.
3. **What was streamed is not attestable** — the delivered chunk sequence
   leaves no evidence, only the assembled terminal result.

0006 and 0008 both named the fix as future work ("resumable streams / chunk
replay"; "streaming replay … out of scope"). This proposal delivers it.

## Design

Record the ordered chunks as **serving state** (never hashed into the chain) and
commit a **digest** of them into evidence. Resume and replay then become one
operation — re-emit recorded chunks from an offset.

- **`chp-chunk-seq-v1` (chunk-sequence evidence).** A deterministic SHA-256 over
  the ordered chunk deltas: `sha256( Σ chp-stable-v1(delta_i) + "\n" )` — the
  `chp-store-head-v1` line scheme, each delta canonicalized so the digest is
  cross-impl byte-exact. A stream's `execution_completed` payload gains
  `chunk_count` and `chunk_seq_digest` (omit-when-absent — only streaming
  completions carry them; usage tokens already ride in this payload, so no
  schema changes). This makes the delivered sequence tamper-evident: a
  resumed/replayed stream is verifiable against the committed digest. Per-chunk
  events are still NOT emitted (0006's noise concern stands) — the digest is the
  evidence.
- **Recording.** The host retains the ordered deltas beside the recorded
  terminal result in the §13 result cache (`invocation_results`, TTL-bounded,
  first-write-wins), keyed by `invocation_id`. A bounded cap
  (`CHP_STREAM_CACHE_MAX_CHUNKS` / bytes) guards unbounded streams — over the cap
  the stream is recorded non-resumable (digest still emitted; replay degrades to
  the terminal result). The record is written even on a mid-stream drop, so a
  partial stream is resumable.
- **Streaming replay (§13).** The `mode != "stream"` exclusion is removed. A
  retried streaming `invocation_id` with cached chunks **re-streams the recorded
  chunks then the recorded terminal result**, `replayed: true`; no lifecycle
  events are appended (the execution did not re-happen). Purge/redaction (§12)
  drops cached chunks with the result.
- **Resumable streams (SSE `Last-Event-ID`).** Each `event: chunk` frame gains an
  `id: <n>` line (n = 0-based chunk index); the terminal `result` frame carries
  the final id. A client whose connection drops reconnects with the **same
  `invocation_id`** and a `Last-Event-ID: <n>` header; the host **resumes from
  chunk n+1** off the recorded buffer, then the terminal result. Resume is
  replay-from-offset; a fresh replay is resume-from-(-1) — one code path. The
  reference client tracks the last id and retries transparently.

## Compatibility

Additive. `chunk_count` / `chunk_seq_digest` are omit-when-absent, so non-stream
`execution_completed` events and all published vectors are byte-identical; SSE
`id:` is standard SSE a pre-0012 client simply ignores; a host that does not
implement resume answers a `Last-Event-ID` reconnect as a fresh stream (the
client falls back to consuming from the start). No new denial code, no new
evidence type — a stream stays the `execution_*` bracket. Wire conformance grows
by one check.

Deferred by design: **live mid-flight resume** (reconnecting to a
still-producing generator — needs live-buffer multiplexing), per-chunk hashed
evidence events, SSE keep-alive ping frames, backpressure/flow-control, durable
cross-restart chunk storage beyond the TTL cache, and resume across a different
host (chunks are host-local serving state).

## Shipped as

- Spec: chp-v0.2.md **§13** (replay extends to streams) + **§13.1 "Streaming
  replay & resume"** (registers `chp-chunk-seq-v1`, `chunk_seq_digest`,
  `chunk_count`, `Last-Event-ID`) + chp-http-binding.md "Resumable streams";
  status line **v0.3.1**; CHANGELOG **[0.3.1]**. No schema change (chunk fields
  ride the freeform `execution_completed` payload)
- Bytes: existing vectors byte-identical (chunk fields omit-when-absent); new
  `chunk-seq.json`; no new statement kind, denial code, or evidence type; no
  store schema change (chunks ride under a serving-only `_chunks` key in the
  §13 result cache)
- Guards: `spec_defines_streaming_replay` + `chunk_seq_vector_verifies`
  (alignment 70→72); wire suite **25→26** (`check_streaming_completion`: `id:`
  frames, committed digest matches the delivered sequence, retried id replays
  identical chunks, `Last-Event-ID` resumes from offset; both reference hosts)
- Implementations: Python `chunk_seq_digest` + `ainvoke_stream` record + digest
  + `resume_from` + gate-0 stream replay + `_record_result`/`_lookup_recorded_chunks`
  (`_chunks`, `CHP_STREAM_CACHE_MAX_CHUNKS` cap); `_invoke_stream` `id:` frames +
  `Last-Event-ID` + drain-on-disconnect; `RemoteCapabilityHost.invoke_stream`
  pinned-id auto-resume; `chp stream verify`. TS `chunkSeqDigest` + `ainvokeStream`
  record/digest/replay + `resumeFrom`; `server.ts` `id:`/`Last-Event-ID`/drain;
  client `invokeStream` pinned-id resume loop; reference `verify.mjs` chunk-seq branch
- Refinement vs proposal: no store schema change — chunks ride under a
  serving-only `_chunks` key in the existing result cache (the plan's "chunks
  column" was unnecessary); drain-on-disconnect (keep recording after client
  drop) is what makes a real drop resumable. Deferrals stayed named (live
  mid-flight resume, per-chunk hashed events, keep-alive pings, backpressure,
  durable cross-restart storage, cross-host resume).
