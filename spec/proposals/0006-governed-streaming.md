# 0006: Governed Streaming — the Stream Mode Gets a Binding

- **Status:** shipped (2026-07-10, spec v0.2.5)
- **Issue:** rad:11ae0ea
- **Affects:** chp-http-binding.md (streaming section for `/invoke`), chp-v0.2.md cross-ref; canonical bytes: **no changes** (the `stream` mode is already in the envelope/descriptor schemas; SSE frames are transport, not canonical objects)

## Problem

The envelope has declared a `stream` mode since v0.1 — and no binding defines
it. Today `mode:"stream"` executes as ordinary sync. Worse, the mesh's
largest real traffic class routes around the gap: the OpenAI-compatible shim
*simulates* streaming (computes the full completion, replays it as canned SSE
chunks), and its **cloud-spill path is an ungoverned byte pump** — raw
`urlopen` passthrough with no gates, no evidence, no token accounting — which
also fires silently as the local-failure fallback. The governed plane covers
everything except the thing the mesh does most.

## Design

**Binding.** `mode:"stream"` on `POST /invoke` responds with
`text/event-stream`: zero or more `event: chunk` frames
(`data: {"delta": …}`), then exactly one terminal `event: result` frame whose
`data` is the **standard `InvocationResult`** (outcome, usage in `data`,
evidence ids). Gates run **before** the stream opens — the pipeline is
untouched; a denial (or any non-executing outcome) is returned as the normal
JSON 200 body and MUST NEVER commit to `text/event-stream`. Clients switch on
Content-Type. A capability advertises streaming by declaring
`modes: ["sync","stream"]`; invoking a stream-capable capability in sync mode
collects the chunks and returns the terminal result (graceful degrade);
`mode:"stream"` against a sync-only capability stays gate-4
`unsupported_mode`.

**Evidence.** The existing bracket, unchanged in shape: `execution_started`
when the stream opens; `execution_completed` at close carrying the usage
payload (`prompt_tokens`/`completion_tokens`/`model`), or `execution_failed`
on a mid-stream error. Per-chunk evidence is deliberately NOT reserved
(noise); handlers MAY `ctx.emit` domain events.

**Reference implementation.** The gate pipeline is extracted into one shared
`_prepare(envelope)` used by both `ainvoke_envelope` and the new
`ainvoke_stream` — two gate copies would drift, and a drifted gate on the
stream path is a security bug. Handlers stream by being **async generators**:
yield chunks; the final yield is a `StreamResult(data)` sentinel (async
generators cannot return values) that becomes the terminal result. The HTTP
handler raises its per-connection socket timeout at stream start (a real
token stream can idle past the 30s default). The Python client gains
`invoke_stream(...)` (a generator of chunks whose return value is the
terminal `InvocationResult`).

**Spill governance — and the live proof.** A new `chp.spill.chat` capability
(async generator, `modes: ["sync","stream"]`) replaces both raw proxy paths.
Spill traffic then runs the full pipeline: gates, `execution_*` bracket, and
`http_response` usage evidence — token accounting works with zero metrics
changes. The shim's spill and local-failure-fallback paths rewire onto it,
turning a silent ungoverned fallback into a governed, evidenced one. This
capability is the arc's end-to-end streaming proof.

## Compatibility

Fully additive: no canonical-object or schema-enum changes; all published
vectors byte-identical. A host that never declares `stream` mode is
unaffected; a client that never sends it sees today's behavior. The streaming
**wire conformance check is a named deferral**: it would force the TS host to
grow SSE now — normative text + reference tests + the live proof carry the
claim until both hosts stream (same posture the mesh suite took at 0003).

Deferred by design: TS host/client streaming, the streaming wire check,
native mlx/local-llm adapter streaming (`stream:true` to the model servers —
the spill capability proves the binding first), SSE keep-alive ping frames,
resumable streams / chunk replay, and backpressure semantics.

## Shipped as

- Spec: binding **"Streaming invocations"** section; CHANGELOG **[0.2.5]**
- Guards: none new (no canonical objects; SSE is transport). Streaming
  wire check remains the named deferral (TS host has no SSE)
- Implementations: host `_prepare` gate extraction (ONE pipeline for
  sync + stream; behavior-preserving — all gate tests unchanged),
  `ainvoke_stream` + `StreamResult` terminal sentinel, sync-mode chunk
  collection (graceful degrade), usage lifted into
  `execution_completed` (unredacted — host-constructed);
  binding SSE path (`event: chunk`/`event: result`, denial = plain
  JSON, 600s stream socket timeout); `RemoteCapabilityHost.invoke_stream`;
  **`chp.spill.chat`** (risk `high`, modes sync+stream, emits
  `http_response` usage) replacing `_proxy_json`/`_proxy_stream` — the
  spill paths and the silent local-failure fallback are now governed
- Refinement vs proposal: none — landed as designed (7 streaming + 4
  spill tests incl. policy-blocks-spill and a fake-OpenAI upstream
  streaming round trip)
