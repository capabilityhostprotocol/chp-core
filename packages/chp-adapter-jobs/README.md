# chp-adapter-jobs

Run any CHP capability as a polled **background job**. Built for heavy or
long-running capabilities — e.g. `huggingface.generate_image` (minutes on MPS) —
that outlive HTTP request timeouts.

## How it works

`submit` runs the target capability via `host.ainvoke` inside a
`ThreadPoolExecutor` and returns a `job_id` immediately. The target runs to
completion server-side regardless of client timeouts, and — because the SQLite
evidence store is thread-safe — keeps its **own full evidence chain**. This
adapter emits only lightweight job-lifecycle events, never the target's payload
or result.

## Capabilities

| Capability | Description |
|---|---|
| `chp.adapters.jobs.submit` | Submit `{capability_id, payload}`; returns a `job_id`. |
| `chp.adapters.jobs.status` | Poll lifecycle state: submitted / running / completed / failed + duration. |
| `chp.adapters.jobs.result` | Fetch a completed job's result data (`ready: false` while running). |
| `chp.adapters.jobs.list` | List all jobs and their state. |

## Example: async image generation

```jsonc
// 1. submit — returns immediately
POST chp.adapters.jobs.submit
{ "capability_id": "chp.adapters.huggingface.generate_image",
  "payload": { "prompt": "a serene mountain lake", "output_path": "/tmp/out.png" } }
// → { "job_id": "job_ab12…", "status": "submitted" }

// 2. poll
POST chp.adapters.jobs.status   { "job_id": "job_ab12…" }   // → running … completed

// 3. fetch result
POST chp.adapters.jobs.result   { "job_id": "job_ab12…" }
// → { "ready": true, "success": true, "result": { "output_path": "/tmp/out.png", … } }
```

## Config

| Field | Default | Meaning |
|---|---|---|
| `max_workers` | `2` | Thread pool size. |
| `allowed_capabilities` | `None` | Allowlist of submittable capability ids (`None` = any). |
