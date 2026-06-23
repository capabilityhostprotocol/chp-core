# The recursive flywheel — the mesh improves its own model

The mesh's governed runs become training data that improves the local model,
**entirely on-fleet** (Apple-Silicon LoRA). The loop:

```
capture ──▶ curate ──▶ finetune (LoRA) ──▶ serve ──▶ better model ──▶ (more, better runs) ──┐
   C1          C2            C3               C4                                              │
   └──────────────────────────────────────────────────────────────────────────────────────┘
```

> **Data hygiene:** training *content* comes from harness/cockpit transcripts (opt-in
> capture); CHP **evidence is redacted** (prompt/completion never recorded) and provides the
> *governance/curation signal* (which runs were sanctioned, conformance-clean, safety-allowed)
> via `audit.query_invocations` — never the text.

## Run the loop

The **NAS is the shared corpus store** — the harness writes one transcript file per
run to it over the mesh (governed + evidenced), so any node can assemble the dataset
before training (no local-only data, no manual copying).

```sh
# C1 — capture transcripts to the NAS while the agent works (opt-in):
export CHP_CAPTURE_NAS_DIR=/volume1/flywheel/traces      # shared corpus on the NAS
cd ../harness && npm run agent -- "some task"            # repeat to build a corpus
#   (CHP_CAPTURE_TRACES=<local path> also works for a local-only corpus)

# C1.5 — pull the shared corpus off the NAS (on whichever node will train):
export CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)
python pull-nas.py /volume1/flywheel/traces ./corpus.jsonl

# C2 — curate good runs into an mlx_lm dataset (train.jsonl / valid.jsonl):
python curate.py ./corpus.jsonl ./data --valid-frac 0.15

# C3 — LoRA fine-tune on a RAM-headroom node (detached, governed, evidenced):
#   chp.adapters.mlx.finetune  data=<.../data>  adapter_path=<.../lora>  iters=300
#   (via the mesh: prefer a node with headroom; tail ~/.chp/logs/mlx-finetune-<name>.log)

# C4 — serve the tuned model (base + LoRA):
#   chp.adapters.mlx.start_server  model=<base>  adapter_path=<.../lora>  port=8081

# C5 — eval-gate, then promote: compare the tuned model vs base on a held-out CHP
#   task (e.g. the scout-relay) before routing traffic to it.
```

## Why this is the CHP payoff

Most stacks can't safely close a self-improvement loop. CHP can because the loop is
**governed** (every step risk-assessed) and **evidenced** (replayable provenance of which runs
trained the model). The mesh's weakest point — small local models — becomes a *self-reinforcing
strength*. See `docs/agentic-mesh.md` and the plan for the recursive layer (governed
self-improvement, reflection-over-traces) this unlocks.
