# The Agentic Mesh — what CHP can do with the fleet as it stands

> Status: design / approach doc. Describes the agentic layer we can build on the
> live four-node CHP mesh, the Hugging Face resource surface we can draw on, and
> the flagship "CHP develops CHP" loop. Companion to `docs/synology-onboarding.md`
> (node bring-up) and the mesh control-plane work (`mesh stats` / capacity routing).

## 1. The substrate: four nodes, one capability namespace

The mesh is a single capability namespace (`chp.adapters.*`) routed through one
gateway, with capacity-aware routing, federated evidence, and policy governance
already spanning every node. The agentic layer does not need new infrastructure —
it is an **orchestration pattern over the capabilities that already exist**.

| Node | Role | Live adapters | Contributes to an agent loop |
|------|------|---------------|------------------------------|
| **primary** | orchestrator / dev brain | `git github ci conformance composition planning scout radicle release` · `huggingface local_llm vllm tei smolagents` · `safety delegation audit secrets host` | drives the loop; reads/writes code; verifies; commits; governs |
| **inference** (Apple-Silicon Mac) | model serving | `huggingface local_llm vllm tei` · `filesystem audit host` | runs the model that does the reasoning/generation |
| **worker** (Mac) | compute | `process jobs http filesystem audit host` | parallel/batch execution, shelling out, fan-out jobs |
| **nas** (Synology) | storage | `filesystem synology process` | corpora, artifacts, datasets, build outputs |

Two properties make this more than "a bunch of microservices":

- **Every capability is governable and evidenced.** `safety.assess` scores each
  invocation; high-risk actions (`*host.update*`, `bash`, `delete`, …) require
  approval; `audit` writes a hash-chained, queryable record on each node, and
  `replay(correlation_id)` / `mesh audit` reassemble a run across the fleet.
- **Routing is capacity-aware.** `gateway.selection: least_loaded` already sends
  inference work to the node with the most GPU/CPU headroom; an agent loop gets
  this for free.

So an "agent" here is: **a reasoning driver that calls CHP capabilities as tools,
routed across nodes, with governance and an audit trail as first-class outputs.**

## 2. The agentic layer

```
            ┌─────────────────────── primary (orchestrator) ───────────────────────┐
            │  reasoning driver  ──calls──▶  CHP capabilities (= the agent's tools)  │
            │  (smolagents.run / a CHP    │   scout.* plan.* git.* github.* ci.*     │
            │   planning loop)            │   conformance.* filesystem.* …           │
            └───────────────┬──────────────────────────┬───────────────────────────┘
                            │ gateway (capacity-routed, governed, evidenced)
              ┌─────────────┼──────────────┬───────────────────────┐
              ▼             ▼              ▼                       ▼
         inference        worker          nas                  (HF cloud)
       local_llm/mlx     jobs/process   synology/fs         Inference Providers
       generate/chat     batch fan-out   corpora/artifacts   spill / specialty
```

The reasoning driver has two viable forms, both already present:

1. **`smolagents.run`** (on primary) — HF's code-first agent framework. We expose
   CHP capabilities to it as tools; smolagents handles the think→act→observe loop.
   Fastest path to a working agent.
2. **A CHP-native loop** — `planning.*` for decomposition + explicit capability
   calls. More control, fully inside CHP's evidence model, no framework dependency.

Either way the **model behind the reasoning** is served on the inference node
(see §4), and **every tool call is a governed, evidenced capability invocation**.

## 3. Flagship: "CHP develops CHP"

A self-hosted coding agent that improves this very repository, running entirely on
your mesh. Each step is an existing capability on a specific node:

| Step | Capability | Node | Notes |
|------|-----------|------|-------|
| 1. Find work | `scout.*` (analyze repo, surface hotspots/gaps) | primary | reads the tree |
| 2. Plan | `planning.*` / `composition.*` | primary | decompose into a change set |
| 3. Generate | `local_llm.chat` / `mlx.chat` | **inference** | the model writes the diff |
| 4. Apply | `filesystem.write_file` | primary | within an allowed path |
| 5. Verify | `ci.run` + `conformance.*` | primary | tests + protocol conformance gate |
| 6. Govern | `safety.assess` on each write/commit | primary | high-risk steps need approval |
| 7. Commit | `git.*` → `github.*` (PR) | primary | on a branch, never default |
| 8. Record | `audit` on every node + `replay(corr_id)` | fleet | full provenance of the run |

This is differentiated precisely because of steps 6 and 8: it is not "an agent that
edits code," it is **an agent whose every action is risk-assessed and recorded in a
tamper-evident chain you can replay**. That is the CHP thesis, dogfooded.

Guardrails to build in from the start: branch-only commits, an allowed-path
filesystem policy, `conformance` as a hard gate before any PR, and `safety` set to
require approval for `git push`/`github` actions.

## 4. Serving the model — pull via HF, serve via MLX (new adapter)

Decision: **pull the model through the HF adapter, serve it with MLX** on the
inference Mac (MLX is ~2–3× faster than Ollama and ~1.5× faster than llama.cpp on
Apple Silicon — but macOS-only).

### 4a. Pull (already supported)
- `huggingface.search_models` / `leaderboard_scores` → choose a Qwen3-family model
  (Apache-2.0; a dense ~4B–35B variant fits a Mac; MoE for headroom).
- `huggingface.pull_for_local_llm` (and `quantize_to_gguf` if a GGUF runtime is
  used) → fetch weights to the inference node's HF cache. Routed with `prefer="inference"`.

### 4b. Serve — `chp-adapter-mlx` (to build)
MLX needs an OpenAI-compatible shim to fit our inference adapter contract. New
adapter `chp-adapter-mlx`:
- Wraps `mlx-lm` (`mlx_lm.server` exposes an OpenAI-compatible `/v1/...`), or calls
  `mlx_lm` in-process.
- Registers `chp.adapters.mlx.generate` / `.chat` / `.list_models` — the **same
  shape as `local_llm`/`vllm`** so the gateway treats it as another inference owner
  and the capacity router (GPU-utilization-aware) can pick it.
- Tagged so `_INFERENCE_HINTS` in the router recognizes it (`mlx` added to the hint
  list) → GPU-aware routing applies.
- Config via env (`MLX_MODEL`, `MLX_BASE_URL`) mirroring the local_llm adapter.

This keeps the abstraction clean: **the agent calls `*.chat`; the mesh decides
whether MLX (local), vLLM, Ollama, or a cloud provider serves it.**

## 5. The broader Hugging Face surface (beyond local models)

HF in 2026 is a registry **plus** libraries **plus** a hosted inference layer
(2.4M+ models, 730K+ datasets, ~1M Spaces). Map of what we can draw on and how it
plugs into the mesh:

| HF resource | What it gives us | Our hook | Use in the agentic mesh |
|-------------|------------------|----------|--------------------------|
| **Models / Hub** | open weights (Qwen3, …) | `huggingface.pull*`, `search_models`, `model_card` | the local reasoning model (§4) |
| **Inference Providers** | OpenAI-compat API routed to Together/Cerebras/Groq/… (fastest/cheapest) | `llm.*` / `http.*` (small adapter possible) | **spill backend**: when the inference GPU is saturated (`mesh stats`), route to cloud; or use a frontier model for hard steps the local model can't do |
| **Datasets** | 730K+ datasets | `huggingface.load_dataset`, `search_datasets`, `dataset_preview` | eval sets for the agent's self-tests; RAG corpora staged on the NAS |
| **Spaces** | ~1M hosted demo apps (Gradio/Streamlit) | `huggingface.call_space` | call specialty models (ASR, image/video gen, OCR) without hosting them |
| **TEI / TGI / vLLM** | production serving runtimes | `tei.*`, `vllm.*` | embeddings (`tei.embed`/`rerank`) for RAG; vLLM for non-Apple GPUs |
| **smolagents** | code-first agent framework | `smolagents.run` | the reasoning driver (§2) |
| **PEFT / AutoTrain** | LoRA/QLoRA fine-tuning | `huggingface.finetune`, `apply_adapter` | fine-tune a small model on CHP's own specs/codebase for sharper CHP-specific generation |
| **Leaderboards** | model rankings by task | `huggingface.leaderboard_scores` | pick the right model per job, automatically |
| **FAISS / embeddings** | vector search | `huggingface.faiss_index`, `tei.embed`, `vector.*` | the retrieval half of distributed RAG |

Two of these are strategically interesting beyond the flagship:

- **Inference Providers as a capacity spill.** The capacity router already knows GPU
  headroom; the natural extension is a policy: *prefer local MLX; spill to an HF
  Inference Provider when GPU utilization is high or the task needs a frontier
  model.* Local-first, cloud-burst — governed and evidenced like everything else.
- **Fine-tune on ourselves.** `huggingface.finetune` + `apply_adapter` on the CHP
  spec/wire-protocol corpus → a LoRA that makes the local model materially better at
  generating conformant CHP code. The "CHP develops CHP" loop then improves its own
  generator.

## 6. Why this is differentiated

Plenty of stacks can run an agent that edits code or answers from a corpus. The
mesh's distinction is **operational**, not model-quality:

1. **Governed** — every action is risk-assessed; high-risk actions gated by policy,
   not vibes.
2. **Evidenced** — a tamper-evident, replayable, fleet-wide record of exactly what
   the agent did and why. Auditable autonomy.
3. **Capacity-aware & portable** — the same agent runs against local MLX, an on-prem
   GPU, or a cloud provider; the mesh routes by headroom and policy. No code change.
4. **Composable across owned hardware** — storage (NAS), compute (worker), inference
   (GPU Mac), orchestration (primary) compose into one system you own end-to-end.

## 7. Build order

1. **Keystone — model serving.** Build `chp-adapter-mlx` (OpenAI-compat over
   `mlx-lm`), add `mlx` to the router's inference hints, deploy to the inference
   node, pull a Qwen3 model via `huggingface.pull_for_local_llm`. Verify
   `mlx.chat` routes with `prefer="inference"` and shows up in capacity routing.
2. **Reasoning driver.** Wire `smolagents.run` (or a CHP-native planning loop) to a
   curated tool set (`scout`, `filesystem`, `git`, `ci`, `conformance`), pointed at
   the local model.
3. **Flagship loop.** Assemble the §3 pipeline behind one entrypoint
   (`examples/chp-develops-chp/`), branch-only + conformance-gated + safety-gated,
   with `replay` of each run as the deliverable artifact.
4. **Extensions.** Inference-Provider spill policy; LoRA fine-tune on the CHP corpus;
   distributed RAG over NAS docs as a second demo.

Each step ships the usual way (tests → sync → chp-core precommit → push → wheel),
and the inference-node pieces (MLX install, model pull) are verified live over the
mesh — no SSH, via `host.stats` + the inference adapters.
