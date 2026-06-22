# CHP-develops-CHP — an agentic loop on the mesh

A self-hosted analysis/coding agent that runs **entirely on the CHP mesh**: the
reasoning model is a local Qwen3 served on the inference node via
`chp.adapters.mlx`, and its *tools are CHP capabilities* routed across the fleet
through the gateway. Every tool call is a governed, evidenced capability
invocation sharing one correlation id, so the whole run is replayable.

```
reason  → chp.adapters.mlx.chat            @ inference   (local LLM)
act     → chp.adapters.scout.query         @ primary     (find code)
          chp.adapters.filesystem.*        @ primary     (read repo)
          chp.adapters.conformance.*       @ primary     (verify)
observe → feed result back → repeat (bounded)
```

This is the demonstration from [`docs/agentic-mesh.md`](../../docs/agentic-mesh.md)
§3. It is **read-only and proposes by default** — it gathers evidence and answers;
it does not write or push. (Mutating actions are designed to go through
`chp.adapters.safety.assess` first; that path is intentionally left behind an
`--apply` flag and not enabled here.)

## Run

```sh
export CHP_GATEWAY_KEY=$(chp-host secrets get CHP_HOST_API_KEY)
python agent.py "What capabilities does the mlx adapter expose, and one improvement? Cite the source."
python agent.py --repo /path/to/chp-core --steps 6 "your task"
```

Requires a running gateway (`http://127.0.0.1:8800`) with, across the mesh:
`mlx` (inference node, server started via `chp.adapters.mlx.start_server`),
`scout` / `filesystem` / `conformance` (primary / repo node).

## What it prints

The final answer, then the **evidence trail**: each governed capability call, its
outcome, and the node it ran on, all under one correlation id — replayable via the
mesh evidence tooling (`router.replay(correlation_id)` / `chp-host mesh audit`).

## A team of agents (coder.py, team.py)

Beyond the single analyst loop, the example includes a **coding agent** and a
**team coordinator** so multiple agents contribute to CHP together over the mesh:

- **`coder.py`** — a single-file coding agent: scout (FastContext) locates the
  file → `read_file` → the coder model (MLX) rewrites it → `safety.assess` gates
  the write → (`--apply`) `write_file` + `conformance.check_source` verifies.
  Propose-only by default; `--apply` writes (run on a branch); never pushes.

  ```sh
  python coder.py --file path/to/file.py "make the smallest change that does X"
  python coder.py --apply --prefer primary "task"   # scout locates the file
  ```

- **`team.py`** — a roster of coders, each on a different model/node (Qwen3-14B on
  the **primary**, Qwen3-4B on the **inference** node), pulling from one task
  backlog (round-robin) and sharing **one correlation id** — the whole
  collaborative session is a single replayable evidence trail.

  ```sh
  python team.py "task one" "src/x.py::task two"   # propose-only
  python team.py --apply --solo primary-coder "task"
  ```

## The agent roster (who does what)

| Agent | Model | Node | Role |
|-------|-------|------|------|
| **scout** | FastContext-1.0-4B-RL (vLLM, tool-calling) | primary :8092 | locates code (`scout.query`) |
| **primary-coder** | Qwen3-14B-4bit (MLX) | primary :8081 | writes changes |
| **edge-coder** | Qwen3-4B-Instruct (MLX) | inference :8081 | writes changes / analysis |

scout is a *specialist* (FastContext is a repo-exploration tool-calling model); the
coders are *generalists* (MLX). They compose: a coder calls scout to find code,
then reasons over it — all as governed, evidenced capabilities routed by the mesh.

## Notes

- Model quality is the limiter: the 4B mangles "change nothing else"; the 14B
  primary-coder is markedly better. Each tool/step is governed and evidenced
  regardless of model.
- The single analyst loop (`agent.py`) is bounded by `--steps`.
