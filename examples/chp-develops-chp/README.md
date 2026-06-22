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

## Notes

- The default model is a 4B local model — capable enough to drive the loop and cite
  files, but small; it occasionally picks a non-existent path or the wrong tool and
  recovers on the next step. Point `--model` at a larger MLX model for stronger
  reasoning once the inference node has the disk/RAM.
- The loop is bounded by `--steps`; the agent is asked for a final answer when the
  budget is reached.
