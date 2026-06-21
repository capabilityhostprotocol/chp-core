# chp-adapter-smolagents

A governed code-writing **meta-agent** over CHP capabilities. Wraps
[smolagents](https://github.com/huggingface/smolagents)' `CodeAgent` as the
single CHP capability `chp.adapters.smolagents.run`.

The twist: the agent's **tools are CHP capabilities**. Each capability id you
list is exposed to the agent as a tool, and every tool call routes back through
the host router via `ctx.ainvoke` — so the agent chains governed CHP
capabilities with a full evidence trail under each call. This gives CHP a
code-execution agentic layer without building one from scratch.

## The async bridge

The agent runs synchronously in a worker thread (`asyncio.to_thread`). When it
calls a tool, the tool schedules `ctx.ainvoke(cap_id, payload)` back onto the
host event loop (`run_coroutine_threadsafe`) and blocks for the result. smolagents
itself is isolated in `_backends.py`, so the adapter stays dependency-light and
unit-testable with a fake backend (no LLM, no code execution).

## Capability

| Capability | Description |
|---|---|
| `chp.adapters.smolagents.run` | Run a CodeAgent on a task, exposing listed CHP capabilities as tools. |

`run` payload: `task` (required), `tools` (list of CHP capability ids),
`model_id`, `max_steps`.

## Model backends

Configured via `SmolagentsConfig.model_type`:

| `model_type` | Backend |
|---|---|
| `openai_server` (default) | Any OpenAI-compatible endpoint — e.g. a local `vllm serve` (`http://localhost:8092/v1`). |
| `mlx` | `MLXModel` — Apple Silicon native. |
| `transformers` | `TransformersModel` — local HF model. |

Install the agent extras: `pip install chp-adapter-smolagents[agent]`.

## Config

| Field | Env | Default |
|---|---|---|
| `model_id` | `SMOLAGENTS_MODEL` | _(none — required)_ |
| `api_base` | `SMOLAGENTS_API_BASE` | `http://localhost:8092/v1` |
| `api_key` | `SMOLAGENTS_API_KEY` | `EMPTY` |
| `max_steps` | — | `6` |
| `allowed_tools` | — | `None` (any capability id allowed) |

## Evidence policy

Emitted: task length, tool names, model id, step count, answer length, latency,
and a `smolagents_tool_invoked` event per tool call (tool id only).
Never emitted: task text, generated code, tool payloads, or the answer text.
