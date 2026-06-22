# chp-adapter-mlx

Apple Silicon native text generation as governed CHP capabilities, backed by a
local [`mlx_lm`](https://github.com/ml-explore/mlx-lm) server. MLX is the fastest
local inference path on Apple Silicon (≈2–3× Ollama, ≈1.5× llama.cpp).

`mlx_lm.server` is OpenAI-compatible, so this adapter mirrors `chp-adapter-vllm` /
`chp-adapter-local-llm` and the gateway routes it as another **inference owner** for
capacity-aware (GPU-utilization) routing.

## Capabilities

| Capability | Risk | Description |
|------------|------|-------------|
| `chp.adapters.mlx.status` | low | Is `mlx`/`mlx-lm` installed (+ versions) and is the server reachable? |
| `chp.adapters.mlx.list_models` | low | Models served by `mlx_lm.server` (`/v1/models`) |
| `chp.adapters.mlx.generate` | medium | Single-turn completion (`/v1/completions`) |
| `chp.adapters.mlx.chat` | medium | Multi-turn chat (`/v1/chat/completions`) |

## Composition & evidence

The adapter imports **no HTTP library** — every server call routes through
`chp.adapters.http`, so HTTP is its own governed evidence chain and the adapter is
conformance-clean. Prompt/completion/message **content is never recorded in
evidence**; only model id, token counts, latency, and errors are.

## Running the backend (inference node)

```sh
pip install mlx-lm
# OpenAI-compatible server on :8081 (8080 collides with llama.cpp)
mlx_lm.server --model mlx-community/Qwen3-... --port 8081
```

Config via env: `MLX_BASE_URL` (default `http://localhost:8081`), `MLX_MODEL`,
`MLX_API_KEY`. Add `"mlx"` to the host profile's `adapters` list to register it.
Verify over the mesh with `chp.adapters.mlx.status`.
