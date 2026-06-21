# chp-adapter-vllm

Apple Silicon native text generation and chat as governed CHP capabilities,
backed by a local [vLLM](https://docs.vllm.ai) server running the
[`vllm-metal`](https://github.com/vllm-project/vllm-metal) plugin (MLX/Metal
compute backend, prebuilt Metal kernels).

Like `chp-adapter-tei`, this adapter imports **no HTTP library**. Every call
routes through `chp.adapters.http` via `ctx.ainvoke` — the lego-block
composition — so each HTTP request is its own governed evidence chain and the
adapter stays conformance-clean. It complements `chp-adapter-huggingface`
(artifact/registry layer) with a production-grade generation substrate.

## Capabilities

| Capability | OpenAI route | Description |
|---|---|---|
| `chp.adapters.vllm.generate` | `/v1/completions` | Single-turn completion. Prompt/completion never in evidence. |
| `chp.adapters.vllm.chat` | `/v1/chat/completions` | Multi-turn chat. Message content never in evidence. |
| `chp.adapters.vllm.list_models` | `/v1/models` | List served models. |

## Running vLLM locally (macOS, Metal)

```bash
curl -fsSL https://raw.githubusercontent.com/vllm-project/vllm-metal/main/install.sh | bash
source ~/.venv-vllm-metal/bin/activate
vllm serve <model-id> --port 8092
```

## Config

| Field | Env | Default |
|---|---|---|
| `base_url` | `VLLM_BASE_URL` | `http://localhost:8092` |
| `api_key` | `VLLM_API_KEY` | `EMPTY` |
| `default_model` | `VLLM_MODEL` | _(none)_ |
| `timeout` | — | `120.0` |

## Evidence policy

Emitted: model id, prompt/completion token counts, message count, finish reason, latency.
Never emitted: prompt text, completion text, chat message content.
