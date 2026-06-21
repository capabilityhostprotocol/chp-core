# chp-adapter-tei

Metal-accelerated text embeddings and reranking as governed CHP capabilities,
backed by a local [Text Embeddings Inference (TEI)](https://huggingface.co/docs/text-embeddings-inference)
server.

TEI is the production embeddings substrate: 5–50x faster than a
`transformers.pipeline` feature-extraction backend, Metal-native on Apple
Silicon, and CUDA-native on NVIDIA. This adapter exposes the same capability
shape as `chp.adapters.huggingface.embed`, so it is a drop-in swappable
backend — the HuggingFace adapter stays the artifact/registry layer.

## Capabilities

| Capability | Description |
|---|---|
| `chp.adapters.tei.embed` | Embed texts. Vectors returned, never recorded in evidence. |
| `chp.adapters.tei.rerank` | Rerank candidates against a query (cross-encoder TEI model). |
| `chp.adapters.tei.info` | Model metadata: model id, dtype, max input length, pooling. |
| `chp.adapters.tei.health` | Server reachability/readiness probe. |

## Running TEI locally (macOS, Metal)

```bash
brew install text-embeddings-inference
text-embeddings-router --model-id sentence-transformers/all-MiniLM-L6-v2 --port 8090
```

## Config

| Field | Env | Default |
|---|---|---|
| `base_url` | `TEI_BASE_URL` | `http://localhost:8090` |
| `api_key` | `TEI_API_KEY` | _(none)_ |
| `timeout` | — | `60.0` |

## Evidence policy

Emitted: model id, input/candidate counts, vector dimension, latency, errors.
Never emitted: input text, embedding vectors, rerank text, rerank scores.
