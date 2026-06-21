"""TEIAdapter — Metal-accelerated text embeddings via a local TEI server.

Wraps a HuggingFace Text Embeddings Inference (TEI) server as governed CHP
capabilities. TEI is Metal-native on Apple Silicon and 5–50x faster than a
transformers.pipeline feature-extraction backend, while exposing the same
capability shape as chp.adapters.huggingface.embed — a swappable backend.

This adapter imports NO HTTP library. Every network call is composed through
the multi-capability router via ``ctx.ainvoke("chp.adapters.http.request", …)``
— the lego-block pattern. HTTP requests become governed evidence events in
their own right, and the TEI adapter stays conformance-clean (no raw_http).

Evidence policy:
  Emitted: input count, vector dimension, candidate count, model id, latency, errors.
  NOT emitted: input text, embedding vectors, rerank text, or rerank scores.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from chp_core import BaseAdapter, capability

_EMITS = [
    "tei_embed_started",
    "tei_embed_completed",
    "tei_embed_failed",
    "tei_rerank_started",
    "tei_rerank_completed",
    "tei_rerank_failed",
    "tei_info_fetched",
    "tei_health_checked",
]

_DEFAULT_BASE_URL = "http://localhost:8090"
_HTTP_CAP = "chp.adapters.http.request"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class TEIConfig:
    base_url: str = ""
    api_key: str = ""
    timeout: float = 60.0

    def resolved_base_url(self) -> str:
        return self.base_url or os.environ.get("TEI_BASE_URL", _DEFAULT_BASE_URL)

    def resolved_api_key(self) -> str:
        return self.api_key or os.environ.get("TEI_API_KEY", "")


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class TEIAdapter(BaseAdapter):
    """Metal-accelerated embeddings via a local Text Embeddings Inference server."""

    adapter_id = "chp.adapters.tei"
    adapter_name = "TEI"
    adapter_description = (
        "Text Embeddings Inference — Metal-accelerated embeddings and reranking "
        "from a local TEI server, composed through chp.adapters.http as governed "
        "CHP capabilities."
    )
    adapter_category = "ai"
    adapter_tags = ["tei", "embeddings", "rerank", "metal", "local", "huggingface"]

    def __init__(self, config: TEIConfig | None = None) -> None:
        self._config = config or TEIConfig()

    # ------------------------------------------------------------------
    # HTTP composition — routes every call through the multi-capability router
    # ------------------------------------------------------------------

    async def _http(self, ctx: Any, method: str, path: str, json_body: Any | None = None) -> dict:
        base = self._config.resolved_base_url().rstrip("/")
        req: dict[str, Any] = {"method": method, "url": f"{base}{path}", "timeout": self._config.timeout}
        if json_body is not None:
            req["json_body"] = json_body
        api_key = self._config.resolved_api_key()
        if api_key:
            req["headers"] = {"Authorization": f"Bearer {api_key}"}

        result = await ctx.ainvoke(_HTTP_CAP, req)
        if not result.success:
            raise RuntimeError(
                f"TEI {method} {path}: http adapter unavailable or denied "
                f"({getattr(result, 'error', 'unknown error')}). "
                "Ensure chp.adapters.http is registered on this host."
            )
        data = result.data
        status = data.get("status_code")
        if status is None or status >= 400:
            raise RuntimeError(f"TEI {method} {path} returned HTTP {status}")
        return data

    # ------------------------------------------------------------------
    # embed
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tei.embed",
        version="1.0.0",
        description=(
            "Generate text embeddings via a local Metal-accelerated TEI server, "
            "composed through chp.adapters.http. Vectors are returned but never "
            "recorded in evidence."
        ),
        category="ai",
        provider="tei",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "inputs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Texts to embed",
                },
                "normalize": {"type": "boolean", "default": True, "description": "L2-normalize output vectors"},
                "truncate": {"type": "boolean", "default": True, "description": "Truncate inputs over the model max length"},
            },
            "required": ["inputs"],
            "additionalProperties": False,
        },
    )
    async def embed(self, ctx: Any, payload: dict) -> dict:
        inputs: list[str] = payload["inputs"]
        normalize: bool = payload.get("normalize", True)
        truncate: bool = payload.get("truncate", True)

        ctx.emit("tei_embed_started", {"input_count": len(inputs), "normalize": normalize}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/embed", {
                "inputs": inputs, "normalize": normalize, "truncate": truncate,
            })
        except Exception as exc:
            ctx.emit("tei_embed_failed", {"input_count": len(inputs), "error": str(exc)[:500]}, redacted=False)
            raise

        vectors = data.get("json") or []
        latency_ms = round((time.monotonic() - t0) * 1000)
        vector_dim = len(vectors[0]) if vectors else 0
        ctx.emit("tei_embed_completed", {
            "input_count": len(inputs),
            "vector_dim": vector_dim,
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "embeddings": vectors,
            "vector_dim": vector_dim,
            "input_count": len(inputs),
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # rerank
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tei.rerank",
        version="1.0.0",
        description=(
            "Rerank candidate texts against a query using a TEI cross-encoder model, "
            "composed through chp.adapters.http. Returns index+score ranking. Text and "
            "scores are not recorded in evidence. Requires the loaded TEI model to be a "
            "sequence-classification (reranker) model."
        ),
        category="ai",
        provider="tei",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1, "description": "Query to rank candidates against"},
                "texts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Candidate texts to rerank",
                },
                "raw_scores": {"type": "boolean", "default": False, "description": "Return raw logits instead of sigmoid scores"},
            },
            "required": ["query", "texts"],
            "additionalProperties": False,
        },
    )
    async def rerank(self, ctx: Any, payload: dict) -> dict:
        query: str = payload["query"]
        texts: list[str] = payload["texts"]
        raw_scores: bool = payload.get("raw_scores", False)

        ctx.emit("tei_rerank_started", {"candidate_count": len(texts)}, redacted=False)

        t0 = time.monotonic()
        try:
            data = await self._http(ctx, "POST", "/rerank", {
                "query": query, "texts": texts, "raw_scores": raw_scores,
            })
        except Exception as exc:
            ctx.emit("tei_rerank_failed", {"candidate_count": len(texts), "error": str(exc)[:500]}, redacted=False)
            raise

        ranking = data.get("json") or []
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("tei_rerank_completed", {
            "candidate_count": len(texts),
            "result_count": len(ranking),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "ranking": ranking,
            "result_count": len(ranking),
            "candidate_count": len(texts),
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # info
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tei.info",
        version="1.0.0",
        description="Fetch the TEI server's model metadata (model id, dtype, max input length) via chp.adapters.http.",
        category="ai",
        provider="tei",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def info(self, ctx: Any, payload: dict) -> dict:
        t0 = time.monotonic()
        data = await self._http(ctx, "GET", "/info")
        latency_ms = round((time.monotonic() - t0) * 1000)

        raw = data.get("json") or {}
        normalized = {
            "model_id": raw.get("model_id"),
            "model_dtype": raw.get("model_dtype"),
            "max_input_length": raw.get("max_input_length"),
            "max_batch_tokens": raw.get("max_batch_tokens"),
            "model_type": raw.get("model_type"),
            "version": raw.get("version"),
        }
        ctx.emit("tei_info_fetched", {
            "model_id": normalized["model_id"],
            "max_input_length": normalized["max_input_length"],
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**normalized, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # health
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.tei.health",
        version="1.0.0",
        description="Check whether the local TEI server is reachable and ready, via chp.adapters.http.",
        category="ai",
        provider="tei",
        risk="low",
        emits=_EMITS,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )
    async def health(self, ctx: Any, payload: dict) -> dict:
        t0 = time.monotonic()
        ok = False
        try:
            data = await self._http(ctx, "GET", "/health")
            ok = data.get("status_code") == 200
        except Exception:
            ok = False
        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("tei_health_checked", {"healthy": ok, "latency_ms": latency_ms}, redacted=False)
        return {"healthy": ok, "base_url": self._config.resolved_base_url(), "latency_ms": latency_ms}
