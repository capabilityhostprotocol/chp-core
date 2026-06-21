"""HuggingFaceAdapter — governed local consumption of HuggingFace Hub artifacts.

Pull models/datasets/tokenizers to local cache, run inference via transformers
pipeline, embed text, tokenize, and audit local cache storage — all as
evidence-producing CHP capability invocations.

Evidence policy:
  Emitted: repo_id, model name, task, token counts, latency, sizes, errors.
  NOT emitted: raw text inputs, model outputs, embeddings, token IDs, dataset rows.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any

from chp_core import BaseAdapter, capability

from ._backends import HFBackend, make_backend

_EMITS = [
    "hf_pull_started",
    "hf_pull_completed",
    "hf_pull_failed",
    "hf_pipeline_started",
    "hf_pipeline_completed",
    "hf_pipeline_failed",
    "hf_embed_started",
    "hf_embed_completed",
    "hf_embed_failed",
    "hf_tokenize_started",
    "hf_tokenize_completed",
    "hf_tokenize_failed",
    "hf_dataset_started",
    "hf_dataset_completed",
    "hf_dataset_failed",
    "hf_cache_scanned",
    "hf_search_started",
    "hf_search_completed",
    "hf_search_failed",
    "hf_model_card_started",
    "hf_model_card_fetched",
    "hf_model_card_failed",
    "hf_pull_local_llm_started",
    "hf_pull_local_llm_completed",
    "hf_pull_local_llm_failed",
    "hf_search_datasets_started",
    "hf_search_datasets_completed",
    "hf_search_datasets_failed",
    "hf_search_spaces_started",
    "hf_search_spaces_completed",
    "hf_search_spaces_failed",
    "hf_list_collections_started",
    "hf_list_collections_completed",
    "hf_list_collections_failed",
    "hf_dataset_preview_started",
    "hf_dataset_preview_completed",
    "hf_dataset_preview_failed",
    "hf_leaderboard_started",
    "hf_leaderboard_completed",
    "hf_leaderboard_failed",
    "hf_evaluate_started",
    "hf_evaluate_completed",
    "hf_evaluate_failed",
    "hf_apply_adapter_started",
    "hf_apply_adapter_completed",
    "hf_apply_adapter_failed",
    "hf_call_space_started",
    "hf_call_space_completed",
    "hf_call_space_failed",
    "hf_finetune_started",
    "hf_finetune_completed",
    "hf_finetune_failed",
    "hf_quantize_started",
    "hf_quantize_completed",
    "hf_quantize_failed",
    "hf_faiss_started",
    "hf_faiss_completed",
    "hf_faiss_failed",
    "hf_transcribe_started",
    "hf_transcribe_completed",
    "hf_transcribe_failed",
    "hf_classify_image_started",
    "hf_classify_image_completed",
    "hf_classify_image_failed",
    "hf_generate_image_started",
    "hf_generate_image_completed",
    "hf_generate_image_failed",
]


@dataclass
class HuggingFaceConfig:
    token: str = ""
    cache_dir: str = ""
    datasets_cache_dir: str = ""
    default_device: str = "cpu"
    allow_remote_downloads: bool = True
    _backend: Any = field(default=None, repr=False)

    def resolved_token(self) -> str:
        return self.token or os.environ.get("HF_TOKEN", "")

    def resolved_cache_dir(self) -> str:
        return self.cache_dir or os.path.expanduser("~/.cache/huggingface/hub")

    def resolved_datasets_cache_dir(self) -> str:
        return self.datasets_cache_dir or os.path.expanduser("~/.cache/huggingface/datasets")


class HuggingFaceAdapter(BaseAdapter):
    """Pull and use HuggingFace Hub artifacts locally with full evidence chains."""

    adapter_id = "chp.adapters.huggingface"
    adapter_name = "HuggingFace"
    adapter_description = (
        "Local consumption of HuggingFace Hub artifacts: pull models/datasets, "
        "run transformers pipelines, embed text, tokenize, and audit local cache."
    )
    adapter_category = "ai"
    adapter_tags = ["huggingface", "transformers", "nlp", "models", "datasets", "local"]

    def __init__(self, config: HuggingFaceConfig | None = None) -> None:
        self._config = config or HuggingFaceConfig()
        self.__backend: HFBackend | None = None

    async def _get_token(self, ctx: Any) -> str:
        """Retrieve HF_TOKEN via secrets adapter (governed), falling back to config/env."""
        if self._config.token:
            return self._config.token
        try:
            result = await ctx.ainvoke("chp.adapters.secrets.get", {"key": "HF_TOKEN"})
            if result.success and result.data.get("value"):
                return result.data["value"]
        except Exception:
            pass
        return os.environ.get("HF_TOKEN", "")

    def _backend(self) -> HFBackend:
        if self._config._backend is not None:
            return self._config._backend
        if self.__backend is None:
            self.__backend = make_backend()
        return self.__backend

    # ------------------------------------------------------------------
    # pull
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.pull",
        version="1.0.0",
        description="Download any HuggingFace Hub artifact (model, dataset, tokenizer) to local cache via snapshot_download.",
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Hub repo ID, e.g. 'bert-base-uncased'"},
                "repo_type": {"type": "string", "enum": ["model", "dataset", "space"], "default": "model"},
                "revision": {"type": "string", "description": "Branch, tag, or commit hash (default: main)"},
                "allow_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Glob patterns to limit which files are downloaded, e.g. ['*.safetensors', '*.json']",
                },
            },
            "required": ["repo_id"],
            "additionalProperties": False,
        },
    )
    async def pull(self, ctx: Any, payload: dict) -> dict:
        repo_id: str = payload["repo_id"]
        repo_type: str = payload.get("repo_type", "model")
        revision: str | None = payload.get("revision")
        allow_patterns: list[str] | None = payload.get("allow_patterns")

        if not self._config.allow_remote_downloads:
            raise RuntimeError(f"Remote downloads disabled (allow_remote_downloads=False). Pre-cache {repo_id} first.")

        ctx.emit("hf_pull_started", {
            "repo_id": repo_id,
            "repo_type": repo_type,
            "revision": revision or "main",
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().pull,
                repo_id,
                repo_type,
                revision,
                allow_patterns,
                await self._get_token(ctx),
                self._config.resolved_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_pull_failed", {
                "repo_id": repo_id,
                "repo_type": repo_type,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_pull_completed", {
            "repo_id": repo_id,
            "repo_type": repo_type,
            "file_count": result["file_count"],
            "size_bytes": result["size_bytes"],
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "repo_id": repo_id,
            "repo_type": repo_type,
            "cache_path": result["cache_path"],
            "file_count": result["file_count"],
            "size_bytes": result["size_bytes"],
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # run_pipeline
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.run_pipeline",
        version="1.0.0",
        description=(
            "Run a transformers.pipeline() task on a locally-cached model. "
            "Inputs and outputs are never recorded in evidence — only metadata."
        ),
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Hub model ID or local cache path"},
                "task": {
                    "type": "string",
                    "description": "Pipeline task, e.g. text-generation, text-classification, ner, summarization, question-answering, fill-mask, image-classification",
                },
                "inputs": {
                    "description": "Input to the pipeline — string, list of strings, or dict (task-dependent)"
                },
                "device": {"type": "string", "description": "Device: cpu, cuda, cuda:N, mps, auto (default: config default_device)"},
                "max_new_tokens": {"type": "integer", "minimum": 1, "maximum": 4096},
            },
            "required": ["model", "task", "inputs"],
            "additionalProperties": False,
        },
    )
    async def run_pipeline(self, ctx: Any, payload: dict) -> dict:
        model: str = payload["model"]
        task: str = payload["task"]
        inputs = payload["inputs"]
        device: str = payload.get("device") or self._config.default_device
        kwargs: dict = {}
        if payload.get("max_new_tokens"):
            kwargs["max_new_tokens"] = payload["max_new_tokens"]

        ctx.emit("hf_pipeline_started", {
            "model": model,
            "task": task,
            "device": device,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().run_pipeline,
                model,
                task,
                inputs,
                device,
                self._config.resolved_cache_dir(),
                **kwargs,
            )
        except Exception as exc:
            ctx.emit("hf_pipeline_failed", {
                "model": model,
                "task": task,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        output_count = len(result) if isinstance(result, list) else 1

        ctx.emit("hf_pipeline_completed", {
            "model": model,
            "task": task,
            "device": device,
            "output_count": output_count,
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "model": model,
            "task": task,
            "device": device,
            "result": result,
            "output_count": output_count,
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # embed
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.embed",
        version="1.0.0",
        description=(
            "Generate text embeddings using a locally-cached feature-extraction model. "
            "Vectors are returned but never stored in evidence."
        ),
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Embedding model, e.g. 'sentence-transformers/all-MiniLM-L6-v2'"},
                "texts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Texts to embed",
                },
                "pooling": {"type": "string", "enum": ["mean", "cls"], "default": "mean"},
                "device": {"type": "string", "description": "Device: cpu, cuda, mps, auto"},
            },
            "required": ["model", "texts"],
            "additionalProperties": False,
        },
    )
    async def embed(self, ctx: Any, payload: dict) -> dict:
        model: str = payload["model"]
        texts: list[str] = payload["texts"]
        pooling: str = payload.get("pooling", "mean")
        device: str = payload.get("device") or self._config.default_device

        ctx.emit("hf_embed_started", {
            "model": model,
            "text_count": len(texts),
            "pooling": pooling,
            "device": device,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            vectors = await asyncio.to_thread(
                self._backend().embed,
                model,
                texts,
                pooling,
                device,
                self._config.resolved_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_embed_failed", {
                "model": model,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        vector_dim = len(vectors[0]) if vectors else 0

        ctx.emit("hf_embed_completed", {
            "model": model,
            "text_count": len(texts),
            "vector_dim": vector_dim,
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "model": model,
            "embeddings": vectors,
            "vector_dim": vector_dim,
            "text_count": len(texts),
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # tokenize
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.tokenize",
        version="1.0.0",
        description="Encode text to token IDs or decode token IDs to text using a fast HuggingFace tokenizer. No full model load required.",
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Tokenizer model ID, e.g. 'gpt2' or 'bert-base-uncased'"},
                "operation": {"type": "string", "enum": ["encode", "decode"], "default": "encode"},
                "texts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Texts to encode (required for encode)",
                },
                "ids": {
                    "type": "array",
                    "items": {"type": "array", "items": {"type": "integer"}},
                    "description": "Token ID sequences to decode (required for decode)",
                },
            },
            "required": ["model"],
            "additionalProperties": False,
        },
    )
    async def tokenize(self, ctx: Any, payload: dict) -> dict:
        model: str = payload["model"]
        operation: str = payload.get("operation", "encode")
        texts: list[str] | None = payload.get("texts")
        ids: list[list[int]] | None = payload.get("ids")

        ctx.emit("hf_tokenize_started", {
            "model": model,
            "operation": operation,
            "input_count": len(texts or ids or []),
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().tokenize,
                model,
                operation,
                texts,
                ids,
                self._config.resolved_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_tokenize_failed", {
                "model": model,
                "operation": operation,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)

        ctx.emit("hf_tokenize_completed", {
            "model": model,
            "operation": operation,
            "text_count": len(texts or ids or []),
            "total_tokens": result.get("total_tokens", 0),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {**result, "model": model, "operation": operation, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # load_dataset
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.load_dataset",
        version="1.0.0",
        description=(
            "Load rows from a HuggingFace dataset (Hub or local). "
            "Streaming=true reads without downloading the full dataset. "
            "Row content is returned but never stored in evidence."
        ),
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Hub dataset ID, e.g. 'squad' or 'imdb'"},
                "split": {"type": "string", "default": "train", "description": "Dataset split (train, validation, test)"},
                "streaming": {"type": "boolean", "default": True, "description": "Stream rows without downloading full dataset"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100},
                "columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Columns to include (default: all)",
                },
            },
            "required": ["repo_id"],
            "additionalProperties": False,
        },
    )
    async def load_dataset(self, ctx: Any, payload: dict) -> dict:
        repo_id: str = payload["repo_id"]
        split: str = payload.get("split", "train")
        streaming: bool = payload.get("streaming", True)
        limit: int = payload.get("limit", 100)
        columns: list[str] | None = payload.get("columns")

        ctx.emit("hf_dataset_started", {
            "repo_id": repo_id,
            "split": split,
            "streaming": streaming,
            "limit": limit,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().load_dataset,
                repo_id,
                split,
                streaming,
                limit,
                columns,
                await self._get_token(ctx),
                self._config.resolved_datasets_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_dataset_failed", {
                "repo_id": repo_id,
                "split": split,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)

        ctx.emit("hf_dataset_completed", {
            "repo_id": repo_id,
            "split": split,
            "row_count": result["row_count"],
            "columns": result["columns"],
            "latency_ms": latency_ms,
        }, redacted=False)

        return {**result, "repo_id": repo_id, "split": split, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # cache_info
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.cache_info",
        version="1.0.0",
        description="Scan the local HuggingFace cache and return a storage summary by artifact for governance and quota management.",
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    )
    async def cache_info(self, ctx: Any, payload: dict) -> dict:
        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().cache_info,
                self._config.resolved_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_cache_scanned", {
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)

        ctx.emit("hf_cache_scanned", {
            "repo_count": result["repo_count"],
            "revision_count": result["revision_count"],
            "total_size_bytes": result["total_size_bytes"],
            "latency_ms": latency_ms,
        }, redacted=False)

        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # search_models
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.search_models",
        version="1.0.0",
        description=(
            "Search HuggingFace Hub for models by task, sort, and filter. "
            "Enables agents to discover models programmatically rather than hardcoding repo_ids."
        ),
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "Pipeline task to filter by, e.g. 'text-generation', 'text-classification', 'automatic-speech-recognition'",
                },
                "sort": {
                    "type": "string",
                    "enum": ["downloads", "likes", "lastModified", "createdAt"],
                    "default": "downloads",
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                "filter": {
                    "type": "string",
                    "description": "Additional tag filter, e.g. 'gguf', 'quantized', 'en'",
                },
            },
            "additionalProperties": False,
        },
    )
    async def search_models(self, ctx: Any, payload: dict) -> dict:
        task: str | None = payload.get("task")
        sort: str = payload.get("sort", "downloads")
        limit: int = payload.get("limit", 20)
        filter_tag: str | None = payload.get("filter")

        ctx.emit("hf_search_started", {
            "task": task,
            "sort": sort,
            "limit": limit,
            "filter": filter_tag,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            models = await asyncio.to_thread(
                self._backend().search_models,
                task,
                sort,
                limit,
                filter_tag,
                await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_search_failed", {
                "task": task,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_search_completed", {
            "task": task,
            "sort": sort,
            "result_count": len(models),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "models": models,
            "result_count": len(models),
            "task": task,
            "sort": sort,
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # model_card
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.model_card",
        version="1.0.0",
        description=(
            "Fetch structured model metadata from HuggingFace Hub: license, pipeline task, "
            "tags, gated status, author, and provenance. Governance gate before deploying any model."
        ),
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Hub repo ID, e.g. 'meta-llama/Llama-3.2-1B'"},
            },
            "required": ["repo_id"],
            "additionalProperties": False,
        },
    )
    async def model_card(self, ctx: Any, payload: dict) -> dict:
        repo_id: str = payload["repo_id"]

        ctx.emit("hf_model_card_started", {
            "repo_id": repo_id,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            info = await asyncio.to_thread(
                self._backend().model_card,
                repo_id,
                await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_model_card_failed", {
                "repo_id": repo_id,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_model_card_fetched", {
            "repo_id": repo_id,
            "pipeline_tag": info.get("pipeline_tag"),
            "license": info.get("license"),
            "gated": info.get("gated"),
            "tag_count": len(info.get("tags", [])),
            "latency_ms": latency_ms,
        }, redacted=False)

        return {**info, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # pull_for_local_llm
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.pull_for_local_llm",
        version="1.0.0",
        description=(
            "Pull GGUF model files from HuggingFace Hub and return the local path ready "
            "to pass directly to chp.adapters.local_llm. Closes the HF registry → llama.cpp loop."
        ),
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Hub repo with GGUF files, e.g. 'TheBloke/Llama-2-7B-GGUF'"},
                "filename": {
                    "type": "string",
                    "description": "Specific GGUF filename to pull (e.g. 'llama-2-7b.Q4_K_M.gguf'). If omitted, pulls all *.gguf files.",
                },
            },
            "required": ["repo_id"],
            "additionalProperties": False,
        },
    )
    async def pull_for_local_llm(self, ctx: Any, payload: dict) -> dict:
        repo_id: str = payload["repo_id"]
        filename: str | None = payload.get("filename")

        if not self._config.allow_remote_downloads:
            raise RuntimeError(f"Remote downloads disabled. Pre-cache {repo_id} first.")

        ctx.emit("hf_pull_local_llm_started", {
            "repo_id": repo_id,
            "filename": filename,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().pull_for_local_llm,
                repo_id,
                filename,
                await self._get_token(ctx),
                self._config.resolved_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_pull_local_llm_failed", {
                "repo_id": repo_id,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_pull_local_llm_completed", {
            "repo_id": repo_id,
            "file_count": result["file_count"],
            "size_bytes": result["size_bytes"],
            "has_recommended": result["recommended_path"] is not None,
            "latency_ms": latency_ms,
        }, redacted=False)

        return {
            "repo_id": repo_id,
            "cache_path": result["cache_path"],
            "gguf_files": result["gguf_files"],
            "recommended_path": result["recommended_path"],
            "file_count": result["file_count"],
            "size_bytes": result["size_bytes"],
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # search_datasets
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.search_datasets",
        version="1.0.0",
        description="Search HuggingFace Hub for datasets by task, sort, and filter. Symmetric to search_models — enables agents to discover datasets before loading them.",
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "task": {"type": "string", "description": "Task category to filter by, e.g. 'text-classification', 'question-answering'"},
                "sort": {"type": "string", "enum": ["downloads", "likes", "lastModified", "createdAt"], "default": "downloads"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                "filter": {"type": "string", "description": "Additional tag filter, e.g. 'en', 'multilingual'"},
            },
            "additionalProperties": False,
        },
    )
    async def search_datasets(self, ctx: Any, payload: dict) -> dict:
        task: str | None = payload.get("task")
        sort: str = payload.get("sort", "downloads")
        limit: int = payload.get("limit", 20)
        filter_tag: str | None = payload.get("filter")

        ctx.emit("hf_search_datasets_started", {"task": task, "sort": sort, "limit": limit, "filter": filter_tag}, redacted=False)

        t0 = time.monotonic()
        try:
            datasets = await asyncio.to_thread(
                self._backend().search_datasets, task, sort, limit, filter_tag, await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_search_datasets_failed", {"task": task, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_search_datasets_completed", {"task": task, "sort": sort, "result_count": len(datasets), "latency_ms": latency_ms}, redacted=False)
        return {"datasets": datasets, "result_count": len(datasets), "task": task, "sort": sort, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # search_spaces
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.search_spaces",
        version="1.0.0",
        description="Search HuggingFace Hub for Spaces (Gradio/Streamlit apps) by SDK, sort, and filter. Precondition for call_space discovery.",
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "sdk": {"type": "string", "enum": ["gradio", "streamlit", "docker", "static"], "description": "Filter by Space SDK type"},
                "sort": {"type": "string", "enum": ["likes", "lastModified", "createdAt"], "default": "likes"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                "filter": {"type": "string", "description": "Tag filter, e.g. 'speech', 'vision', 'nlp'"},
            },
            "additionalProperties": False,
        },
    )
    async def search_spaces(self, ctx: Any, payload: dict) -> dict:
        sdk: str | None = payload.get("sdk")
        sort: str = payload.get("sort", "likes")
        limit: int = payload.get("limit", 20)
        filter_tag: str | None = payload.get("filter")

        ctx.emit("hf_search_spaces_started", {"sdk": sdk, "sort": sort, "limit": limit, "filter": filter_tag}, redacted=False)

        t0 = time.monotonic()
        try:
            spaces = await asyncio.to_thread(
                self._backend().search_spaces, sdk, sort, limit, filter_tag, await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_search_spaces_failed", {"sdk": sdk, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_search_spaces_completed", {"sdk": sdk, "sort": sort, "result_count": len(spaces), "latency_ms": latency_ms}, redacted=False)
        return {"spaces": spaces, "result_count": len(spaces), "sdk": sdk, "sort": sort, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # list_collections
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.list_collections",
        version="1.0.0",
        description="List HuggingFace Hub Collections — curated groupings of models and datasets. Enables agents to navigate thematic clusters (e.g. 'Open LLM Leaderboard 2').",
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "owner": {"type": "string", "description": "Filter by owner username or org, e.g. 'huggingface', 'open-llm-leaderboard'"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            "additionalProperties": False,
        },
    )
    async def list_collections(self, ctx: Any, payload: dict) -> dict:
        owner: str | None = payload.get("owner")
        limit: int = payload.get("limit", 20)

        ctx.emit("hf_list_collections_started", {"owner": owner, "limit": limit}, redacted=False)

        t0 = time.monotonic()
        try:
            collections = await asyncio.to_thread(
                self._backend().list_collections, owner, limit, await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_list_collections_failed", {"owner": owner, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_list_collections_completed", {"owner": owner, "result_count": len(collections), "latency_ms": latency_ms}, redacted=False)
        return {"collections": collections, "result_count": len(collections), "owner": owner, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # dataset_preview
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.dataset_preview",
        version="1.0.0",
        description=(
            "Preview the schema and first N rows of a HuggingFace dataset via the Dataset Viewer API — "
            "no download required. Governance check before load_dataset. Row content returned but never stored in evidence."
        ),
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Hub dataset repo ID, e.g. 'squad', 'imdb'"},
                "split": {"type": "string", "default": "train", "description": "Dataset split to preview"},
                "config": {"type": "string", "description": "Dataset config/subset name (if required by dataset)"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 5},
            },
            "required": ["repo_id"],
            "additionalProperties": False,
        },
    )
    async def dataset_preview(self, ctx: Any, payload: dict) -> dict:
        repo_id: str = payload["repo_id"]
        split: str = payload.get("split", "train")
        config: str | None = payload.get("config")
        limit: int = payload.get("limit", 5)

        ctx.emit("hf_dataset_preview_started", {"repo_id": repo_id, "split": split, "limit": limit}, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().dataset_preview, repo_id, split, config, limit, await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_dataset_preview_failed", {"repo_id": repo_id, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_dataset_preview_completed", {
            "repo_id": repo_id, "split": split, "row_count": result["row_count"],
            "column_count": len(result["columns"]), "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "repo_id": repo_id, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # leaderboard_scores
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.leaderboard_scores",
        version="1.0.0",
        description=(
            "Fetch evaluation benchmark scores for a model from HuggingFace Hub (MMLU, ARC, TruthfulQA, etc.). "
            "Evidence-backed model selection before pull. Score values returned but not emitted in evidence."
        ),
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Hub model repo ID to fetch evaluation results for"},
            },
            "required": ["repo_id"],
            "additionalProperties": False,
        },
    )
    async def leaderboard_scores(self, ctx: Any, payload: dict) -> dict:
        repo_id: str = payload["repo_id"]

        ctx.emit("hf_leaderboard_started", {"repo_id": repo_id}, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().leaderboard_scores, repo_id, await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_leaderboard_failed", {"repo_id": repo_id, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_leaderboard_completed", {
            "repo_id": repo_id, "result_count": result["result_count"], "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # evaluate
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.evaluate",
        version="1.0.0",
        description=(
            "Compute evaluation metrics (BLEU, ROUGE, accuracy, F1, exact_match) against ground-truth references. "
            "Quality gate: score keys logged in evidence, predictions and references never emitted."
        ),
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "metric": {"type": "string", "description": "Metric name: 'bleu', 'rouge', 'accuracy', 'f1', 'exact_match'"},
                "predictions": {"type": "array", "items": {}, "description": "Model outputs — strings or ints"},
                "references": {"type": "array", "items": {}, "description": "Ground-truth labels — strings or ints"},
                "kwargs": {"type": "object", "description": "Extra metric parameters (e.g. tokenizer for BLEU)"},
            },
            "required": ["metric", "predictions", "references"],
            "additionalProperties": False,
        },
    )
    async def evaluate(self, ctx: Any, payload: dict) -> dict:
        metric: str = payload["metric"]
        predictions: list = payload["predictions"]
        references: list = payload["references"]
        kwargs: dict | None = payload.get("kwargs")

        ctx.emit("hf_evaluate_started", {
            "metric": metric,
            "sample_count": len(predictions),
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().evaluate_metric, metric, predictions, references, kwargs,
            )
        except Exception as exc:
            ctx.emit("hf_evaluate_failed", {"metric": metric, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_evaluate_completed", {
            "metric": metric,
            "score_keys": list(result.get("scores", {}).keys()),
            "sample_count": len(predictions),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {
            "metric": metric,
            "scores": result["scores"],
            "sample_count": len(predictions),
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # apply_adapter
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.apply_adapter",
        version="1.0.0",
        description=(
            "Download a LoRA/PEFT adapter from HuggingFace Hub and inspect its configuration. "
            "Returns the local adapter path ready for inference. No full base-model load required."
        ),
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "base_model": {"type": "string", "description": "Base model the adapter targets, e.g. 'meta-llama/Llama-3.2-1B'"},
                "adapter_repo_id": {"type": "string", "description": "Hub PEFT adapter repo ID, e.g. 'org/llama-3-1b-lora'"},
            },
            "required": ["base_model", "adapter_repo_id"],
            "additionalProperties": False,
        },
    )
    async def apply_adapter(self, ctx: Any, payload: dict) -> dict:
        base_model: str = payload["base_model"]
        adapter_repo_id: str = payload["adapter_repo_id"]

        ctx.emit("hf_apply_adapter_started", {
            "base_model": base_model,
            "adapter_repo_id": adapter_repo_id,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().apply_adapter,
                base_model,
                adapter_repo_id,
                self._config.resolved_cache_dir(),
                await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_apply_adapter_failed", {
                "adapter_repo_id": adapter_repo_id,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_apply_adapter_completed", {
            "adapter_repo_id": adapter_repo_id,
            "peft_type": result.get("peft_type"),
            "base_model_name": result.get("base_model_name"),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # call_space
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.call_space",
        version="1.0.0",
        description=(
            "Invoke any HuggingFace Gradio Space as a governed CHP capability via gradio_client. "
            "Space ID, api_name, and latency logged in evidence. Inputs and outputs never emitted."
        ),
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "space_id": {"type": "string", "description": "Hub Space ID, e.g. 'stabilityai/stable-diffusion'"},
                "api_name": {"type": "string", "default": "/predict", "description": "Gradio API endpoint name"},
                "inputs": {"description": "Positional inputs — single value or list"},
            },
            "required": ["space_id", "inputs"],
            "additionalProperties": False,
        },
    )
    async def call_space(self, ctx: Any, payload: dict) -> dict:
        space_id: str = payload["space_id"]
        api_name: str = payload.get("api_name", "/predict")
        inputs = payload["inputs"]

        ctx.emit("hf_call_space_started", {
            "space_id": space_id,
            "api_name": api_name,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().call_space,
                space_id,
                api_name,
                inputs,
                await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_call_space_failed", {
                "space_id": space_id,
                "api_name": api_name,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_call_space_completed", {
            "space_id": space_id,
            "api_name": api_name,
            "latency_ms": latency_ms,
        }, redacted=False)
        return {
            "space_id": space_id,
            "api_name": api_name,
            "result": result,
            "latency_ms": latency_ms,
        }

    # ------------------------------------------------------------------
    # finetune
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.finetune",
        version="1.0.0",
        description=(
            "Fine-tune a HuggingFace classification model locally using transformers.Trainer. "
            "Governance: model, dataset, hyperparameters, and final loss logged in evidence. "
            "No training content or intermediate weights emitted."
        ),
        category="ai",
        risk="high",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model": {"type": "string", "description": "Base model to fine-tune, e.g. 'distilbert-base-uncased'"},
                "dataset_repo_id": {"type": "string", "description": "Hub dataset for training, e.g. 'imdb'"},
                "output_dir": {"type": "string", "description": "Local path to save the fine-tuned model"},
                "task_type": {"type": "string", "enum": ["text-classification"], "default": "text-classification"},
                "num_epochs": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
                "batch_size": {"type": "integer", "minimum": 1, "maximum": 64, "default": 8},
                "learning_rate": {"type": "number", "minimum": 1e-7, "maximum": 0.1, "default": 5e-5},
                "max_steps": {"type": "integer", "minimum": 1, "description": "Override num_epochs with a fixed step count"},
            },
            "required": ["model", "dataset_repo_id", "output_dir"],
            "additionalProperties": False,
        },
    )
    async def finetune(self, ctx: Any, payload: dict) -> dict:
        model: str = payload["model"]
        dataset_repo_id: str = payload["dataset_repo_id"]
        output_dir: str = payload["output_dir"]
        task_type: str = payload.get("task_type", "text-classification")
        num_epochs: int = payload.get("num_epochs", 3)
        batch_size: int = payload.get("batch_size", 8)
        learning_rate: float = payload.get("learning_rate", 5e-5)
        max_steps: int | None = payload.get("max_steps")

        ctx.emit("hf_finetune_started", {
            "model": model,
            "dataset": dataset_repo_id,
            "task_type": task_type,
            "num_epochs": num_epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "max_steps": max_steps,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().finetune,
                model,
                dataset_repo_id,
                output_dir,
                task_type,
                num_epochs,
                batch_size,
                learning_rate,
                max_steps,
                self._config.resolved_cache_dir(),
                await self._get_token(ctx),
            )
        except Exception as exc:
            ctx.emit("hf_finetune_failed", {
                "model": model,
                "dataset": dataset_repo_id,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_finetune_completed", {
            "model": model,
            "dataset": dataset_repo_id,
            "output_dir": result.get("output_dir"),
            "steps": result.get("steps"),
            "final_loss": result.get("final_loss"),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # quantize_to_gguf
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.quantize_to_gguf",
        version="1.0.0",
        description=(
            "Convert a local HuggingFace model directory to quantized GGUF using llama.cpp tools. "
            "Two-step: convert_hf_to_gguf.py → f16 GGUF, then llama-quantize → target type. "
            "Output path feeds directly into local_llm adapter."
        ),
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "model_path": {"type": "string", "description": "Local HuggingFace model directory (output of pull capability)"},
                "output_path": {"type": "string", "description": "Destination .gguf file path"},
                "quantization": {"type": "string", "default": "Q4_K_M", "description": "Quantization type: Q4_K_M, Q8_0, Q4_0, Q2_K, Q5_K_M, Q6_K"},
                "convert_script": {"type": "string", "description": "Path to convert_hf_to_gguf.py (auto-detected from Homebrew if omitted)"},
                "quantize_bin": {"type": "string", "description": "Path to llama-quantize binary (auto-detected from Homebrew if omitted)"},
            },
            "required": ["model_path", "output_path"],
            "additionalProperties": False,
        },
    )
    async def quantize_to_gguf(self, ctx: Any, payload: dict) -> dict:
        model_path: str = payload["model_path"]
        output_path: str = payload["output_path"]
        quantization: str = payload.get("quantization", "Q4_K_M")
        convert_script: str | None = payload.get("convert_script")
        quantize_bin: str | None = payload.get("quantize_bin")

        ctx.emit("hf_quantize_started", {
            "model_path": model_path,
            "output_path": output_path,
            "quantization": quantization,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().quantize_to_gguf,
                model_path,
                output_path,
                quantization,
                convert_script,
                quantize_bin,
            )
        except Exception as exc:
            ctx.emit("hf_quantize_failed", {
                "model_path": model_path,
                "quantization": quantization,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_quantize_completed", {
            "output_path": result.get("output_path"),
            "quantization": quantization,
            "input_size_bytes": result.get("input_size_bytes"),
            "output_size_bytes": result.get("output_size_bytes"),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # faiss_index
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.faiss_index",
        version="1.0.0",
        description=(
            "Build or search a FAISS cosine-similarity index for RAG pipelines. "
            "'build': creates IndexFlatIP from float embeddings, saves to disk. "
            "'search': loads index, returns top-K nearest indices and scores. "
            "Vector content never emitted in evidence."
        ),
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "operation": {"type": "string", "enum": ["build", "search"]},
                "index_path": {"type": "string", "description": "Path to save (build) or load (search) the FAISS index"},
                "embeddings": {
                    "type": "array",
                    "items": {"type": "array", "items": {"type": "number"}},
                    "description": "Float embedding matrix (required for build)",
                },
                "query": {
                    "type": "array",
                    "items": {"type": "number"},
                    "description": "Query vector (required for search)",
                },
                "top_k": {"type": "integer", "minimum": 1, "maximum": 100, "default": 5},
            },
            "required": ["operation", "index_path"],
            "additionalProperties": False,
        },
    )
    async def faiss_index(self, ctx: Any, payload: dict) -> dict:
        operation: str = payload["operation"]
        index_path: str = payload["index_path"]
        embeddings: list | None = payload.get("embeddings")
        query: list | None = payload.get("query")
        top_k: int = payload.get("top_k", 5)
        dimension: int | None = len(embeddings[0]) if embeddings else None

        ctx.emit("hf_faiss_started", {
            "operation": operation,
            "index_path": index_path,
            "vector_count": len(embeddings) if embeddings else None,
            "top_k": top_k if operation == "search" else None,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().faiss_index,
                operation,
                embeddings,
                index_path,
                query,
                top_k,
                dimension,
            )
        except Exception as exc:
            ctx.emit("hf_faiss_failed", {
                "operation": operation,
                "index_path": index_path,
                "error": str(exc)[:500],
            }, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_faiss_completed", {
            "operation": operation,
            "index_path": result.get("index_path", index_path),
            "vector_count": result.get("vector_count"),
            "top_k": result.get("top_k"),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # transcribe_audio
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.transcribe_audio",
        version="1.0.0",
        description=(
            "Transcribe an audio file to text using a Whisper ASR pipeline. Input is a local "
            "file path (e.g. from the filesystem adapter). The transcript is returned but never "
            "recorded in evidence — only model, language, segment count, and latency."
        ),
        category="ai",
        risk="medium",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "audio_path": {"type": "string", "description": "Local path to the audio file"},
                "model": {"type": "string", "default": "openai/whisper-base", "description": "ASR model id"},
                "language": {"type": "string", "description": "Force a transcription language (e.g. 'english'); omit for auto-detect"},
                "device": {"type": "string", "description": "Device: cpu, mps, cuda, auto"},
            },
            "required": ["audio_path"],
            "additionalProperties": False,
        },
    )
    async def transcribe_audio(self, ctx: Any, payload: dict) -> dict:
        audio_path: str = payload["audio_path"]
        model: str = payload.get("model", "openai/whisper-base")
        language: str | None = payload.get("language")
        device: str = payload.get("device") or self._config.default_device

        ctx.emit("hf_transcribe_started", {"model": model, "language": language, "device": device}, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().transcribe_audio,
                audio_path, model, language, device, self._config.resolved_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_transcribe_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_transcribe_completed", {
            "model": model,
            "language": result.get("language"),
            "segment_count": result.get("segment_count"),
            "char_count": result.get("char_count"),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "model": model, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # classify_image
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.classify_image",
        version="1.0.0",
        description=(
            "Classify an image with a ViT/DeiT image-classification pipeline. Input is a local "
            "image path. Top-N labels and scores are returned but not recorded in evidence — "
            "only model, prediction count, and latency."
        ),
        category="ai",
        risk="low",
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Local path to the image file"},
                "model": {"type": "string", "default": "google/vit-base-patch16-224", "description": "Image-classification model id"},
                "top_k": {"type": "integer", "minimum": 1, "maximum": 100, "default": 5},
                "device": {"type": "string", "description": "Device: cpu, mps, cuda, auto"},
            },
            "required": ["image_path"],
            "additionalProperties": False,
        },
    )
    async def classify_image(self, ctx: Any, payload: dict) -> dict:
        image_path: str = payload["image_path"]
        model: str = payload.get("model", "google/vit-base-patch16-224")
        top_k: int = payload.get("top_k", 5)
        device: str = payload.get("device") or self._config.default_device

        ctx.emit("hf_classify_image_started", {"model": model, "top_k": top_k, "device": device}, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().classify_image,
                image_path, model, top_k, device, self._config.resolved_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_classify_image_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_classify_image_completed", {
            "model": model,
            "prediction_count": result.get("prediction_count"),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "model": model, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # generate_image
    # ------------------------------------------------------------------

    @capability(
        id="chp.adapters.huggingface.generate_image",
        version="1.0.0",
        description=(
            "Generate an image from a text prompt via a diffusers DiffusionPipeline (Stable "
            "Diffusion, etc.) and save it to a local path. The prompt and image bytes are never "
            "recorded in evidence — only model, steps, seed, output dimensions, and latency."
        ),
        category="ai",
        risk="medium",
        side_effects=["file_write"],
        emits=_EMITS,
        input_schema={
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "minLength": 1, "description": "Text prompt for image generation"},
                "output_path": {"type": "string", "description": "Local path to save the generated image (e.g. /tmp/out.png)"},
                "model": {"type": "string", "default": "stabilityai/sd-turbo", "description": "Diffusers model id"},
                "num_inference_steps": {"type": "integer", "minimum": 1, "maximum": 150, "default": 4},
                "guidance_scale": {"type": "number", "minimum": 0.0, "maximum": 20.0, "default": 0.0},
                "seed": {"type": "integer", "description": "Random seed for reproducibility"},
                "device": {"type": "string", "description": "Device: cpu, mps, cuda, auto"},
            },
            "required": ["prompt", "output_path"],
            "additionalProperties": False,
        },
    )
    async def generate_image(self, ctx: Any, payload: dict) -> dict:
        prompt: str = payload["prompt"]
        output_path: str = payload["output_path"]
        model: str = payload.get("model", "stabilityai/sd-turbo")
        steps: int = payload.get("num_inference_steps", 4)
        guidance: float = payload.get("guidance_scale", 0.0)
        seed: int | None = payload.get("seed")
        device: str = payload.get("device") or self._config.default_device

        ctx.emit("hf_generate_image_started", {
            "model": model, "steps": steps, "seed": seed, "device": device,
        }, redacted=False)

        t0 = time.monotonic()
        try:
            result = await asyncio.to_thread(
                self._backend().generate_image,
                prompt, model, steps, guidance, seed, output_path, device, self._config.resolved_cache_dir(),
            )
        except Exception as exc:
            ctx.emit("hf_generate_image_failed", {"model": model, "error": str(exc)[:500]}, redacted=False)
            raise

        latency_ms = round((time.monotonic() - t0) * 1000)
        ctx.emit("hf_generate_image_completed", {
            "model": model,
            "steps": result.get("steps"),
            "seed": result.get("seed"),
            "width": result.get("width"),
            "height": result.get("height"),
            "output_path": result.get("output_path"),
            "latency_ms": latency_ms,
        }, redacted=False)
        return {**result, "model": model, "latency_ms": latency_ms}
