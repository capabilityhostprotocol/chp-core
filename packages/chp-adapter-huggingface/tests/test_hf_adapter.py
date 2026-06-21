"""Tests for chp-adapter-huggingface.

All tests use FakeHFBackend — no huggingface_hub, transformers, or datasets
libraries needed to run this suite.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from chp_adapter_huggingface import HuggingFaceAdapter, HuggingFaceConfig
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore


# ---------------------------------------------------------------------------
# FakeHFBackend — zero real network/library calls
# ---------------------------------------------------------------------------

class FakeHFBackend:
    def pull(self, repo_id, repo_type, revision, allow_patterns, token, cache_dir) -> dict:
        return {
            "cache_path": f"/fake/cache/{repo_id.replace('/', '--')}",
            "file_count": 5,
            "size_bytes": 1_048_576,
        }

    def run_pipeline(self, model, task, inputs, device, cache_dir, **kwargs) -> Any:
        if isinstance(inputs, list):
            return [{"label": "POSITIVE", "score": 0.99}] * len(inputs)
        return [{"label": "POSITIVE", "score": 0.99}]

    def embed(self, model, texts, pooling, device, cache_dir) -> list[list[float]]:
        dim = 384
        return [[0.1] * dim for _ in texts]

    def tokenize(self, model, operation, texts, ids, cache_dir) -> dict:
        if operation == "decode":
            return {"decoded": ["hello world"] * len(ids or []), "text_count": len(ids or [])}
        encoded = [[101, 7592, 102]] * len(texts or [])
        counts = [len(e) for e in encoded]
        return {"encoded": encoded, "token_counts": counts, "total_tokens": sum(counts)}

    def load_dataset(self, repo_id, split, streaming, limit, columns, token, cache_dir) -> dict:
        rows = [{"text": f"row {i}", "label": i % 2} for i in range(limit)]
        cols = columns or ["text", "label"]
        if columns:
            rows = [{k: r[k] for k in columns if k in r} for r in rows]
        return {"rows": rows, "row_count": len(rows), "columns": cols}

    def cache_info(self, cache_dir) -> dict:
        return {
            "repos": [
                {
                    "repo_id": "bert-base-uncased",
                    "repo_type": "model",
                    "size_bytes": 420_000_000,
                    "nb_files": 8,
                    "last_accessed": 1718000000,
                    "revisions": [{"commit_hash": "abc123", "size_bytes": 420_000_000, "nb_files": 8}],
                }
            ],
            "repo_count": 1,
            "total_size_bytes": 420_000_000,
            "revision_count": 1,
        }

    def search_models(self, task, sort, limit, filter_tag, token) -> list[dict]:
        return [
            {
                "repo_id": f"org/model-{i}",
                "task": task or "text-generation",
                "downloads": 1000 * (limit - i),
                "library": "transformers",
                "license": "license:apache-2.0",
                "gated": False,
            }
            for i in range(min(limit, 3))
        ]

    def model_card(self, repo_id, token) -> dict:
        return {
            "repo_id": repo_id,
            "author": "fake-org",
            "license": "license:mit",
            "pipeline_tag": "text-generation",
            "tags": ["text-generation", "en", "license:mit"],
            "gated": False,
            "likes": 42,
            "downloads": 99000,
            "created_at": "2024-01-01T00:00:00",
            "last_modified": "2024-06-01T00:00:00",
            "sha": "deadbeef",
        }

    def search_datasets(self, task, sort, limit, filter_tag, token) -> list[dict]:
        return [
            {
                "repo_id": f"org/dataset-{i}",
                "task_categories": [task or "text-classification"],
                "downloads": 5000 * (limit - i),
                "likes": 100,
                "license": "license:apache-2.0",
                "gated": False,
            }
            for i in range(min(limit, 3))
        ]

    def search_spaces(self, sdk, sort, limit, filter_tag, token) -> list[dict]:
        return [
            {
                "repo_id": f"org/space-{i}",
                "sdk": sdk or "gradio",
                "likes": 200 * (limit - i),
                "author": "org",
                "tags": ["nlp", "demo"],
            }
            for i in range(min(limit, 3))
        ]

    def list_collections(self, owner, limit, token) -> list[dict]:
        return [
            {
                "slug": f"{owner or 'huggingface'}/collection-{i}",
                "title": f"Test Collection {i}",
                "description": "A curated collection",
                "upvotes": 42,
                "item_count": 5,
                "owner": owner or "huggingface",
            }
            for i in range(min(limit, 2))
        ]

    def dataset_preview(self, repo_id, split, config, limit, token) -> dict:
        columns = ["text", "label"]
        rows = [{"text": f"sample {i}", "label": i % 2} for i in range(limit)]
        return {"rows": rows, "row_count": len(rows), "columns": columns, "split": split, "config": config}

    def leaderboard_scores(self, repo_id, token) -> dict:
        return {
            "repo_id": repo_id,
            "eval_results": [
                {"task_type": "text-generation", "dataset_name": "mmlu", "dataset_type": "cais/mmlu",
                 "metric_name": "accuracy", "metric_type": "accuracy", "metric_value": 0.72},
                {"task_type": "text-generation", "dataset_name": "arc", "dataset_type": "ai2_arc",
                 "metric_name": "accuracy", "metric_type": "accuracy", "metric_value": 0.65},
            ],
            "result_count": 2,
        }

    def evaluate_metric(self, metric, predictions, references, kwargs) -> dict:
        if metric == "bleu":
            scores: dict = {"bleu": 0.45}
        elif metric.startswith("rouge"):
            scores = {"rouge1": 0.5, "rouge2": 0.3, "rougeL": 0.4, "rougeLsum": 0.4}
        elif metric == "accuracy":
            scores = {"accuracy": 0.87}
        elif metric == "f1":
            scores = {"f1": 0.82}
        else:
            scores = {metric: 0.75}
        return {"metric": metric, "scores": scores}

    def apply_adapter(self, base_model, adapter_repo_id, cache_dir, token) -> dict:
        return {
            "adapter_path": f"/fake/cache/{adapter_repo_id.replace('/', '--')}",
            "peft_type": "LORA",
            "base_model_name": base_model,
            "requested_base_model": base_model,
            "target_modules": ["q_proj", "v_proj"],
            "r": 16,
            "lora_alpha": 32,
        }

    def call_space(self, space_id, api_name, inputs, token) -> Any:
        return f"fake_result_from_{space_id}"

    def finetune(self, model, dataset_repo_id, output_dir, task_type, num_epochs, batch_size, learning_rate, max_steps, cache_dir, token) -> dict:
        return {
            "output_dir": output_dir,
            "model": model,
            "dataset": dataset_repo_id,
            "task_type": task_type,
            "final_loss": 0.234,
            "steps": max_steps if max_steps is not None else num_epochs * 100,
        }

    def quantize_to_gguf(self, model_path, output_path, quantization, convert_script, quantize_bin) -> dict:
        return {
            "output_path": output_path,
            "quantization": quantization,
            "input_size_bytes": 2_000_000_000,
            "output_size_bytes": 700_000_000,
        }

    def faiss_index(self, operation, embeddings, index_path, query, top_k, dimension) -> dict:
        if operation == "build":
            return {
                "index_path": index_path,
                "vector_count": len(embeddings or []),
                "dimension": dimension or 384,
            }
        return {
            "indices": [0, 1, 2],
            "scores": [0.95, 0.87, 0.72],
            "top_k": top_k or 5,
        }

    def transcribe_audio(self, audio_path, model, language, device, cache_dir) -> dict:
        text = "the quick brown fox"
        return {"text": text, "language": language or "english", "segment_count": 2, "char_count": len(text)}

    def classify_image(self, image_path, model, top_k, device, cache_dir) -> dict:
        preds = [{"label": f"class_{i}", "score": round(0.9 - i * 0.1, 3)} for i in range(min(top_k, 3))]
        return {"predictions": preds, "prediction_count": len(preds)}

    def generate_image(self, prompt, model, num_inference_steps, guidance_scale, seed, output_path, device, cache_dir) -> dict:
        return {"output_path": output_path, "width": 512, "height": 512, "steps": num_inference_steps, "seed": seed}

    def pull_for_local_llm(self, repo_id, filename, token, cache_dir) -> dict:
        fake_path = f"/fake/cache/{repo_id.replace('/', '--')}"
        gguf_name = filename or "model.Q4_K_M.gguf"
        gguf_path = f"{fake_path}/{gguf_name}"
        return {
            "cache_path": fake_path,
            "gguf_files": [gguf_path],
            "recommended_path": gguf_path,
            "file_count": 1,
            "size_bytes": 4_000_000_000,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_host() -> LocalCapabilityHost:
    store = SQLiteEvidenceStore(":memory:")
    host = LocalCapabilityHost(store=store)
    config = HuggingFaceConfig(_backend=FakeHFBackend())
    register_adapter(host, HuggingFaceAdapter(config))
    return host


def _invoke(host: LocalCapabilityHost, cap_id: str, payload: dict | None = None):
    return asyncio.get_event_loop().run_until_complete(
        host.ainvoke(cap_id, payload or {})
    )


# ---------------------------------------------------------------------------
# HuggingFaceConfig
# ---------------------------------------------------------------------------

class TestHuggingFaceConfig:
    def test_resolved_token_from_env(self, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "fake-token")
        config = HuggingFaceConfig()
        assert config.resolved_token() == "fake-token"

    def test_resolved_token_explicit_wins(self, monkeypatch):
        monkeypatch.setenv("HF_TOKEN", "env-token")
        config = HuggingFaceConfig(token="explicit-token")
        assert config.resolved_token() == "explicit-token"

    def test_resolved_token_empty_without_env(self, monkeypatch):
        monkeypatch.delenv("HF_TOKEN", raising=False)
        config = HuggingFaceConfig()
        assert config.resolved_token() == ""

    def test_resolved_cache_dir_default(self):
        config = HuggingFaceConfig()
        assert "huggingface" in config.resolved_cache_dir()

    def test_resolved_cache_dir_custom(self, tmp_path):
        config = HuggingFaceConfig(cache_dir=str(tmp_path))
        assert config.resolved_cache_dir() == str(tmp_path)


# ---------------------------------------------------------------------------
# pull
# ---------------------------------------------------------------------------

class TestPull:
    def test_returns_cache_path(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.pull", {
            "repo_id": "bert-base-uncased",
        })
        assert result.success
        assert "cache_path" in result.data
        assert result.data["repo_id"] == "bert-base-uncased"
        assert result.data["file_count"] == 5
        assert result.data["size_bytes"] == 1_048_576

    def test_default_repo_type_is_model(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.pull", {
            "repo_id": "bert-base-uncased",
        })
        assert result.data["repo_type"] == "model"

    def test_dataset_repo_type(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.pull", {
            "repo_id": "squad",
            "repo_type": "dataset",
        })
        assert result.success
        assert result.data["repo_type"] == "dataset"

    def test_remote_downloads_disabled_raises(self):
        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost(store=store)
        config = HuggingFaceConfig(_backend=FakeHFBackend(), allow_remote_downloads=False)
        register_adapter(host, HuggingFaceAdapter(config))
        result = _invoke(host, "chp.adapters.huggingface.pull", {"repo_id": "bert-base-uncased"})
        assert not result.success

    def test_duration_ms_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.pull", {"repo_id": "gpt2"})
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# run_pipeline
# ---------------------------------------------------------------------------

class TestRunPipeline:
    def test_basic_classification(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.run_pipeline", {
            "model": "distilbert-base-uncased-finetuned-sst-2-english",
            "task": "text-classification",
            "inputs": "I love CHP!",
        })
        assert result.success
        assert result.data["task"] == "text-classification"
        assert "result" in result.data
        assert result.data["output_count"] >= 1

    def test_batch_inputs(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.run_pipeline", {
            "model": "distilbert-base-uncased-finetuned-sst-2-english",
            "task": "text-classification",
            "inputs": ["good", "bad", "ok"],
        })
        assert result.success
        assert result.data["output_count"] == 3

    def test_result_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.run_pipeline", {
            "model": "bert-base",
            "task": "text-classification",
            "inputs": "SECRET_SENTINEL_XYZ",
        })
        assert result.success
        # Verify input text not in evidence events
        replay = host.replay(result.invocation_id)
        replay_str = str(replay)
        assert "SECRET_SENTINEL_XYZ" not in replay_str


# ---------------------------------------------------------------------------
# embed
# ---------------------------------------------------------------------------

class TestEmbed:
    def test_returns_vectors(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.embed", {
            "model": "sentence-transformers/all-MiniLM-L6-v2",
            "texts": ["hello world", "goodbye"],
        })
        assert result.success
        assert result.data["text_count"] == 2
        assert len(result.data["embeddings"]) == 2
        assert result.data["vector_dim"] == 384

    def test_vectors_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.embed", {
            "model": "all-MiniLM-L6-v2",
            "texts": ["test"],
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        # Evidence should have text_count and vector_dim, but NOT the actual float arrays
        for evt in replay:
            payload = evt.get("payload", {})
            assert "embeddings" not in payload
            assert "vectors" not in payload

    def test_pooling_option_accepted(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.embed", {
            "model": "all-MiniLM-L6-v2",
            "texts": ["test"],
            "pooling": "cls",
        })
        assert result.success


# ---------------------------------------------------------------------------
# tokenize
# ---------------------------------------------------------------------------

class TestTokenize:
    def test_encode(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.tokenize", {
            "model": "bert-base-uncased",
            "operation": "encode",
            "texts": ["Hello world", "Goodbye"],
        })
        assert result.success
        assert result.data["total_tokens"] == 6  # 3 per text
        assert len(result.data["encoded"]) == 2

    def test_decode(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.tokenize", {
            "model": "bert-base-uncased",
            "operation": "decode",
            "ids": [[101, 7592, 102]],
        })
        assert result.success
        assert len(result.data["decoded"]) == 1

    def test_default_operation_is_encode(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.tokenize", {
            "model": "gpt2",
            "texts": ["test"],
        })
        assert result.success
        assert result.data["operation"] == "encode"


# ---------------------------------------------------------------------------
# load_dataset
# ---------------------------------------------------------------------------

class TestLoadDataset:
    def test_returns_rows(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.load_dataset", {
            "repo_id": "imdb",
            "limit": 10,
        })
        assert result.success
        assert result.data["row_count"] == 10
        assert len(result.data["rows"]) == 10

    def test_column_filter(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.load_dataset", {
            "repo_id": "imdb",
            "limit": 5,
            "columns": ["text"],
        })
        assert result.success
        for row in result.data["rows"]:
            assert "text" in row
            assert "label" not in row

    def test_streaming_flag_accepted(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.load_dataset", {
            "repo_id": "squad",
            "streaming": False,
            "limit": 3,
        })
        assert result.success

    def test_rows_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.load_dataset", {
            "repo_id": "imdb",
            "limit": 2,
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            assert "rows" not in evt.get("payload", {})


# ---------------------------------------------------------------------------
# cache_info
# ---------------------------------------------------------------------------

class TestCacheInfo:
    def test_returns_repo_summary(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.cache_info", {})
        assert result.success
        assert result.data["repo_count"] == 1
        assert result.data["total_size_bytes"] == 420_000_000
        assert len(result.data["repos"]) == 1
        assert result.data["repos"][0]["repo_id"] == "bert-base-uncased"

    def test_revision_info_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.cache_info", {})
        repo = result.data["repos"][0]
        assert "revisions" in repo
        assert repo["revisions"][0]["commit_hash"] == "abc123"


# ---------------------------------------------------------------------------
# search_datasets
# ---------------------------------------------------------------------------

class TestSearchDatasets:
    def test_returns_dataset_list(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_datasets", {"limit": 3})
        assert result.success
        assert result.data["result_count"] == 3
        assert len(result.data["datasets"]) == 3

    def test_dataset_fields_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_datasets", {"limit": 1})
        assert result.success
        d = result.data["datasets"][0]
        for field in ("repo_id", "task_categories", "downloads", "likes", "license", "gated"):
            assert field in d, f"missing field: {field}"

    def test_task_filter_accepted(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_datasets", {"task": "text-classification", "limit": 2})
        assert result.success

    def test_default_sort_is_downloads(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_datasets", {})
        assert result.success
        assert result.data["sort"] == "downloads"


# ---------------------------------------------------------------------------
# search_spaces
# ---------------------------------------------------------------------------

class TestSearchSpaces:
    def test_returns_space_list(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_spaces", {"limit": 3})
        assert result.success
        assert result.data["result_count"] == 3

    def test_space_fields_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_spaces", {"limit": 1})
        assert result.success
        s = result.data["spaces"][0]
        for field in ("repo_id", "sdk", "likes", "author", "tags"):
            assert field in s

    def test_sdk_filter_accepted(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_spaces", {"sdk": "gradio", "limit": 2})
        assert result.success
        assert result.data["sdk"] == "gradio"

    def test_default_sort_is_likes(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_spaces", {})
        assert result.success
        assert result.data["sort"] == "likes"


# ---------------------------------------------------------------------------
# list_collections
# ---------------------------------------------------------------------------

class TestListCollections:
    def test_returns_collection_list(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.list_collections", {"limit": 2})
        assert result.success
        assert result.data["result_count"] == 2

    def test_collection_fields_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.list_collections", {"limit": 1})
        assert result.success
        c = result.data["collections"][0]
        for field in ("slug", "title", "upvotes", "item_count", "owner"):
            assert field in c

    def test_owner_filter_accepted(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.list_collections", {"owner": "huggingface", "limit": 1})
        assert result.success
        assert result.data["owner"] == "huggingface"


# ---------------------------------------------------------------------------
# dataset_preview
# ---------------------------------------------------------------------------

class TestDatasetPreview:
    def test_returns_rows_and_columns(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.dataset_preview", {"repo_id": "imdb", "limit": 3})
        assert result.success
        assert result.data["row_count"] == 3
        assert len(result.data["columns"]) == 2
        assert result.data["repo_id"] == "imdb"

    def test_rows_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.dataset_preview", {"repo_id": "imdb", "limit": 2})
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            assert "rows" not in evt.get("payload", {})

    def test_split_accepted(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.dataset_preview", {"repo_id": "squad", "split": "validation"})
        assert result.success
        assert result.data["split"] == "validation"

    def test_default_limit_is_5(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.dataset_preview", {"repo_id": "imdb"})
        assert result.success
        assert result.data["row_count"] == 5


# ---------------------------------------------------------------------------
# leaderboard_scores
# ---------------------------------------------------------------------------

class TestLeaderboardScores:
    def test_returns_eval_results(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.leaderboard_scores", {"repo_id": "meta-llama/Llama-3.2-1B"})
        assert result.success
        assert result.data["repo_id"] == "meta-llama/Llama-3.2-1B"
        assert result.data["result_count"] == 2
        assert len(result.data["eval_results"]) == 2

    def test_eval_result_fields_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.leaderboard_scores", {"repo_id": "gpt2"})
        assert result.success
        er = result.data["eval_results"][0]
        for field in ("task_type", "dataset_name", "metric_name", "metric_value"):
            assert field in er

    def test_scores_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.leaderboard_scores", {"repo_id": "gpt2"})
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            assert "eval_results" not in evt.get("payload", {})
            assert "metric_value" not in evt.get("payload", {})

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.leaderboard_scores", {"repo_id": "gpt2"})
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# search_models
# ---------------------------------------------------------------------------

class TestSearchModels:
    def test_returns_model_list(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_models", {
            "task": "text-generation",
            "limit": 3,
        })
        assert result.success
        assert result.data["result_count"] == 3
        assert len(result.data["models"]) == 3
        assert result.data["task"] == "text-generation"

    def test_model_fields_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_models", {
            "task": "text-classification",
            "limit": 1,
        })
        assert result.success
        model = result.data["models"][0]
        for field in ("repo_id", "task", "downloads", "library", "license", "gated"):
            assert field in model, f"missing field: {field}"

    def test_default_sort_is_downloads(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_models", {})
        assert result.success
        assert result.data["sort"] == "downloads"

    def test_filter_tag_accepted(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_models", {
            "filter": "gguf",
            "limit": 2,
        })
        assert result.success

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.search_models", {"limit": 1})
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# model_card
# ---------------------------------------------------------------------------

class TestModelCard:
    def test_returns_metadata(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.model_card", {
            "repo_id": "bert-base-uncased",
        })
        assert result.success
        assert result.data["repo_id"] == "bert-base-uncased"
        assert result.data["author"] == "fake-org"
        assert result.data["pipeline_tag"] == "text-generation"

    def test_license_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.model_card", {
            "repo_id": "gpt2",
        })
        assert result.success
        assert result.data["license"] is not None

    def test_gated_flag_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.model_card", {
            "repo_id": "meta-llama/Llama-3.2-1B",
        })
        assert result.success
        assert isinstance(result.data["gated"], bool)

    def test_tags_is_list(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.model_card", {
            "repo_id": "distilbert-base-uncased",
        })
        assert result.success
        assert isinstance(result.data["tags"], list)

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.model_card", {
            "repo_id": "gpt2",
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# pull_for_local_llm
# ---------------------------------------------------------------------------

class TestPullForLocalLlm:
    def test_returns_gguf_path(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.pull_for_local_llm", {
            "repo_id": "TheBloke/Llama-2-7B-GGUF",
        })
        assert result.success
        assert result.data["repo_id"] == "TheBloke/Llama-2-7B-GGUF"
        assert len(result.data["gguf_files"]) >= 1
        assert result.data["recommended_path"] is not None
        assert result.data["recommended_path"].endswith(".gguf")

    def test_specific_filename(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.pull_for_local_llm", {
            "repo_id": "TheBloke/Llama-2-7B-GGUF",
            "filename": "llama-2-7b.Q4_K_M.gguf",
        })
        assert result.success
        assert result.data["file_count"] == 1
        assert "llama-2-7b.Q4_K_M.gguf" in result.data["recommended_path"]

    def test_remote_downloads_disabled_raises(self):
        store = SQLiteEvidenceStore(":memory:")
        host = LocalCapabilityHost(store=store)
        config = HuggingFaceConfig(_backend=FakeHFBackend(), allow_remote_downloads=False)
        register_adapter(host, HuggingFaceAdapter(config))
        result = _invoke(host, "chp.adapters.huggingface.pull_for_local_llm", {
            "repo_id": "TheBloke/Llama-2-7B-GGUF",
        })
        assert not result.success

    def test_size_bytes_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.pull_for_local_llm", {
            "repo_id": "TheBloke/Llama-2-7B-GGUF",
        })
        assert result.success
        assert result.data["size_bytes"] > 0

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.pull_for_local_llm", {
            "repo_id": "TheBloke/Llama-2-7B-GGUF",
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------

class TestEvaluate:
    def test_accuracy_metric(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.evaluate", {
            "metric": "accuracy",
            "predictions": [1, 0, 1, 1, 0],
            "references": [1, 0, 1, 0, 0],
        })
        assert result.success
        assert result.data["metric"] == "accuracy"
        assert "scores" in result.data
        assert "accuracy" in result.data["scores"]
        assert result.data["sample_count"] == 5

    def test_bleu_metric(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.evaluate", {
            "metric": "bleu",
            "predictions": ["the cat sat"],
            "references": ["the cat sat on the mat"],
        })
        assert result.success
        assert "bleu" in result.data["scores"]

    def test_predictions_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.evaluate", {
            "metric": "accuracy",
            "predictions": [1, 0],
            "references": [1, 1],
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            p = evt.get("payload", {})
            assert "predictions" not in p
            assert "references" not in p

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.evaluate", {
            "metric": "f1",
            "predictions": [1, 0],
            "references": [1, 0],
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# apply_adapter
# ---------------------------------------------------------------------------

class TestApplyAdapter:
    def test_returns_adapter_path(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.apply_adapter", {
            "base_model": "meta-llama/Llama-3.2-1B",
            "adapter_repo_id": "org/my-lora-adapter",
        })
        assert result.success
        assert "adapter_path" in result.data
        assert result.data["peft_type"] == "LORA"
        assert result.data["base_model_name"] == "meta-llama/Llama-3.2-1B"

    def test_target_modules_and_rank_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.apply_adapter", {
            "base_model": "meta-llama/Llama-3.2-1B",
            "adapter_repo_id": "org/my-lora-adapter",
        })
        assert result.success
        assert isinstance(result.data["target_modules"], list)
        assert result.data["r"] == 16
        assert result.data["lora_alpha"] == 32

    def test_requested_base_model_echoed(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.apply_adapter", {
            "base_model": "gpt2",
            "adapter_repo_id": "org/gpt2-lora",
        })
        assert result.success
        assert result.data["requested_base_model"] == "gpt2"

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.apply_adapter", {
            "base_model": "gpt2",
            "adapter_repo_id": "org/gpt2-lora",
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# call_space
# ---------------------------------------------------------------------------

class TestCallSpace:
    def test_returns_result(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.call_space", {
            "space_id": "stabilityai/stable-diffusion",
            "api_name": "/predict",
            "inputs": "a cat",
        })
        assert result.success
        assert result.data["space_id"] == "stabilityai/stable-diffusion"
        assert "result" in result.data

    def test_inputs_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.call_space", {
            "space_id": "test/space",
            "inputs": "SECRET_INPUT_XYZ",
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            assert "inputs" not in evt.get("payload", {})
            assert "SECRET_INPUT_XYZ" not in str(evt.get("payload", {}))

    def test_default_api_name_is_predict(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.call_space", {
            "space_id": "test/space",
            "inputs": "hello",
        })
        assert result.success
        assert result.data["api_name"] == "/predict"

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.call_space", {
            "space_id": "test/space",
            "inputs": "hello",
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# finetune
# ---------------------------------------------------------------------------

class TestFinetune:
    def test_returns_output_dir(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.finetune", {
            "model": "distilbert-base-uncased",
            "dataset_repo_id": "imdb",
            "output_dir": "/tmp/ft-output",
        })
        assert result.success
        assert result.data["output_dir"] == "/tmp/ft-output"
        assert result.data["model"] == "distilbert-base-uncased"
        assert "final_loss" in result.data
        assert "steps" in result.data

    def test_training_content_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.finetune", {
            "model": "distilbert-base-uncased",
            "dataset_repo_id": "imdb",
            "output_dir": "/tmp/ft-output",
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            p = evt.get("payload", {})
            assert "weights" not in p
            assert "training_data" not in p

    def test_max_steps_override(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.finetune", {
            "model": "distilbert-base-uncased",
            "dataset_repo_id": "imdb",
            "output_dir": "/tmp/ft-output",
            "max_steps": 50,
        })
        assert result.success
        assert result.data["steps"] == 50

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.finetune", {
            "model": "distilbert-base-uncased",
            "dataset_repo_id": "imdb",
            "output_dir": "/tmp/ft-output",
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# quantize_to_gguf
# ---------------------------------------------------------------------------

class TestQuantizeToGguf:
    def test_returns_output_path(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.quantize_to_gguf", {
            "model_path": "/tmp/llama-3-1b",
            "output_path": "/tmp/llama-3-1b-Q4_K_M.gguf",
        })
        assert result.success
        assert result.data["output_path"] == "/tmp/llama-3-1b-Q4_K_M.gguf"
        assert result.data["quantization"] == "Q4_K_M"

    def test_custom_quantization(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.quantize_to_gguf", {
            "model_path": "/tmp/model",
            "output_path": "/tmp/model.Q8_0.gguf",
            "quantization": "Q8_0",
        })
        assert result.success
        assert result.data["quantization"] == "Q8_0"

    def test_size_metadata_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.quantize_to_gguf", {
            "model_path": "/tmp/model",
            "output_path": "/tmp/model.gguf",
        })
        assert result.success
        assert "input_size_bytes" in result.data
        assert "output_size_bytes" in result.data
        assert result.data["output_size_bytes"] < result.data["input_size_bytes"]

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.quantize_to_gguf", {
            "model_path": "/tmp/model",
            "output_path": "/tmp/model.gguf",
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# faiss_index
# ---------------------------------------------------------------------------

class TestFaissIndex:
    def test_build_returns_index_info(self):
        embeddings = [[0.1, 0.2, 0.3, 0.4], [0.5, 0.6, 0.7, 0.8], [0.9, 0.1, 0.2, 0.3]]
        result = _invoke(_make_host(), "chp.adapters.huggingface.faiss_index", {
            "operation": "build",
            "index_path": "/tmp/test.index",
            "embeddings": embeddings,
        })
        assert result.success
        assert result.data["index_path"] == "/tmp/test.index"
        assert result.data["vector_count"] == 3

    def test_search_returns_indices_and_scores(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.faiss_index", {
            "operation": "search",
            "index_path": "/tmp/test.index",
            "query": [0.1, 0.2, 0.3, 0.4],
            "top_k": 3,
        })
        assert result.success
        assert "indices" in result.data
        assert "scores" in result.data
        assert result.data["top_k"] == 3

    def test_vectors_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.faiss_index", {
            "operation": "build",
            "index_path": "/tmp/test.index",
            "embeddings": [[1.0, 2.0], [3.0, 4.0]],
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            p = evt.get("payload", {})
            assert "embeddings" not in p
            assert "query" not in p

    def test_default_top_k_is_5(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.faiss_index", {
            "operation": "search",
            "index_path": "/tmp/test.index",
            "query": [1.0, 2.0, 3.0],
        })
        assert result.success
        assert result.data["top_k"] == 5

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.faiss_index", {
            "operation": "build",
            "index_path": "/tmp/test.index",
            "embeddings": [[1.0, 2.0]],
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# transcribe_audio
# ---------------------------------------------------------------------------

class TestTranscribeAudio:
    def test_returns_text(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.transcribe_audio", {
            "audio_path": "/tmp/sample.wav",
        })
        assert result.success
        assert result.data["text"] == "the quick brown fox"
        assert result.data["segment_count"] == 2
        assert result.data["char_count"] == len("the quick brown fox")

    def test_transcript_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.transcribe_audio", {
            "audio_path": "/tmp/secret.wav",
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            p = evt.get("payload", {})
            assert "text" not in p
            assert "the quick brown fox" not in str(p)

    def test_language_passthrough(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.transcribe_audio", {
            "audio_path": "/tmp/s.wav", "language": "english",
        })
        assert result.success
        assert result.data["language"] == "english"

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.transcribe_audio", {"audio_path": "/tmp/s.wav"})
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# classify_image
# ---------------------------------------------------------------------------

class TestClassifyImage:
    def test_returns_predictions(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.classify_image", {
            "image_path": "/tmp/cat.jpg", "top_k": 3,
        })
        assert result.success
        assert result.data["prediction_count"] == 3
        assert "label" in result.data["predictions"][0]
        assert "score" in result.data["predictions"][0]

    def test_predictions_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.classify_image", {"image_path": "/tmp/cat.jpg"})
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            p = evt.get("payload", {})
            assert "predictions" not in p

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.classify_image", {"image_path": "/tmp/x.jpg"})
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# generate_image
# ---------------------------------------------------------------------------

class TestGenerateImage:
    def test_returns_output_path(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.generate_image", {
            "prompt": "a serene mountain lake", "output_path": "/tmp/out.png", "seed": 42,
        })
        assert result.success
        assert result.data["output_path"] == "/tmp/out.png"
        assert result.data["width"] == 512
        assert result.data["seed"] == 42

    def test_prompt_not_in_evidence(self):
        host = _make_host()
        result = _invoke(host, "chp.adapters.huggingface.generate_image", {
            "prompt": "SECRET_PROMPT_IMG_77", "output_path": "/tmp/out.png",
        })
        assert result.success
        replay = host.replay(result.invocation_id)
        for evt in replay:
            blob = str(evt.get("payload", {}))
            assert "SECRET_PROMPT_IMG_77" not in blob
            assert "prompt" not in evt.get("payload", {})

    def test_latency_present(self):
        result = _invoke(_make_host(), "chp.adapters.huggingface.generate_image", {
            "prompt": "x", "output_path": "/tmp/o.png",
        })
        assert result.data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# Model/pipeline cache (warm-model reuse)
# ---------------------------------------------------------------------------

class TestPipelineCache:
    def test_same_key_builds_once(self):
        from chp_adapter_huggingface._backends import _RealHFBackend
        be = _RealHFBackend()
        calls = []

        def factory():
            calls.append(1)
            return object()

        a = be._cached(("pipeline", "x", "m", "cpu", ""), factory)
        b = be._cached(("pipeline", "x", "m", "cpu", ""), factory)
        assert a is b  # reused, not rebuilt
        assert len(calls) == 1

    def test_distinct_keys_build_separately(self):
        from chp_adapter_huggingface._backends import _RealHFBackend
        be = _RealHFBackend()
        a = be._cached(("k1",), object)
        b = be._cached(("k2",), object)
        assert a is not b

    def test_lru_eviction_bounded(self):
        from chp_adapter_huggingface._backends import _RealHFBackend, _MAX_CACHED_MODELS
        be = _RealHFBackend()
        for i in range(_MAX_CACHED_MODELS + 2):
            be._cached((i,), object)
        assert len(be._model_cache) == _MAX_CACHED_MODELS
        assert (0,) not in be._model_cache  # oldest evicted
        assert (_MAX_CACHED_MODELS + 1,) in be._model_cache  # newest retained


# ---------------------------------------------------------------------------
# Conformance
# ---------------------------------------------------------------------------

class TestConformance:
    def test_adapter_has_no_violations(self):
        from chp_adapter_conformance import check_source_file
        import chp_adapter_huggingface.adapter as mod
        import inspect

        src_path = inspect.getfile(mod)
        violations = check_source_file(src_path)
        assert not violations, f"HuggingFaceAdapter has conformance violations: {violations}"
