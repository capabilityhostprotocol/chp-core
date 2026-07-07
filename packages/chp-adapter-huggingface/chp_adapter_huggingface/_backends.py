"""HuggingFace backend — ALL library imports isolated here.

adapter.py never imports from huggingface_hub, transformers, datasets, or tokenizers
directly. This file is the only place those libraries are touched, keeping the adapter
conformance-checker-clean and making tests possible without installing any HF libraries.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from typing import Any, Protocol, runtime_checkable

# Bounded number of warm pipelines/tokenizers kept resident per backend instance.
_MAX_CACHED_MODELS = 4


# ---------------------------------------------------------------------------
# Protocol — what adapter.py depends on
# ---------------------------------------------------------------------------

@runtime_checkable
class HFBackend(Protocol):
    def pull(
        self,
        repo_id: str,
        repo_type: str,
        revision: str | None,
        allow_patterns: list[str] | None,
        token: str,
        cache_dir: str,
    ) -> dict: ...

    def run_pipeline(
        self,
        model: str,
        task: str,
        inputs: Any,
        device: str,
        cache_dir: str,
        **kwargs: Any,
    ) -> Any: ...

    def embed(
        self,
        model: str,
        texts: list[str],
        pooling: str,
        device: str,
        cache_dir: str,
    ) -> list[list[float]]: ...

    def tokenize(
        self,
        model: str,
        operation: str,
        texts: list[str] | None,
        ids: list[list[int]] | None,
        cache_dir: str,
    ) -> dict: ...

    def load_dataset(
        self,
        repo_id: str,
        split: str,
        streaming: bool,
        limit: int,
        columns: list[str] | None,
        token: str,
        cache_dir: str,
    ) -> dict: ...

    def cache_info(self, cache_dir: str) -> dict: ...

    def search_models(
        self,
        task: str | None,
        sort: str,
        limit: int,
        filter_tag: str | None,
        token: str,
    ) -> list[dict]: ...

    def model_card(
        self,
        repo_id: str,
        token: str,
    ) -> dict: ...

    def pull_for_local_llm(
        self,
        repo_id: str,
        filename: str | None,
        token: str,
        cache_dir: str,
    ) -> dict: ...

    def search_datasets(
        self,
        task: str | None,
        sort: str,
        limit: int,
        filter_tag: str | None,
        token: str,
    ) -> list[dict]: ...

    def search_spaces(
        self,
        sdk: str | None,
        sort: str,
        limit: int,
        filter_tag: str | None,
        token: str,
    ) -> list[dict]: ...

    def list_collections(
        self,
        owner: str | None,
        limit: int,
        token: str,
    ) -> list[dict]: ...

    def dataset_preview(
        self,
        repo_id: str,
        split: str,
        config: str | None,
        limit: int,
        token: str,
    ) -> dict: ...

    def leaderboard_scores(
        self,
        repo_id: str,
        token: str,
    ) -> dict: ...

    def evaluate_metric(
        self,
        metric: str,
        predictions: list,
        references: list,
        kwargs: dict | None,
    ) -> dict: ...

    def apply_adapter(
        self,
        base_model: str,
        adapter_repo_id: str,
        cache_dir: str,
        token: str,
    ) -> dict: ...

    def call_space(
        self,
        space_id: str,
        api_name: str,
        inputs: Any,
        token: str,
    ) -> Any: ...

    def finetune(
        self,
        model: str,
        dataset_repo_id: str,
        output_dir: str,
        task_type: str,
        num_epochs: int,
        batch_size: int,
        learning_rate: float,
        max_steps: int | None,
        cache_dir: str,
        token: str,
    ) -> dict: ...

    def quantize_to_gguf(
        self,
        model_path: str,
        output_path: str,
        quantization: str,
        convert_script: str | None,
        quantize_bin: str | None,
    ) -> dict: ...

    def faiss_index(
        self,
        operation: str,
        embeddings: list | None,
        index_path: str,
        query: list | None,
        top_k: int,
        dimension: int | None,
    ) -> dict: ...

    def transcribe_audio(
        self,
        audio_path: str,
        model: str,
        language: str | None,
        device: str,
        cache_dir: str,
    ) -> dict: ...

    def classify_image(
        self,
        image_path: str,
        model: str,
        top_k: int,
        device: str,
        cache_dir: str,
    ) -> dict: ...

    def generate_image(
        self,
        prompt: str,
        model: str,
        num_inference_steps: int,
        guidance_scale: float,
        seed: int | None,
        output_path: str,
        device: str,
        cache_dir: str,
    ) -> dict: ...


# ---------------------------------------------------------------------------
# Real backend — lazy-imports all HF libraries
# ---------------------------------------------------------------------------

class _RealHFBackend:
    """Wraps huggingface_hub, transformers, datasets, tokenizers.

    Loaded pipelines/tokenizers are cached (bounded LRU) on the backend
    instance — which lives for the host's lifetime — so repeated calls reuse a
    warm model instead of reloading it from disk every invocation.
    """

    def __init__(self) -> None:
        self._model_cache: "OrderedDict[tuple, Any]" = OrderedDict()
        self._cache_lock = threading.Lock()

    def _cached(self, key: tuple, factory: Any) -> Any:
        """Return a cached object for ``key`` or build it via ``factory`` (LRU-bounded).

        The (slow) factory runs outside the lock so loading one model does not
        block cache hits for other models; a rare concurrent double-load of the
        same key is harmless (last write wins).
        """
        with self._cache_lock:
            obj = self._model_cache.get(key)
            if obj is not None:
                self._model_cache.move_to_end(key)
                return obj
        obj = factory()
        with self._cache_lock:
            self._model_cache[key] = obj
            self._model_cache.move_to_end(key)
            while len(self._model_cache) > _MAX_CACHED_MODELS:
                self._model_cache.popitem(last=False)
        return obj

    def pull(
        self,
        repo_id: str,
        repo_type: str,
        revision: str | None,
        allow_patterns: list[str] | None,
        token: str,
        cache_dir: str,
    ) -> dict:
        from huggingface_hub import snapshot_download

        local_path = snapshot_download(
            repo_id=repo_id,
            repo_type=repo_type,
            revision=revision or None,
            allow_patterns=allow_patterns or None,
            token=token or None,
            cache_dir=cache_dir or None,
        )

        # Gather stats from the downloaded directory
        file_count = 0
        size_bytes = 0
        for root, _dirs, files in os.walk(local_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    size_bytes += os.path.getsize(fpath)
                    file_count += 1
                except OSError:
                    pass

        return {
            "cache_path": local_path,
            "file_count": file_count,
            "size_bytes": size_bytes,
        }

    def run_pipeline(
        self,
        model: str,
        task: str,
        inputs: Any,
        device: str,
        cache_dir: str,
        **kwargs: Any,
    ) -> Any:
        _device = _resolve_device(device)
        pipe = self._cached(
            ("pipeline", task, model, device, cache_dir),
            lambda: _make_pipeline(task, model, _device, cache_dir),
        )
        return pipe(inputs, **kwargs)

    def embed(
        self,
        model: str,
        texts: list[str],
        pooling: str,
        device: str,
        cache_dir: str,
    ) -> list[list[float]]:
        _device = _resolve_device(device)
        pipe = self._cached(
            ("pipeline", "feature-extraction", model, device, cache_dir),
            lambda: _make_pipeline("feature-extraction", model, _device, cache_dir),
        )
        raw = pipe(texts)

        vectors: list[list[float]] = []
        for item in raw:
            # item shape: (seq_len, hidden) — pool over sequence dimension
            token_vecs = item[0]  # (seq_len, hidden)
            if pooling == "cls":
                vec = token_vecs[0]
            else:  # mean
                n = len(token_vecs)
                vec = [sum(token_vecs[i][j] for i in range(n)) / n for j in range(len(token_vecs[0]))]
            vectors.append([float(v) for v in vec])

        return vectors

    def tokenize(
        self,
        model: str,
        operation: str,
        texts: list[str] | None,
        ids: list[list[int]] | None,
        cache_dir: str,
    ) -> dict:
        tokenizer = self._cached(
            ("tokenizer", model, cache_dir),
            lambda: _make_tokenizer(model, cache_dir),
        )

        if operation == "decode":
            if not ids:
                return {"decoded": [], "text_count": 0}
            decoded = [tokenizer.decode(seq, skip_special_tokens=True) for seq in ids]
            return {"decoded": decoded, "text_count": len(decoded)}

        # encode
        if not texts:
            return {"encoded": [], "token_counts": [], "total_tokens": 0}
        encoded = tokenizer(texts, add_special_tokens=True)
        input_ids: list[list[int]] = encoded["input_ids"]
        token_counts = [len(seq) for seq in input_ids]
        return {
            "encoded": input_ids,
            "token_counts": token_counts,
            "total_tokens": sum(token_counts),
        }

    def load_dataset(
        self,
        repo_id: str,
        split: str,
        streaming: bool,
        limit: int,
        columns: list[str] | None,
        token: str,
        cache_dir: str,
    ) -> dict:
        from datasets import load_dataset as hf_load_dataset

        ds = hf_load_dataset(
            repo_id,
            split=split,
            streaming=streaming,
            token=token or None,
            cache_dir=cache_dir or None,
        )

        rows: list[dict] = []
        for i, row in enumerate(ds):
            if i >= limit:
                break
            if columns:
                row = {k: v for k, v in row.items() if k in columns}
            rows.append(row)

        all_columns = columns or (list(rows[0].keys()) if rows else [])
        return {
            "rows": rows,
            "row_count": len(rows),
            "columns": all_columns,
        }

    def cache_info(self, cache_dir: str) -> dict:
        from huggingface_hub import scan_cache_dir

        info = scan_cache_dir(cache_dir or None)

        repos = []
        for repo in info.repos:
            revisions = [
                {
                    "commit_hash": rev.commit_hash,
                    "size_bytes": rev.size_on_disk,
                    "nb_files": rev.nb_files,
                }
                for rev in repo.revisions
            ]
            repos.append({
                "repo_id": repo.repo_id,
                "repo_type": repo.repo_type,
                "size_bytes": repo.size_on_disk,
                "nb_files": repo.nb_files,
                "last_accessed": repo.last_accessed,
                "revisions": revisions,
            })

        return {
            "repos": repos,
            "repo_count": len(repos),
            "total_size_bytes": info.size_on_disk,
            "revision_count": sum(len(r["revisions"]) for r in repos),
        }


    def search_datasets(
        self,
        task: str | None,
        sort: str,
        limit: int,
        filter_tag: str | None,
        token: str,
    ) -> list[dict]:
        from huggingface_hub import HfApi

        api = HfApi(token=token or None)
        datasets = list(api.list_datasets(
            filter=filter_tag or None,
            task_categories=task or None,
            sort=sort,
            limit=limit,
            full=True,
        ))

        results = []
        for d in datasets:
            tags = d.tags or []
            license_tag = next((t for t in tags if t.startswith("license:")), None)
            results.append({
                "repo_id": d.id,
                "task_categories": getattr(d, "task_categories", []) or [],
                "downloads": getattr(d, "downloads", 0) or 0,
                "likes": getattr(d, "likes", 0) or 0,
                "license": license_tag,
                "gated": bool(getattr(d, "gated", False)),
            })
        return results

    def search_spaces(
        self,
        sdk: str | None,
        sort: str,
        limit: int,
        filter_tag: str | None,
        token: str,
    ) -> list[dict]:
        from huggingface_hub import HfApi

        api = HfApi(token=token or None)
        # fetch more than needed to allow client-side sdk filtering
        fetch_limit = limit * 3 if sdk else limit
        spaces_raw = list(api.list_spaces(
            filter=filter_tag or None,
            sort=sort,
            limit=fetch_limit,
            full=True,
        ))
        if sdk:
            spaces_raw = [s for s in spaces_raw if getattr(s, "sdk", None) == sdk]
        spaces = spaces_raw[:limit]

        results = []
        for s in spaces:
            tags = getattr(s, "tags", []) or []
            results.append({
                "repo_id": s.id,
                "sdk": getattr(s, "sdk", None),
                "likes": getattr(s, "likes", 0) or 0,
                "author": getattr(s, "author", None),
                "tags": tags[:10],
            })
        return results

    def list_collections(
        self,
        owner: str | None,
        limit: int,
        token: str,
    ) -> list[dict]:
        from huggingface_hub import HfApi

        api = HfApi(token=token or None)
        collections = list(api.list_collections(
            owner=owner or None,
            limit=limit,
        ))

        results = []
        for c in collections:
            owner_val = getattr(c, "owner", None)
            owner_name = owner_val.get("name", str(owner_val)) if isinstance(owner_val, dict) else str(owner_val or "")
            results.append({
                "slug": c.slug,
                "title": c.title,
                "description": getattr(c, "description", None),
                "upvotes": getattr(c, "upvotes", 0) or 0,
                "item_count": len(getattr(c, "items", []) or []),
                "owner": owner_name,
            })
        return results

    def dataset_preview(
        self,
        repo_id: str,
        split: str,
        config: str | None,
        limit: int,
        token: str,
    ) -> dict:
        from datasets import load_dataset_builder
        from datasets import load_dataset as hf_load_dataset

        # Schema without downloading data
        builder = load_dataset_builder(repo_id, config or None, token=token or None)
        features = builder.info.features
        columns = list(features.keys()) if features else []

        # First rows via streaming — no full download
        ds = hf_load_dataset(
            repo_id,
            config or None,
            split=split,
            streaming=True,
            token=token or None,
        )
        rows: list[dict] = []
        for row in ds:
            if len(rows) >= limit:
                break
            rows.append(row)

        return {
            "rows": rows,
            "row_count": len(rows),
            "columns": columns,
            "split": split,
            "config": config,
        }

    def leaderboard_scores(
        self,
        repo_id: str,
        token: str,
    ) -> dict:
        from huggingface_hub import HfApi

        api = HfApi(token=token or None)
        info = api.model_info(repo_id=repo_id)

        # eval_results may be on card_data or directly on the model info object
        raw_evals = (
            getattr(info, "eval_results", None)
            or (info.card_data.eval_results if info.card_data else None)
            or []
        )
        eval_results = []
        for er in (raw_evals or []):
            eval_results.append({
                "task_type": getattr(er, "task_type", None),
                "dataset_name": getattr(er, "dataset_name", None),
                "dataset_type": getattr(er, "dataset_type", None),
                "metric_name": getattr(er, "metric_name", None),
                "metric_type": getattr(er, "metric_type", None),
                "metric_value": getattr(er, "metric_value", None),
            })

        return {
            "repo_id": info.id,
            "eval_results": eval_results,
            "result_count": len(eval_results),
        }

    def evaluate_metric(
        self,
        metric: str,
        predictions: list,
        references: list,
        kwargs: dict | None,
    ) -> dict:
        import evaluate as hf_evaluate

        m = hf_evaluate.load(metric)
        scores = m.compute(predictions=predictions, references=references, **(kwargs or {}))
        return {"metric": metric, "scores": scores}

    def apply_adapter(
        self,
        base_model: str,
        adapter_repo_id: str,
        cache_dir: str,
        token: str,
    ) -> dict:
        from peft import PeftConfig
        from huggingface_hub import snapshot_download

        adapter_path = snapshot_download(
            repo_id=adapter_repo_id,
            token=token or None,
            cache_dir=cache_dir or None,
        )
        config = PeftConfig.from_pretrained(adapter_path)
        target_mods: list[str] = []
        tm = getattr(config, "target_modules", None)
        if tm:
            target_mods = sorted(tm) if isinstance(tm, (set, list)) else [str(tm)]
        return {
            "adapter_path": adapter_path,
            "peft_type": str(config.peft_type),
            "base_model_name": config.base_model_name_or_path,
            "requested_base_model": base_model,
            "target_modules": target_mods,
            "r": getattr(config, "r", None),
            "lora_alpha": getattr(config, "lora_alpha", None),
        }

    def call_space(
        self,
        space_id: str,
        api_name: str,
        inputs: Any,
        token: str,
    ) -> Any:
        from gradio_client import Client

        client = Client(space_id, hf_token=token or None)
        if isinstance(inputs, list):
            result = client.predict(*inputs, api_name=api_name)
        else:
            result = client.predict(inputs, api_name=api_name)
        return result

    def finetune(
        self,
        model: str,
        dataset_repo_id: str,
        output_dir: str,
        task_type: str,
        num_epochs: int,
        batch_size: int,
        learning_rate: float,
        max_steps: int | None,
        cache_dir: str,
        token: str,
    ) -> dict:
        from transformers import (
            AutoTokenizer,
            AutoModelForSequenceClassification,
            TrainingArguments,
            Trainer,
        )
        from datasets import load_dataset as hf_load_dataset

        ds = hf_load_dataset(dataset_repo_id, token=token or None, cache_dir=cache_dir or None)
        tokenizer = AutoTokenizer.from_pretrained(model, cache_dir=cache_dir or None)

        label_feat = ds["train"].features.get("label")
        num_labels = label_feat.num_classes if hasattr(label_feat, "num_classes") else 2

        model_obj = AutoModelForSequenceClassification.from_pretrained(
            model, num_labels=num_labels, cache_dir=cache_dir or None
        )

        _text_cols = [c for c in ("text", "sentence", "content", "document") if c in ds["train"].features]
        text_col = _text_cols[0] if _text_cols else list(ds["train"].features.keys())[0]

        def _tokenize(examples: dict) -> dict:
            return tokenizer(examples[text_col], truncation=True, padding="max_length", max_length=128)

        tokenized = ds.map(_tokenize, batched=True)

        args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=num_epochs,
            per_device_train_batch_size=batch_size,
            learning_rate=learning_rate,
            max_steps=max_steps or -1,
            report_to="none",
            push_to_hub=False,
        )

        eval_ds = tokenized.get("validation") or tokenized.get("test")
        trainer = Trainer(
            model=model_obj,
            args=args,
            train_dataset=tokenized["train"],
            eval_dataset=eval_ds,
        )

        train_result = trainer.train()
        trainer.save_model(output_dir)

        return {
            "output_dir": output_dir,
            "model": model,
            "dataset": dataset_repo_id,
            "task_type": task_type,
            "final_loss": round(train_result.training_loss, 6),
            "steps": train_result.global_step,
        }

    def quantize_to_gguf(
        self,
        model_path: str,
        output_path: str,
        quantization: str,
        convert_script: str | None,
        quantize_bin: str | None,
    ) -> dict:
        import subprocess
        import tempfile

        conv_script = convert_script or "/opt/homebrew/bin/convert_hf_to_gguf.py"
        quant_bin = quantize_bin or "/opt/homebrew/bin/llama-quantize"

        if not os.path.exists(conv_script):
            raise FileNotFoundError(f"convert_hf_to_gguf.py not found at {conv_script}")
        if not os.path.exists(quant_bin):
            raise FileNotFoundError(f"llama-quantize not found at {quant_bin}")

        tmp_fd, tmp_gguf = tempfile.mkstemp(suffix=".gguf")
        os.close(tmp_fd)
        try:
            conv = subprocess.run(
                ["python3", conv_script, model_path, "--outtype", "f16", "--outfile", tmp_gguf],
                capture_output=True, text=True, timeout=3600,
            )
            if conv.returncode != 0:
                raise RuntimeError(f"GGUF conversion failed: {conv.stderr[:1000]}")

            quant = subprocess.run(
                [quant_bin, tmp_gguf, output_path, quantization],
                capture_output=True, text=True, timeout=3600,
            )
            if quant.returncode != 0:
                raise RuntimeError(f"Quantization failed: {quant.stderr[:1000]}")

            input_size = os.path.getsize(tmp_gguf) if os.path.exists(tmp_gguf) else 0
            output_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0

            return {
                "output_path": output_path,
                "quantization": quantization,
                "input_size_bytes": input_size,
                "output_size_bytes": output_size,
            }
        finally:
            if os.path.exists(tmp_gguf):
                os.unlink(tmp_gguf)

    def faiss_index(
        self,
        operation: str,
        embeddings: list | None,
        index_path: str,
        query: list | None,
        top_k: int,
        dimension: int | None,
    ) -> dict:
        import faiss
        import numpy as np

        if operation == "build":
            if not embeddings:
                raise ValueError("embeddings required for build operation")
            vectors = np.array(embeddings, dtype=np.float32)
            dim = int(vectors.shape[1])
            faiss.normalize_L2(vectors)
            index = faiss.IndexFlatIP(dim)
            index.add(vectors)
            faiss.write_index(index, index_path)
            return {
                "index_path": index_path,
                "vector_count": int(index.ntotal),
                "dimension": dim,
            }
        elif operation == "search":
            if query is None:
                raise ValueError("query required for search operation")
            index = faiss.read_index(index_path)
            q = np.array([query], dtype=np.float32)
            faiss.normalize_L2(q)
            scores, indices = index.search(q, top_k)
            return {
                "indices": indices[0].tolist(),
                "scores": scores[0].tolist(),
                "top_k": top_k,
            }
        else:
            raise ValueError(f"Unknown faiss_index operation: {operation!r}. Use 'build' or 'search'.")

    def search_models(
        self,
        task: str | None,
        sort: str,
        limit: int,
        filter_tag: str | None,
        token: str,
    ) -> list[dict]:
        from huggingface_hub import HfApi

        api = HfApi(token=token or None)
        # HfApi.list_models uses `pipeline_tag` for the task (not `task=`, which it rejects).
        models = list(api.list_models(
            filter=filter_tag or None,
            pipeline_tag=task or None,
            sort=sort,
            limit=limit,
            full=True,
        ))

        results = []
        for m in models:
            tags = m.tags or []
            license_tag = next((t for t in tags if t.startswith("license:")), None)
            results.append({
                "repo_id": m.id,
                "task": getattr(m, "pipeline_tag", None),
                "downloads": getattr(m, "downloads", 0) or 0,
                "library": getattr(m, "library_name", None),
                "license": license_tag,
                "gated": bool(getattr(m, "gated", False)),
            })
        return results

    def model_card(
        self,
        repo_id: str,
        token: str,
    ) -> dict:
        from huggingface_hub import HfApi

        api = HfApi(token=token or None)
        info = api.model_info(repo_id=repo_id)
        tags = info.tags or []
        license_tag = next((t for t in tags if t.startswith("license:")), None)
        return {
            "repo_id": info.id,
            "author": info.author,
            "license": license_tag,
            "pipeline_tag": info.pipeline_tag,
            "tags": tags,
            "gated": bool(getattr(info, "gated", False)),
            "likes": getattr(info, "likes", None),
            "downloads": getattr(info, "downloads", None),
            "created_at": str(info.created_at) if getattr(info, "created_at", None) else None,
            "last_modified": str(info.last_modified) if getattr(info, "last_modified", None) else None,
            "sha": getattr(info, "sha", None),
        }

    def pull_for_local_llm(
        self,
        repo_id: str,
        filename: str | None,
        token: str,
        cache_dir: str,
    ) -> dict:
        import glob
        from huggingface_hub import hf_hub_download, snapshot_download

        if filename:
            local_path = hf_hub_download(
                repo_id=repo_id,
                filename=filename,
                token=token or None,
                cache_dir=cache_dir or None,
            )
            size_bytes = os.path.getsize(local_path) if os.path.exists(local_path) else 0
            return {
                "cache_path": os.path.dirname(local_path),
                "gguf_files": [local_path],
                "recommended_path": local_path,
                "file_count": 1,
                "size_bytes": size_bytes,
            }

        local_path = snapshot_download(
            repo_id=repo_id,
            allow_patterns=["*.gguf", "*.json"],
            token=token or None,
            cache_dir=cache_dir or None,
        )

        gguf_files = sorted(glob.glob(os.path.join(local_path, "**", "*.gguf"), recursive=True))
        size_bytes = sum(os.path.getsize(f) for f in gguf_files if os.path.exists(f))

        return {
            "cache_path": local_path,
            "gguf_files": gguf_files,
            "recommended_path": gguf_files[0] if gguf_files else None,
            "file_count": len(gguf_files),
            "size_bytes": size_bytes,
        }


    def transcribe_audio(
        self,
        audio_path: str,
        model: str,
        language: str | None,
        device: str,
        cache_dir: str,
    ) -> dict:
        pipe = self._cached(
            ("pipeline", "automatic-speech-recognition", model, device, cache_dir),
            lambda: _make_pipeline("automatic-speech-recognition", model, _resolve_device(device), cache_dir),
        )
        kwargs: dict[str, Any] = {"return_timestamps": True}
        if language:
            kwargs["generate_kwargs"] = {"language": language}
        result = pipe(audio_path, **kwargs)

        text = result.get("text", "") if isinstance(result, dict) else str(result)
        chunks = result.get("chunks", []) if isinstance(result, dict) else []
        detected_language = language
        return {
            "text": text,
            "language": detected_language,
            "segment_count": len(chunks),
            "char_count": len(text),
        }

    def classify_image(
        self,
        image_path: str,
        model: str,
        top_k: int,
        device: str,
        cache_dir: str,
    ) -> dict:
        pipe = self._cached(
            ("pipeline", "image-classification", model, device, cache_dir),
            lambda: _make_pipeline("image-classification", model, _resolve_device(device), cache_dir),
        )
        raw = pipe(image_path, top_k=top_k)
        predictions = [
            {"label": r.get("label"), "score": float(r.get("score", 0.0))}
            for r in (raw or [])
        ]
        return {"predictions": predictions, "prediction_count": len(predictions)}

    def generate_image(
        self,
        prompt: str,
        model: str,
        num_inference_steps: int,
        guidance_scale: float,
        seed: int | None,
        output_path: str,
        device: str,
        cache_dir: str,
    ) -> dict:
        import torch
        from diffusers import DiffusionPipeline

        pipe = DiffusionPipeline.from_pretrained(model, cache_dir=cache_dir or None)
        dev = _resolve_diffusers_device(device)
        pipe = pipe.to(dev)

        generator = None
        if seed is not None:
            generator = torch.Generator(device=dev).manual_seed(seed)

        image = pipe(
            prompt,
            num_inference_steps=num_inference_steps,
            guidance_scale=guidance_scale,
            generator=generator,
        ).images[0]
        image.save(output_path)

        return {
            "output_path": output_path,
            "width": image.width,
            "height": image.height,
            "steps": num_inference_steps,
            "seed": seed,
        }


def _resolve_diffusers_device(device: str) -> str:
    """Map a device string to a diffusers .to() target."""
    if device in ("mps", "cpu") or device.startswith("cuda"):
        return device
    # auto
    try:
        import torch
        if torch.backends.mps.is_available():
            return "mps"
        if torch.cuda.is_available():
            return "cuda"
    except ImportError:
        pass
    return "cpu"


def _resolve_device(device: str) -> int | str:
    """Map device string to transformers-accepted value."""
    if device == "cpu":
        return -1
    if device == "mps":
        return "mps"
    if device.startswith("cuda"):
        parts = device.split(":")
        return int(parts[1]) if len(parts) > 1 else 0
    if device == "auto":
        try:
            import torch
            if torch.backends.mps.is_available():
                return "mps"
            if torch.cuda.is_available():
                return 0
        except ImportError:
            pass
        return -1
    return -1


def _make_pipeline(task: str, model: str, device: Any, cache_dir: str) -> Any:
    """Build a transformers pipeline (factory for the warm-model cache)."""
    from transformers import pipeline

    return pipeline(
        task,
        model=model,
        device=device,
        model_kwargs={"cache_dir": cache_dir or None} if cache_dir else {},
    )


def _make_tokenizer(model: str, cache_dir: str) -> Any:
    """Build a fast tokenizer (factory for the warm-model cache)."""
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(model, cache_dir=cache_dir or None)


def make_backend() -> _RealHFBackend:
    return _RealHFBackend()
