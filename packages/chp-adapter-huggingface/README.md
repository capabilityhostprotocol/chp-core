# chp-adapter-huggingface

Local consumption of HuggingFace Hub artifacts: pull models/datasets, run transformers pipelines, embed text, tokenize, and audit local cache.

## Capabilities

| Capability | Risk | Description |
|---|---|---|
| `pull` | medium | Download any HuggingFace Hub artifact (model, dataset, tokenizer) to local cache via snapshot_download. |
| `run_pipeline` | medium | Run a transformers.pipeline() task on a locally-cached model. Inputs and outputs are never recorded in evidenc |
| `embed` | medium | Generate text embeddings using a locally-cached feature-extraction model. Vectors are returned but never store |
| `tokenize` | low | Encode text to token IDs or decode token IDs to text using a fast HuggingFace tokenizer. No full model load re |
| `load_dataset` | medium | Load rows from a HuggingFace dataset (Hub or local). Streaming=true reads without downloading the full dataset |
| `cache_info` | low | Scan the local HuggingFace cache and return a storage summary by artifact for governance and quota management. |
| `search_models` | low | Search HuggingFace Hub for models by task, sort, and filter. Enables agents to discover models programmaticall |
| `model_card` | low | Fetch structured model metadata from HuggingFace Hub: license, pipeline task, tags, gated status, author, and  |
| `pull_for_local_llm` | medium | Pull GGUF model files from HuggingFace Hub and return the local path ready to pass directly to chp.adapters.lo |
| `search_datasets` | low | Search HuggingFace Hub for datasets by task, sort, and filter. Symmetric to search_models — enables agents to  |
| `search_spaces` | low | Search HuggingFace Hub for Spaces (Gradio/Streamlit apps) by SDK, sort, and filter. Precondition for call_spac |
| `list_collections` | low | List HuggingFace Hub Collections — curated groupings of models and datasets. Enables agents to navigate themat |
| `dataset_preview` | low | Preview the schema and first N rows of a HuggingFace dataset via the Dataset Viewer API — no download required |
| `leaderboard_scores` | low | Fetch evaluation benchmark scores for a model from HuggingFace Hub (MMLU, ARC, TruthfulQA, etc.). Evidence-bac |
| `evaluate` | low | Compute evaluation metrics (BLEU, ROUGE, accuracy, F1, exact_match) against ground-truth references. Quality g |
| `apply_adapter` | medium | Download a LoRA/PEFT adapter from HuggingFace Hub and inspect its configuration. Returns the local adapter pat |
| `call_space` | medium | Invoke any HuggingFace Gradio Space as a governed CHP capability via gradio_client. Space ID, api_name, and la |
| `finetune` | high | Fine-tune a HuggingFace classification model locally using transformers.Trainer. Governance: model, dataset, h |
| `quantize_to_gguf` | medium | Convert a local HuggingFace model directory to quantized GGUF using llama.cpp tools. Two-step: convert_hf_to_g |
| `faiss_index` | low | Build or search a FAISS cosine-similarity index for RAG pipelines. 'build': creates IndexFlatIP from float emb |
| `transcribe_audio` | medium | Transcribe an audio file to text using a Whisper ASR pipeline. Input is a local file path (e.g. from the files |
| `classify_image` | low | Classify an image with a ViT/DeiT image-classification pipeline. Input is a local image path. Top-N labels and |
| `generate_image` | medium | Generate an image from a text prompt via a diffusers DiffusionPipeline (Stable Diffusion, etc.) and save it to |

## Notes

Every capability is governed (risk-assessed via `safety.assess`) and evidenced (redacted: counts/ids, never payloads). Mutating ops may require approval.

_README generated deterministically from the adapter's `@capability` metadata (`stewards/gen_readme.py`); refine the prose as needed._
