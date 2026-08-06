"""hf.finetune causal-LM QLoRA — the gated decision logic + task_type dispatch.

Real QLoRA training needs CUDA + trl/peft/bitsandbytes and is proven on a GPU node; here we pin the
pure plan (the 4-bit/CUDA gate + LoRA defaults/overrides) and that finetune routes by task_type."""
from __future__ import annotations

import pytest

from chp_adapter_huggingface._backends import _RealHFBackend, _qlora_plan


def test_qlora_4bit_requires_cuda():
    with pytest.raises(RuntimeError, match="CUDA"):
        _qlora_plan({"load_in_4bit": True}, cuda_available=False)   # fail closed, don't silently downgrade


def test_qlora_defaults_on_cuda():
    p = _qlora_plan({}, cuda_available=True)
    assert p["load_in_4bit"] is True
    assert (p["lora_r"], p["lora_alpha"], p["lora_dropout"], p["max_seq_len"]) == (16, 32, 0.05, 1024)


def test_qlora_plain_lora_allowed_off_gpu_and_overrides():
    p = _qlora_plan({"load_in_4bit": False, "lora_r": 8, "max_seq_len": 512, "text_field": "chat"},
                    cuda_available=False)
    assert p["load_in_4bit"] is False and p["lora_r"] == 8   # plain LoRA needs no CUDA
    assert p["max_seq_len"] == 512 and p["text_field"] == "chat"


def test_finetune_dispatches_by_task_type(monkeypatch):
    b = _RealHFBackend()
    calls = []
    monkeypatch.setattr(b, "_finetune_causal_lm", lambda *a, **k: calls.append("causal") or {})
    monkeypatch.setattr(b, "_finetune_classification", lambda *a, **k: calls.append("cls") or {})
    b.finetune("m", "d", "/o", "causal-lm", 1, 1, 1e-4, 10, "", "", {"lora_r": 8})
    b.finetune("m", "d", "/o", "text-classification", 1, 1, 1e-4, 10, "", "")
    assert calls == ["causal", "cls"]


def test_inline_dataset_flows_to_causal_lm(monkeypatch):
    """Inline records (mesh facts) reach the causal-lm path via options — no Hub dataset needed."""
    b = _RealHFBackend()
    seen = {}
    monkeypatch.setattr(b, "_finetune_causal_lm",
                        lambda *a, **k: seen.update(options=a[-1]) or {})
    b.finetune("m", "", "/o", "causal-lm", 1, 1, 1e-4, 10, "", "", {"dataset": [{"text": "mesh fact"}]})
    assert seen["options"]["dataset"] == [{"text": "mesh fact"}]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
