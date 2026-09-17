"""hf.finetune grpo — the reward bridge (the RLVR crux).

The training backend is pure (no ctx); the adapter builds a reward_fn that marshals each completion
into a governed CHP reward cap via run_coroutine_threadsafe. Here a real host runs finetune(task_type=
'grpo') with a tiny verify cap standing in for chp.adapters.eval.verify — proving the adapter builds
the callback, threads it to ctx.ainvoke, passes the per-prompt reference through, and returns one score
per completion aligned to the batch. FakeHFBackend.finetune calls reward_fn the way GRPOTrainer would.
"""
from __future__ import annotations

import asyncio

from chp_core import BaseAdapter, LocalCapabilityHost, capability, register_adapter
from chp_core.store import SQLiteEvidenceStore

from chp_adapter_huggingface import HuggingFaceAdapter, HuggingFaceConfig

from test_hf_adapter import FakeHFBackend


class _FakeVerifyAdapter(BaseAdapter):
    adapter_id = "chp.adapters.eval"

    @capability(id="chp.adapters.eval.verify", version="1.0.0",
                description="test reward: 1.0 iff output == reference", category="ai", risk="low")
    async def verify(self, ctx, payload):   # noqa: ANN001
        return {"score": 1.0 if payload["output"] == payload.get("reference") else 0.0}


def _host() -> LocalCapabilityHost:
    host = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(host, HuggingFaceAdapter(HuggingFaceConfig(_backend=FakeHFBackend())))
    register_adapter(host, _FakeVerifyAdapter())
    return host


def test_grpo_reward_bridges_to_verify_cap():
    host = _host()
    res = asyncio.get_event_loop().run_until_complete(host.ainvoke(
        "chp.adapters.huggingface.finetune",
        {"model": "Qwen/Qwen3-0.6B", "output_dir": "/tmp/o", "task_type": "grpo",
         "dataset": [{"prompt": "q", "reference": "good answer"}]},
    ))
    assert res.success, res
    # FakeHFBackend scored ["good answer", "bad answer"] against reference "good answer"
    assert res.data["rewards"] == [1.0, 0.0]   # reward reached the cap, reference passed, order kept


if __name__ == "__main__":
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
