"""huggingface.rerank: cross-encoder scores → results sorted by relevance desc, with top_k."""
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore
from chp_adapter_huggingface import HuggingFaceAdapter, HuggingFaceConfig
from test_hf_adapter import FakeHFBackend


def _host():
    h = LocalCapabilityHost(store=SQLiteEvidenceStore(":memory:"))
    register_adapter(h, HuggingFaceAdapter(HuggingFaceConfig(_backend=FakeHFBackend())))
    return h


def test_rerank_sorts_by_relevance_and_topk():
    docs = ["invoke a CLI command",              # 0 overlap with "search models"
            "search HuggingFace for models",     # 2 overlap → best
            "list the models on a node"]         # 1 overlap ("models")
    r = _host().invoke("chp.adapters.huggingface.rerank",
                       {"query": "search models", "documents": docs, "top_k": 2})
    assert r.outcome == "success"
    res = r.data["results"]
    assert len(res) == 2                          # top_k honored
    assert res[0]["index"] == 1                   # most-relevant doc first
    assert res[0]["score"] >= res[1]["score"]     # sorted desc
