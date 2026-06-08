"""Tests for vector retrieval capabilities."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core.retrieval import (
    InMemoryVectorRetrievalCapability,
    SQLiteVectorRetrievalCapability,
    _cosine,
)


# Minimal deterministic "embedding": bag-of-words over a 5-word vocabulary.
VOCAB = ["cat", "dog", "car", "sun", "moon"]


def fake_embed(text: str) -> list[float]:
    words = text.lower().split()
    return [float(words.count(w)) for w in VOCAB]


DOCS = [
    {"source_id": "d1", "content": "cat cat dog", "title": "Pets"},
    {"source_id": "d2", "content": "car car car", "title": "Vehicles"},
    {"source_id": "d3", "content": "sun moon sun", "title": "Sky"},
]


class CosineHelperTests(unittest.TestCase):
    def test_identical_vectors(self) -> None:
        v = [1.0, 2.0, 3.0]
        self.assertAlmostEqual(_cosine(v, v), 1.0)

    def test_orthogonal_vectors(self) -> None:
        self.assertAlmostEqual(_cosine([1.0, 0.0], [0.0, 1.0]), 0.0)

    def test_zero_vector_returns_zero(self) -> None:
        self.assertEqual(_cosine([0.0, 0.0], [1.0, 2.0]), 0.0)
        self.assertEqual(_cosine([1.0, 2.0], [0.0, 0.0]), 0.0)

    def test_opposite_vectors(self) -> None:
        self.assertAlmostEqual(_cosine([1.0, 0.0], [-1.0, 0.0]), -1.0)


class InMemoryVectorRetrievalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cap = InMemoryVectorRetrievalCapability(fake_embed, DOCS)

    def test_retrieve_returns_correct_top_result(self) -> None:
        result = self.cap.retrieve("cat dog", top_k=1)
        self.assertEqual(result.result_count, 1)
        self.assertEqual(result.source_refs[0].source_id, "d1")

    def test_retrieval_type_is_vector(self) -> None:
        result = self.cap.retrieve("car", top_k=3)
        self.assertEqual(result.retrieval_type, "vector")

    def test_top_k_limits_results(self) -> None:
        result = self.cap.retrieve("cat dog car sun moon", top_k=2)
        self.assertLessEqual(result.result_count, 2)

    def test_no_match_returns_empty(self) -> None:
        cap = InMemoryVectorRetrievalCapability(fake_embed, [])
        result = cap.retrieve("cat", top_k=5)
        self.assertEqual(result.result_count, 0)

    def test_ingest_live_adds_document(self) -> None:
        cap = InMemoryVectorRetrievalCapability(fake_embed, [])
        cap.ingest({"source_id": "d4", "content": "cat cat cat", "title": "Many Cats"})
        result = cap.retrieve("cat", top_k=1)
        self.assertEqual(result.source_refs[0].source_id, "d4")

    def test_scores_are_in_descending_order(self) -> None:
        result = self.cap.retrieve("cat dog car sun moon", top_k=3)
        scores = [r.score for r in result.source_refs]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_source_ref_has_title(self) -> None:
        result = self.cap.retrieve("car", top_k=1)
        self.assertEqual(result.source_refs[0].title, "Vehicles")

    def test_empty_documents_at_init(self) -> None:
        cap = InMemoryVectorRetrievalCapability(fake_embed)
        result = cap.retrieve("cat", top_k=5)
        self.assertEqual(result.result_count, 0)


class SQLiteVectorRetrievalTests(unittest.TestCase):
    def _make_cap(self, path: str) -> SQLiteVectorRetrievalCapability:
        return SQLiteVectorRetrievalCapability(path, fake_embed)

    def test_retrieve_from_pre_embedded_docs(self) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            cap = self._make_cap(path)
            cap.embed_and_store("d1", "cat cat dog")
            cap.embed_and_store("d2", "car car car")
            result = cap.retrieve("cat", top_k=1)
            self.assertEqual(result.source_refs[0].source_id, "d1")
            cap.close()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_retrieval_type_is_vector(self) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            cap = self._make_cap(path)
            cap.embed_and_store("d1", "cat cat")
            result = cap.retrieve("cat", top_k=1)
            self.assertEqual(result.retrieval_type, "vector")
            cap.close()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_persistence_across_reopen(self) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            cap1 = self._make_cap(path)
            cap1.embed_and_store("d1", "sun moon sun")
            cap1.embed_and_store("d2", "cat cat dog")
            cap1.close()

            cap2 = self._make_cap(path)
            result = cap2.retrieve("sun moon", top_k=1)
            self.assertEqual(result.source_refs[0].source_id, "d1")
            cap2.close()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_no_embed_fn_raises(self) -> None:
        with self.assertRaises(ValueError):
            SQLiteVectorRetrievalCapability(":memory:", None)  # type: ignore[arg-type]

    def test_empty_store_returns_no_results(self) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            cap = self._make_cap(path)
            result = cap.retrieve("cat", top_k=5)
            self.assertEqual(result.result_count, 0)
            cap.close()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_shared_file_with_sqlite_ingestion(self) -> None:
        """SQLiteVectorRetrievalCapability reads documents written by SQLiteIngestionCapability."""
        import tempfile
        from chp_core.ingestion import SQLiteIngestionCapability

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            ing = SQLiteIngestionCapability(path)
            ing.ingest("car car car", source_id="shared-1", content_type="text/plain")
            ing.close()

            cap = self._make_cap(path)
            cap.embed_and_store("shared-1", "car car car")
            result = cap.retrieve("car", top_k=1)
            self.assertEqual(result.source_refs[0].source_id, "shared-1")
            cap.close()
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
