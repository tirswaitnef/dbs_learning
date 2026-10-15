import importlib.util
import json
import sys
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from rag.config import Settings
from rag.embeddings import E5Embedding

HAS_NUMPY = importlib.util.find_spec("numpy") is not None
if HAS_NUMPY:
    import numpy as np
    from rag.document_store import DocumentVectorStore, ingest_documents, normalize_rows, retrieve_documents


class StubEncoder:
    """Known numerical vectors for tests. NOT semantic embeddings or an E5 substitute."""
    def embed_documents(self, texts):
        return np.array([[3, 0, 0] if "alpha" in t else [0, 4, 0] for t in texts], dtype=np.float32)

    def embed_query(self, question):
        return np.array([1, 0, 0], dtype=np.float32)


@unittest.skipUnless(HAS_NUMPY, "Install numpy for numeric store tests")
class DocumentStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.raw = self.root / "raw"
        self.raw.mkdir()
        (self.raw / "a.md").write_text("alpha source", encoding="utf-8")
        (self.raw / "b.md").write_text("beta source", encoding="utf-8")
        self.output = self.root / "store"
        self.settings = Settings(embed_model="test-only-encoder")
        self.store = ingest_documents(self.raw, self.output, self.settings, embedder=StubEncoder())

    def test_roundtrip_float32_and_source_ranking(self):
        saved = DocumentVectorStore.load(self.output, self.settings)
        self.assertEqual(saved.vectors.dtype, np.float32)
        self.assertEqual(saved.vectors.shape, (2, 3))
        results = saved.search(np.array([5, 0, 0]), top_k=10)
        self.assertEqual([r["source"] for r in results], ["a.md", "b.md"])
        self.assertAlmostEqual(results[0]["score"], 1)
        self.assertAlmostEqual(results[1]["score"], 0)
        self.assertEqual(results[0]["text"], "alpha source")

    def test_complete_ingest_query_without_reembedding_documents(self):
        class QueryOnly:
            def embed_query(self, question):
                return np.array([0, 1, 0])
            def embed_documents(self, texts):
                raise AssertionError("Queries must not re-embed documents")
        result = retrieve_documents("test", self.output, self.raw, self.settings,
                                    embedder=QueryOnly(), top_k=1)
        self.assertEqual(result[0]["source"], "b.md")

    def test_raw_and_sidecar_changes_require_reingest(self):
        (self.raw / "a.md.meta.json").write_text('{"title":"new"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed since ingest"):
            self.store.verify_corpus(self.raw)
        (self.raw / "a.md.meta.json").unlink()
        (self.raw / "a.md").write_text("changed", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.verify_corpus(self.raw)

    def test_model_and_chunk_configuration_mismatch_rejected(self):
        for settings in [replace(self.settings, embed_model="other"),
                         replace(self.settings, embed_revision="new"),
                         replace(self.settings, chunk_size=900)]:
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                DocumentVectorStore.load(self.output, settings)

    def test_vector_and_metadata_corruption_rejected(self):
        vector_path = self.output / "vector_store.npz"
        original = vector_path.read_bytes()
        vector_path.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "checksum"):
            DocumentVectorStore.load(self.output, self.settings)
        vector_path.write_bytes(original)
        meta_path = self.output / "vector_store.meta.json"
        metadata = json.loads(meta_path.read_text())
        metadata["chunks"][0]["source"] = "wrong-source.md"
        meta_path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, "metadata changed"):
            DocumentVectorStore.load(self.output, self.settings)

    def test_invalid_vectors_and_queries_rejected(self):
        for vectors in [[[0, 0]], [[float("nan"), 1]], [], [1, 2]]:
            with self.subTest(vectors=vectors), self.assertRaises(ValueError):
                normalize_rows(vectors)
        for query in [[1, 0], [0, 0, 0], [float("inf"), 0, 0]]:
            with self.subTest(query=query), self.assertRaises(ValueError):
                self.store.search(query)

    def test_threshold_topk_and_ties(self):
        self.assertEqual(len(self.store.search([1, 0, 0], top_k=2, min_score=0.5)), 1)
        self.assertEqual(self.store.search([-1, 0, 0], min_score=0.5), [])
        tied = self.store.search([1, 1, 0], top_k=2)
        self.assertEqual([r["source"] for r in tied], ["a.md", "b.md"])
        with self.assertRaises(ValueError):
            self.store.search([1, 0, 0], top_k=0)

    def test_no_documents_and_output_inside_raw_rejected(self):
        with self.assertRaises(ValueError):
            ingest_documents(self.raw, self.raw / "store", self.settings, embedder=StubEncoder())
        for path in self.raw.iterdir():
            path.unlink()
        with self.assertRaisesRegex(ValueError, "No nonempty"):
            ingest_documents(self.raw, self.output, self.settings, embedder=StubEncoder())

    def test_e5_roles_cpu_cache_and_float32(self):
        calls = {}
        class FakeModel:
            max_seq_length = 512
            def __init__(self, name, **kwargs):
                calls["init"] = kwargs
            def tokenizer(self, text, **kwargs):
                return {"input_ids": list(range(len(text)))}
            def encode(self, inputs, **kwargs):
                calls["inputs"] = inputs
                calls["encode"] = kwargs
                return np.array([[1, 0, 0] for _ in inputs], dtype=np.float64)
        fake_module = types.ModuleType("sentence_transformers")
        fake_module.SentenceTransformer = FakeModel
        with patch.dict(sys.modules, {"sentence_transformers": fake_module}):
            encoder = E5Embedding("fake", "revision", local_files_only=True)
            self.assertEqual(encoder.embed_documents(["hello"]).dtype, np.float32)
            self.assertEqual(calls["inputs"], ["passage: hello"])
            self.assertEqual(calls["encode"]["prompt"], "")
            encoder.embed_query("question")
            self.assertEqual(calls["inputs"], ["query: question"])
            self.assertEqual(calls["init"]["device"], "cpu")
            self.assertTrue(calls["init"]["local_files_only"])
            with self.assertRaisesRegex(ValueError, "exceeds"):
                encoder.embed_documents(["a" * 513])
            with self.assertRaises(ValueError):
                encoder.embed_query("")


if __name__ == "__main__":
    unittest.main()
