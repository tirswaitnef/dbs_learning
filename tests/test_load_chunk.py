import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from rag.chunker import chunk_documents
from rag.loader import load_documents
from rag.schemas import Document


class LoadChunkTests(unittest.TestCase):
    def test_recursive_relative_sources_empty_and_unsupported(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "nested").mkdir()
            (root / "same.md").write_text("first", encoding="utf-8")
            (root / "nested/same.md").write_text("second", encoding="utf-8")
            (root / "empty.txt").write_text(" \n ", encoding="utf-8")
            (root / "image.png").write_bytes(b"dummy")
            (root / "extra.markdown").write_text("third", encoding="utf-8-sig")
            result = load_documents(root)
            self.assertEqual([x.source for x in result.documents], ["extra.markdown", "nested/same.md", "same.md"])
            self.assertEqual(len(result.skipped), 2)
            self.assertEqual(result.documents[0].text, "third")

    def test_tutorial_lengths_and_offsets(self):
        docs = [Document("one.md", "a" * 1291), Document("two.md", "b" * 1530)]
        chunks = chunk_documents(docs)
        self.assertEqual([len(c.text) for c in chunks], [800, 611, 800, 800, 170])
        self.assertEqual([(c.start, c.end) for c in chunks[:2]], [(0, 800), (680, 1291)])
        for c in chunks:
            doc = next(d for d in docs if d.source == c.source)
            self.assertEqual(c.text, doc.text[c.start:c.end])

    def test_metadata_and_hash_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.md").write_text("Tiếng Việt " * 100, encoding="utf-8")
            meta = {"url": "https://owasp.org/", "section": "example", "approved": False}
            (root / "a.md.meta.json").write_text(json.dumps(meta), encoding="utf-8")
            result = load_documents(root)
            chunks = chunk_documents(result.documents)
            self.assertEqual(chunks[0].metadata, meta)
            self.assertEqual(len(chunks[0].source_sha256), 64)
            self.assertEqual(chunks[0].text[-120:], chunks[1].text[:120])
            chunks[0].metadata["section"] = "changed"
            self.assertEqual(chunks[1].metadata["section"], "example")

    def test_invalid_settings_even_for_empty_corpus(self):
        for size, overlap in [(0, 0), (800, -1), (800, 800), (-1, 0)]:
            with self.subTest(size=size, overlap=overlap), self.assertRaises(ValueError):
                chunk_documents([], size, overlap)

    def test_exact_boundary_no_extra_chunk(self):
        self.assertEqual(len(chunk_documents([Document("a", "x" * 800)])), 1)
        self.assertEqual(len(chunk_documents([Document("a", "x" * 1480)])), 2)

    def test_no_text_pdf_skipped_and_corrupt_file_fails(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "test.pdf").write_bytes(b"fixture")
            with patch("rag.loader.load_document", return_value=""):
                result = load_documents(d)
                self.assertEqual(result.documents, [])
                self.assertIn("OCR", result.skipped[0]["reason"])
            with patch("rag.loader.load_document", side_effect=ValueError("corrupt")):
                with self.assertRaisesRegex(ValueError, "Cannot read test.pdf"):
                    load_documents(d)

    def test_malformed_metadata_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.txt").write_text("hello", encoding="utf-8")
            (root / "a.txt.meta.json").write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Metadata must be an object"):
                load_documents(root)


if __name__ == "__main__":
    unittest.main()
