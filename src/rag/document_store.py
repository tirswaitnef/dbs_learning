"""Episode 03: document retrieval only, without LLM calls or remediation approval."""
import hashlib
import json
import os
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from .chunker import chunk_documents, fit_document_chunks
from .embeddings import E5Embedding, embed_query_safe
from .loader import load_documents
from .schemas import digest


def corpus_digest(documents):
    return digest([asdict(doc) for doc in documents])


def normalize_rows(vectors):
    matrix = np.asarray(vectors, dtype=np.float32)
    if matrix.ndim != 2 or not all(matrix.shape) or not np.isfinite(matrix).all():
        raise ValueError("Vectors must be a nonempty finite 2D matrix")
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    if not np.isfinite(norms).all() or np.any(norms == 0):
        raise ValueError("Cannot normalize zero/invalid vectors")
    return np.asarray(matrix / norms, dtype=np.float32)


class DocumentVectorStore:
    def __init__(self, vectors, metadata):
        self.vectors = np.asarray(vectors)
        self.metadata = metadata
        chunks = metadata.get("chunks")
        if (metadata.get("format") != "document-v1" or not isinstance(chunks, list)
                or not chunks or self.vectors.dtype != np.float32
                or self.vectors.ndim != 2 or self.vectors.shape[0] != len(chunks)
                or self.vectors.shape[1] != metadata.get("dimensions")
                or not np.isfinite(self.vectors).all()):
            raise ValueError("Invalid document vector store")
        if not np.allclose(np.linalg.norm(self.vectors, axis=1), 1, atol=1e-5):
            raise ValueError("Stored vectors must be normalized")
        if digest(chunks) != metadata.get("chunks_sha256"):
            raise ValueError("Chunk metadata changed; re-ingest")
        for c in chunks:
            if (not isinstance(c.get("text"), str) or not c["text"]
                    or not isinstance(c.get("source"), str) or not c["source"]
                    or not isinstance(c.get("metadata"), dict)
                    or type(c.get("index")) is not int or c["index"] < 0
                    or type(c.get("start")) is not int or c["start"] < 0
                    or type(c.get("end")) is not int
                    or c["end"] - c["start"] != len(c["text"])):
                raise ValueError("Invalid chunk provenance")

    def save(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        # Publish each file atomically; checksum catches an interrupted pair update.
        fd, temp_name = tempfile.mkstemp(dir=directory, suffix=".npz")
        os.close(fd)
        tmp = Path(temp_name)
        try:
            np.savez_compressed(tmp, vectors=self.vectors)
            metadata = {**self.metadata, "vectors_sha256": hashlib.sha256(tmp.read_bytes()).hexdigest()}
            os.replace(tmp, directory / "vector_store.npz")
            fd, temp_name = tempfile.mkstemp(dir=directory, suffix=".json")
            os.close(fd)
            tmp = Path(temp_name)
            tmp.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.replace(tmp, directory / "vector_store.meta.json")
            self.metadata = metadata
        finally:
            tmp.unlink(missing_ok=True)

    @classmethod
    def load(cls, directory, settings):
        directory = Path(directory)
        metadata = json.loads((directory / "vector_store.meta.json").read_text(encoding="utf-8"))
        if (metadata.get("model") != settings.embed_model
                or metadata.get("revision") != settings.embed_revision
                or metadata.get("prefixes") != {"document": "passage: ", "query": "query: "}
                or metadata.get("chunk_size") != settings.chunk_size
                or metadata.get("chunk_overlap") != settings.chunk_overlap):
            raise ValueError("Model/chunk configuration differs from store; re-ingest")
        vector_path = directory / "vector_store.npz"
        if hashlib.sha256(vector_path.read_bytes()).hexdigest() != metadata.get("vectors_sha256"):
            raise ValueError("Vector/metadata checksum mismatch; re-ingest")
        with np.load(vector_path, allow_pickle=False) as saved:
            vectors = saved["vectors"].copy()
        return cls(vectors, metadata)

    def verify_corpus(self, raw_directory):
        current = load_documents(raw_directory)
        if corpus_digest(current.documents) != self.metadata["corpus_sha256"]:
            raise ValueError("Raw documents/metadata changed since ingest; re-ingest")

    def search(self, query_vector, *, top_k=4, min_score=None):
        if type(top_k) is not int or top_k < 1:
            raise ValueError("top_k must be a positive integer")
        if min_score is not None and not -1 <= min_score <= 1:
            raise ValueError("min_score must be in [-1, 1]")
        q = np.asarray(query_vector, dtype=np.float32)
        if q.ndim != 1 or len(q) != self.vectors.shape[1]:
            raise ValueError("Query and document dimensions differ")
        q = normalize_rows(q[None, :])[0]
        scores = self.vectors @ q
        order = np.argsort(-scores, kind="stable")[:top_k]
        return [{**self.metadata["chunks"][int(i)], "score": float(scores[i])}
                for i in order if min_score is None or scores[i] >= min_score]


def ingest_documents(raw_directory, output_directory, settings, *, embedder=None, offline=False):
    if Path(output_directory).resolve().is_relative_to(Path(raw_directory).resolve()):
        raise ValueError("Vector output must be outside the raw directory")
    result = load_documents(raw_directory)
    chunks = chunk_documents(result.documents, settings.chunk_size, settings.chunk_overlap)
    if not chunks:
        raise ValueError("No nonempty supported documents to embed")
    encoder = embedder or E5Embedding(settings.embed_model, settings.embed_revision,
                                      local_files_only=offline)
    chunks = fit_document_chunks(result.documents, chunks, encoder, settings.chunk_overlap)
    if not chunks:
        raise ValueError("No nonempty supported documents to embed")
    vectors = normalize_rows(encoder.embed_documents([c.text for c in chunks]))
    metadata = {"format": "document-v1", "model": settings.embed_model,
                "revision": settings.embed_revision, "dimensions": vectors.shape[1],
                "dtype": "float32", "created_at": datetime.now(timezone.utc).isoformat(),
                "prefixes": {"document": "passage: ", "query": "query: "},
                "chunk_size": settings.chunk_size, "chunk_overlap": settings.chunk_overlap,
                "corpus_sha256": corpus_digest(result.documents),
                "chunks": [asdict(c) for c in chunks],
                "document_count": len(result.documents), "skipped": result.skipped,
                "purpose": "retrieval-only; source correctness/approval not established"}
    metadata["chunks_sha256"] = digest(metadata["chunks"])
    store = DocumentVectorStore(vectors, metadata)
    store.save(output_directory)
    return store


def retrieve_documents(question, directory, raw_directory, settings, *, top_k=None,
                       min_score=None, offline=False, embedder=None):
    if not isinstance(question, str) or not question.strip():
        raise ValueError("Question must be nonempty")
    store = DocumentVectorStore.load(directory, settings)
    store.verify_corpus(raw_directory)
    encoder = embedder or E5Embedding(settings.embed_model, settings.embed_revision,
                                      local_files_only=offline)
    vector = embed_query_safe(encoder, question, overlap=settings.chunk_overlap)
    return store.search(vector, top_k=settings.top_k if top_k is None else top_k,
                        min_score=min_score)
