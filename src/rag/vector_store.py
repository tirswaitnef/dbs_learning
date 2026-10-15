import json
from pathlib import Path

from .chunker import chunk_cards
from .embeddings import E5Embedding
from .schemas import card_digest


def build_store(cards, settings, destination):
    import numpy as np
    chunks = chunk_cards(cards, settings.chunk_size, settings.chunk_overlap)
    if not chunks:
        raise ValueError("No approved knowledge cards")
    encoder = E5Embedding(settings.embed_model, settings.embed_revision)
    matrix = encoder.encode([c["text"] for c in chunks])
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    np.save(destination / "vectors.npy", matrix, allow_pickle=False)
    manifest = {"format": 1, "model": settings.embed_model,
                "revision": settings.embed_revision, "cards_sha256": card_digest(cards),
                "chunk_size": settings.chunk_size, "overlap": settings.chunk_overlap,
                "chunks": chunks}
    (destination / "index.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(chunks)


class VectorStore:
    def __init__(self, path, cards, settings):
        import numpy as np
        path = Path(path)
        self.meta = json.loads((path / "index.json").read_text(encoding="utf-8"))
        if (self.meta["format"] != 1 or self.meta["cards_sha256"] != card_digest(cards)
                or self.meta["model"] != settings.embed_model
                or self.meta["revision"] != settings.embed_revision
                or self.meta["chunk_size"] != settings.chunk_size
                or self.meta["overlap"] != settings.chunk_overlap):
            raise ValueError("Index/config/knowledge mismatch. Run ingest again.")
        self.vectors = np.load(path / "vectors.npy", allow_pickle=False)
        if (self.vectors.ndim != 2 or len(self.vectors) != len(self.meta["chunks"])
                or not np.isfinite(self.vectors).all()):
            raise ValueError("Invalid vector matrix; run ingest again")
        self.encoder = E5Embedding(settings.embed_model, settings.embed_revision)

    def scores(self, query):
        vector = self.encoder.encode([query], query=True)[0]
        return [(c["card_id"], float(score)) for c, score in
                zip(self.meta["chunks"], self.vectors @ vector)]
