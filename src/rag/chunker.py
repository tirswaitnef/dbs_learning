from copy import deepcopy

from .embeddings import split_spans_for_encoder
from .schemas import Chunk


def split_text(text, size=800, overlap=120):
    if not 0 <= overlap < size:
        raise ValueError("Require 0 <= overlap < size")
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        yield text[start:end]
        if end == len(text):
            break
        start = end - overlap


def chunk_cards(cards, size=800, overlap=120):
    # Each card is one reviewed section. Never merge unrelated OWASP sections.
    return [{"id": f"{c.id}:{i}", "card_id": c.id, "text": text}
            for c in cards if c.approved
            for i, text in enumerate(split_text(c.text(), size, overlap))]


def chunk_documents(documents, size=800, overlap=120):
    """Offsets refer to extracted Python text: start inclusive, end exclusive.

    They are not byte offsets or PDF page numbers. Document boundaries are kept.
    """
    if not 0 <= overlap < size:
        raise ValueError("Require 0 <= overlap < size")
    chunks = []
    for doc in documents:
        for index, text in enumerate(split_text(doc.text, size, overlap)):
            start = index * (size - overlap)
            chunks.append(Chunk(doc.source, index, start, start + len(text), text,
                                doc.source_sha256, deepcopy(doc.metadata)))
    return chunks


def fit_document_chunks(documents, chunks, encoder, overlap=120):
    """Sub-split any chunk whose subword tokens exceed encoder.model.max_seq_length."""
    by_source = {doc.source: doc.text for doc in documents}
    fitted = []
    next_index = {}
    for chunk in chunks:
        full_text = by_source[chunk.source]
        spans = split_spans_for_encoder(full_text, chunk.start, chunk.end, encoder,
                                        overlap=overlap, query=False)
        for s, e in spans:
            idx = next_index.get(chunk.source, 0)
            next_index[chunk.source] = idx + 1
            fitted.append(Chunk(chunk.source, idx, s, e, full_text[s:e],
                                chunk.source_sha256, deepcopy(chunk.metadata)))
    return fitted


def fit_card_chunks(chunks, encoder, overlap=120):
    fitted = []
    per_card = {}
    for item in chunks:
        text = item["text"]
        spans = split_spans_for_encoder(text, 0, len(text), encoder,
                                        overlap=overlap, query=False)
        for s, e in spans:
            cid = item["card_id"]
            idx = per_card.get(cid, 0)
            per_card[cid] = idx + 1
            fitted.append({"id": f"{cid}:{idx}", "card_id": cid, "text": text[s:e]})
    return fitted
