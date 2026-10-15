from copy import deepcopy

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
