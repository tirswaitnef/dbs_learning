"""Inspect retrieved OWASP guidance; not an unrestricted chatbot."""
import argparse
from _bootstrap import ROOT
from rag.config import load_settings
from rag.loader import load_cards
from rag.parsers import normalize_cwe
from rag.retriever import retrieve
from rag.schemas import Finding
from rag.vector_store import VectorStore

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Inspect E5 retrieval by question and CWE")
    p.add_argument("question")
    p.add_argument("--cwe", required=True)
    args = p.parse_args()
    try:
        settings = load_settings()
        cards = load_cards(ROOT / "data/raw/owasp/cards.json")
        store = VectorStore(ROOT / "data/processed/e5", cards, settings)
        # Query intent only, never persisted as a finding or claimed test evidence.
        query = Finding("query", args.question, normalize_cwe(args.cwe), "unknown", "unknown",
                        ("retrieval-only",), "user-query", "not-a-scan")
        matches = retrieve(query, cards, store=store, top_k=settings.top_k, min_score=settings.min_score)
        by_id = {c.id: c for c in cards}
        if not matches:
            print("Chưa tìm thấy hướng dẫn phù hợp trong kho hiện tại.")
        for match in matches:
            c = by_id[match["card_id"]]
            print(f"{c.id} — score={match['score']:.4f}\n{c.guidance_vi}\n{c.applicability_vi}\n{c.url}\n")
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        p.exit(1, f"Retrieval failed: {exc}\n")
