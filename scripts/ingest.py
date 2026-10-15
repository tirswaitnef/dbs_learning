import argparse
from _bootstrap import ROOT
from rag.config import load_settings
from rag.loader import load_cards
from rag.vector_store import build_store

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Chunk reviewed OWASP cards and build E5 index")
    p.add_argument("--cards", default=ROOT / "data/raw/owasp/cards.json")
    p.add_argument("--output", default=ROOT / "data/processed/e5")
    args = p.parse_args()
    try:
        n = build_store(load_cards(args.cards), load_settings(), args.output)
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        p.exit(1, f"Ingest failed: {exc}\n")
    print(f"Indexed {n} chunks: {args.output}")
