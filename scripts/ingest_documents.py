import argparse
from pathlib import Path
from _bootstrap import ROOT
from rag.config import load_settings


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Episode 03: document chunks -> E5 CPU -> local vector store")
    p.add_argument("--raw", type=Path, default=ROOT / "data/raw/owasp/documents")
    p.add_argument("--output", type=Path, default=ROOT / "data/processed/documents")
    p.add_argument("--offline", action="store_true", help="Only use cached model; never download")
    args = p.parse_args()
    try:
        from rag.document_store import ingest_documents
        store = ingest_documents(args.raw, args.output, load_settings(), offline=args.offline)
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        p.exit(1, f"Document ingest failed: {exc}\n")
    print(f"Documents: {store.metadata['document_count']}")
    print(f"Embedding matrix: {store.vectors.shape}, dtype={store.vectors.dtype}")
    print(f"Store: {args.output.resolve()}")
    print("Gemini API calls = 0. Retrieved text is not automatically approved guidance.")
