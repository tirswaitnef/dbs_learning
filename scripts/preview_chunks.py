"""Episode 02: load/chunk locally without API or embedding downloads."""
import argparse
import json
from dataclasses import asdict
from pathlib import Path

from _bootstrap import ROOT
from rag.chunker import chunk_documents
from rag.config import Settings
from rag.loader import load_documents


def main():
    p = argparse.ArgumentParser(description="Offline document loading and chunk preview")
    p.add_argument("--raw", type=Path, default=ROOT / "data/raw/owasp/documents")
    p.add_argument("--output", type=Path, default=ROOT / "data/processed/load-chunk")
    p.add_argument("--chunk-size", type=int, default=Settings.chunk_size)
    p.add_argument("--overlap", type=int, default=Settings.chunk_overlap)
    args = p.parse_args()
    # Keep generated JSON outside raw, avoiding repeated ingestion of outputs.
    if args.output.resolve().is_relative_to(args.raw.resolve()):
        p.error("Output must be outside the raw document directory")
    try:
        Settings(chunk_size=args.chunk_size, chunk_overlap=args.overlap)
        result = load_documents(args.raw)
        chunks = chunk_documents(result.documents, args.chunk_size, args.overlap)
    except (ValueError, OSError) as exc:
        p.exit(1, f"Load/chunk failed: {exc}\n")
    print(f"Raw directory: {args.raw.resolve()}")
    for doc in result.documents:
        print(f"LOAD {doc.source}: {len(doc.text)} characters")
    for item in result.skipped:
        print(f"SKIP {item['source']}: {item['reason']}")
    print(f"chunk_size={args.chunk_size} | overlap={args.overlap}")
    print(f"Created {len(chunks)} chunks from {len(result.documents)} documents")
    for chunk in chunks:
        print(f"- {chunk.source} | chunk #{chunk.index} | [{chunk.start}:{chunk.end}] | {len(chunk.text)} characters")
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / "chunks.jsonl"
    output.write_text("".join(json.dumps(asdict(c), ensure_ascii=False) + "\n" for c in chunks), encoding="utf-8")
    summary = {"document_count": len(result.documents), "chunk_count": len(chunks),
               "chunk_size": args.chunk_size, "chunk_overlap": args.overlap,
               "documents": [{"source": d.source, "characters": len(d.text),
                              "source_sha256": d.source_sha256} for d in result.documents],
               "skipped": result.skipped,
               "status": "loaded-and-chunked-only; not approved OWASP guidance"}
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Saved: {output.resolve()}")
    if not chunks:
        print("No text chunks available. Add supported nonempty files; PDFs may need OCR.")


if __name__ == "__main__":
    main()
