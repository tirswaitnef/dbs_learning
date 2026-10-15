import argparse
import json
from pathlib import Path
from _bootstrap import ROOT
from rag.config import load_settings


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Episode 03: local E5 retrieval; no LLM answer")
    p.add_argument("question")
    p.add_argument("--raw", type=Path, default=ROOT / "data/raw/owasp/documents")
    p.add_argument("--store", type=Path, default=ROOT / "data/processed/documents")
    p.add_argument("--top-k", type=int)
    p.add_argument("--min-score", type=float, help="Optional cosine filter; not a confidence probability")
    p.add_argument("--offline", action="store_true", help="Use cached model only")
    p.add_argument("--json", action="store_true", help="Print structured retrieval context")
    args = p.parse_args()
    try:
        from rag.document_store import retrieve_documents
        results = retrieve_documents(args.question, args.store, args.raw, load_settings(),
                                     top_k=args.top_k, min_score=args.min_score, offline=args.offline)
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        p.exit(1, f"Retrieval failed: {exc}\n")
    if args.json:
        print(json.dumps({"question": args.question, "gemini_api_calls": 0,
                          "results": results}, ensure_ascii=False, indent=2))
    else:
        print("Local retrieval only. Gemini API calls = 0.")
        if not results:
            print("No chunks passed the selected filter; no answer generated.")
        for rank, r in enumerate(results, 1):
            print(f"\n{rank}. {r['source']} | chunk #{r['index']} | score={r['score']:.4f}")
            print(f"Characters [{r['start']}:{r['end']}]")
            print(r["text"])
            if r["metadata"]:
                print("Metadata:", json.dumps(r["metadata"], ensure_ascii=False))
