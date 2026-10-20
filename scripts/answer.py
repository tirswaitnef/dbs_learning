import argparse
import json
from pathlib import Path
from _bootstrap import ROOT
from rag.config import load_settings
from rag.qa import RAGPipeline


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Episode 04: retrieved context -> grounded AI answer with checked citations")
    p.add_argument("question")
    p.add_argument("--raw", type=Path, default=ROOT / "data/raw/owasp/documents")
    p.add_argument("--store", type=Path, default=ROOT / "data/processed/documents")
    p.add_argument("--top-k", type=int)
    p.add_argument("--min-score", type=float)
    p.add_argument("--offline-embeddings", action="store_true", help="Cache-only E5; pairs with local Ollama for full offline run")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    try:
        pipeline = RAGPipeline(load_settings(), args.store, args.raw)
        result = pipeline.answer(args.question, top_k=args.top_k, min_score=args.min_score,
                                 offline_embeddings=args.offline_embeddings)
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        p.exit(1, f"Answer failed: {exc}\n")
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print("Status:", result.status)
        print(result.answer)
        if result.sources:
            print("\nNguồn thực sự được trích dẫn:")
            for source in result.sources:
                print(f"[{source['source_id']}] {source['source']} | chunk #{source['index']} | score={source['score']:.4f}")
        print("\nKiểm tra tự động: ID nguồn và trích đoạn; chưa xác minh đầy đủ ý nghĩa câu trả lời.")
    if result.status == "rejected_output":
        p.exit(2)
