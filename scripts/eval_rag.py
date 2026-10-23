"""Run quantitative AI & Hybrid RAG evaluation benchmarks and emit Markdown / JSON tables."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rag.eval_benchmark import render_evaluation_markdown, run_full_evaluation


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        description="Evaluate Hybrid RAG retrieval (Dense vs BM25 vs RRF), 137->25 OWASP pruning, and AI guardrails."
    )
    parser.add_argument(
        "--db-corpus-dir",
        type=Path,
        default=ROOT / "data/raw/owasp/official/CheatSheetSeries-master/cheatsheets",
        help="Path to the pruned DB-focused OWASP Cheat Sheet directory (default: bundled 25 sheets).",
    )
    parser.add_argument(
        "--full-corpus-dir",
        type=Path,
        default=None,
        help="Optional path to full upstream OWASP Cheat Sheets directory (137 .md files) for ablation comparison.",
    )
    parser.add_argument(
        "--offline-svd",
        action="store_true",
        help="Force deterministic unsupervised SVD dense encoder without loading SentenceTransformers.",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Optional Markdown output path to save full formatted tables.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional JSON output path to save raw benchmark metrics.",
    )
    args = parser.parse_args()

    results = run_full_evaluation(
        db_corpus_dir=args.db_corpus_dir,
        full_corpus_dir=args.full_corpus_dir,
        prefer_e5=not args.offline_svd,
    )
    md = render_evaluation_markdown(results)
    print(md)

    if args.output_md:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text(md, encoding="utf-8")
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
