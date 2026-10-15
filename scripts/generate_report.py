import argparse
from _bootstrap import ROOT
from rag.config import Settings, load_settings
from rag.pipeline import run_report
from rag.parsers import SUPPORTED_FORMATS

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Generate an evidence-first OWASP report")
    p.add_argument("--input", required=True)
    p.add_argument("--format", choices=SUPPORTED_FORMATS, default="normalized")
    p.add_argument("--mode", choices=["demo", "gemini", "owasp"], default="demo")
    p.add_argument("--cards", default=ROOT / "data/raw/owasp/cards.json")
    p.add_argument("--index", default=ROOT / "data/processed/e5")
    p.add_argument("--output", default=ROOT / "data/reports/latest")
    p.add_argument("--raw", default=ROOT / "data/raw/owasp/official/CheatSheetSeries-master/cheatsheets")
    p.add_argument("--store", default=ROOT / "data/processed/owasp-official")
    p.add_argument("--offline-embeddings", action="store_true")
    args = p.parse_args()
    try:
        settings = load_settings() if args.mode != "demo" else Settings()
        if args.mode == "owasp":
            from rag.official_report import run_corpus_report
            paths = run_corpus_report(args.input, args.output, settings, raw_directory=args.raw,
                                      store_directory=args.store, format_=args.format, offline=args.offline_embeddings,
                                      progress=lambda message: print(message, flush=True))
        else:
            paths = run_report(args.input, args.cards, args.output, settings,
                               format_=args.format, mode=args.mode, index_path=args.index)
    except Exception as exc:
        # Keep SDK errors/HTTP headers out of terminal output; no silent demo fallback.
        if isinstance(exc, (ValueError, FileNotFoundError, ImportError, RuntimeError)):
            p.exit(1, f"Report failed: {exc}\n")
        p.exit(1, f"Report failed ({type(exc).__name__}). Check model/access/input; no AI output saved.\n")
    for path in paths:
        print(path)
