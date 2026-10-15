"""Python-only demo: no API, embedding download, or .env needed; requires reportlab."""
from _bootstrap import ROOT
from rag.config import Settings
from rag.pipeline import run_report

if __name__ == "__main__":
    paths = run_report(ROOT / "data/raw/scans/example.json", ROOT / "data/raw/owasp/cards.json",
                       ROOT / "data/reports/demo", Settings())
    print("DEMO ONLY — no AI, no embeddings")
    for path in paths:
        print(path)
