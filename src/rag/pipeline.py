import hashlib
from pathlib import Path

from .llm import demo_plan, gemini_plan
from .loader import load_cards
from .parsers import load_findings
from .report_builder import build_report, write_report
from .retriever import retrieve
from .vector_store import VectorStore


def run_report(scan_path, cards_path, output, settings, *, format_="normalized",
               mode="demo", index_path=None, report_metadata=None,display_filename=None):
    if mode not in {"demo", "gemini"}:
        raise ValueError("Mode must be demo or gemini")
    cards = load_cards(cards_path)
    findings = load_findings(scan_path, format_)
    if mode == "gemini" and len(findings) > 100:
        raise ValueError("Gemini report mode supports at most 100 records per call; split the input")
    store = VectorStore(index_path, cards, settings) if mode == "gemini" else None
    candidates = {f.id: retrieve(f, cards, store=store, top_k=settings.top_k,
                                  min_score=settings.min_score) for f in findings}
    if mode == "gemini" and findings:
        plan = gemini_plan(findings, candidates, cards, settings)
    else:
        plan = demo_plan(findings, candidates)
    report = build_report(findings, candidates, cards, plan,
                          mode="gemini-constrained" if mode == "gemini" else "demo-no-ai",
                          scan_sha256=hashlib.sha256(Path(scan_path).read_bytes()).hexdigest(),
                          model=settings.chat_model if mode == "gemini" else "")
    if mode == "gemini":
        # Cards mode selects approved guidance; the same reasoning frame gives the model
        # the finding-specific prose, so the report is not the same text for every input.
        from .analysis import enrich_report
        enrich_report(report, settings, mode="gemini-constrained-analysis")
    from .report_view import attach_context
    attach_context(report,scan_path,format_,report_metadata,display_filename)
    return write_report(report, output)
