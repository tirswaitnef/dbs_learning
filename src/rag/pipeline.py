import hashlib
from dataclasses import replace
from pathlib import Path

from .llm import demo_plan, gemini_plan
from .loader import load_cards
from .parsers import load_findings
from .report_builder import build_report, write_report
from .retriever import retrieve
from .vector_store import VectorStore


def run_report(scan_path, cards_path, output, settings, *, format_="normalized",
               mode="demo", index_path=None, report_metadata=None, display_filename=None):
    if mode not in {"demo", "gemini", "ollama"}:
        raise ValueError("Mode must be demo, ollama or gemini")
    ai_mode = mode != "demo"
    if mode == "ollama" and settings.llm_provider.strip().lower() != "ollama":
        settings = replace(settings, llm_provider="ollama")
    prefix = "ollama" if (ai_mode and settings.resolved_provider == "ollama") else "gemini"
    cards = load_cards(cards_path)
    findings = load_findings(scan_path, format_)
    if ai_mode and len(findings) > 100:
        raise ValueError("AI report mode supports at most 100 records per call; split the input")
    store = VectorStore(index_path, cards, settings) if ai_mode else None
    candidates = {f.id: retrieve(f, cards, store=store, top_k=settings.top_k,
                                  min_score=settings.top_k and settings.min_score) for f in findings}
    if ai_mode and findings:
        plan = gemini_plan(findings, candidates, cards, settings)
    else:
        plan = demo_plan(findings, candidates)
    report = build_report(findings, candidates, cards, plan,
                          mode=f"{prefix}-constrained" if ai_mode else "demo-no-ai",
                          scan_sha256=hashlib.sha256(Path(scan_path).read_bytes()).hexdigest(),
                          model=settings.model_label if ai_mode else "")
    if ai_mode:
        # Cards mode selects approved guidance; the same reasoning frame gives the model
        # the finding-specific prose, so the report is not the same text for every input.
        from .analysis import enrich_report
        enrich_report(report, settings, mode=f"{prefix}-constrained-analysis")
    from .report_view import attach_context
    attach_context(report, scan_path, format_, report_metadata, display_filename)
    return write_report(report, output)
