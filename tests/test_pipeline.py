import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rag.chunker import split_text
from rag.config import Settings
from rag.llm import demo_plan
from rag.loader import load_cards
from rag.parsers import load_findings, parse_normalized, parse_zap
from rag.pipeline import run_report
from rag.report_builder import build_report, render_markdown
from rag.retriever import retrieve
from rag.schemas import Finding
from rag.validators import validate_plan


class GuardrailTests(unittest.TestCase):
    def setUp(self):
        self.cards = load_cards(ROOT / "data/raw/owasp/cards.json")
        self.f = Finding("F", "SQL Injection", "CWE-89", "high", "example.test",
                         ("scanner-provided evidence",), "test", "input#/0")
        self.candidates = {"F": retrieve(self.f, self.cards)}

    def test_unknown_cwe_abstains(self):
        self.assertEqual(retrieve(replace(self.f, cwe="CWE-999"), self.cards), [])

    def test_missing_evidence_abstains(self):
        self.assertEqual(retrieve(replace(self.f, evidence=()), self.cards), [])

    def test_unapproved_guidance_excluded(self):
        self.assertEqual(retrieve(self.f, [replace(c, approved=False) for c in self.cards]), [])

    def test_ai_cannot_invent_guidance(self):
        with self.assertRaises(ValueError):
            validate_plan({"items": [{"finding_id": "F", "guidance_ids": ["invented"]}]},
                          [self.f], self.candidates)

    def test_ai_cannot_use_wrong_cwe_card(self):
        with self.assertRaises(ValueError):
            validate_plan({"items": [{"finding_id": "F", "guidance_ids": ["OWASP-XSS-ENCODE"]}]},
                          [self.f], self.candidates)

    def test_ai_cannot_write_freeform_remediation(self):
        with self.assertRaises(ValueError):
            validate_plan({"items": [{"finding_id": "F", "guidance_ids": [],
                                     "remediation": "disable authentication"}]}, [self.f], self.candidates)

    def test_ai_cannot_omit_or_duplicate_finding(self):
        valid = {"finding_id": "F", "guidance_ids": []}
        for items in [[], [valid, valid]]:
            with self.subTest(items=items), self.assertRaises(ValueError):
                validate_plan({"items": items}, [self.f], self.candidates)

    def test_non_owasp_and_lookalike_urls_rejected(self):
        rows = json.loads((ROOT / "data/raw/owasp/cards.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "cards.json"
            for url in ["https://owasp.org.evil.test/a", "http://owasp.org/a", "https://evil.test/a"]:
                rows[0]["url"] = url
                p.write_text(json.dumps(rows), encoding="utf-8")
                with self.subTest(url=url), self.assertRaises(ValueError):
                    load_cards(p)

    def test_retrieval_filters_score_and_cwe(self):
        class Store:
            def scores(self, _):
                return [("OWASP-SQLI-PARAM", 0.8), ("OWASP-XSS-ENCODE", 0.99)]
        matches = retrieve(self.f, self.cards, store=Store(), min_score=0.75)
        self.assertEqual([m["card_id"] for m in matches], ["OWASP-SQLI-PARAM"])
        self.assertEqual(retrieve(self.f, self.cards, store=Store(), min_score=0.9), [])

    def test_report_preserves_input_and_escapes_markup(self):
        f = replace(self.f, title="<script>alert(1)</script>", evidence=("[click](javascript:bad)",))
        report = build_report([f], self.candidates, self.cards,
                              demo_plan([f], self.candidates), mode="demo-no-ai", scan_sha256="test")
        self.assertEqual(report["findings"][0]["evidence"], f.evidence)
        text = render_markdown(report)
        self.assertNotIn("<script>", text)
        self.assertNotIn("[click](javascript:bad)", text)
        self.assertIn(self.cards[0].url, text)

    def test_parser_does_not_treat_zap_attack_as_evidence(self):
        data = {"site": [{"alerts": [{"alert": "SQL Injection", "cweid": "89",
                "instances": [{"attack": "payload only"}]}]}]}
        self.assertEqual(parse_zap(data, "zap.json")[0].evidence, ())

    def test_normalized_evidence_must_be_list(self):
        data = {"schema_version": 1, "tool": "x", "findings": [
            {"id": "1", "title": "x", "evidence": "not a list"}]}
        with self.assertRaises(ValueError):
            parse_normalized(data, "file.json")

    def test_duplicate_finding_ids_rejected(self):
        data = {"schema_version": 1, "tool": "x", "findings": [{"id": "1", "title": "x"}] * 2}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "duplicate.json"
            p.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                load_findings(p)

    def test_chunking_terminates_and_preserves_overlap(self):
        self.assertEqual(list(split_text("abcdefghij", 6, 2)), ["abcdef", "efghij"])
        with self.assertRaises(ValueError):
            list(split_text("abc", 2, 2))

    def test_demo_end_to_end_including_abstention(self):
        with tempfile.TemporaryDirectory() as d:
            md, js, *_ = run_report(ROOT / "data/raw/scans/example.json", ROOT / "data/raw/owasp/cards.json",
                                d, Settings())
            data = json.loads(js.read_text(encoding="utf-8"))
            self.assertEqual(data["mode"], "demo-no-ai")
            self.assertEqual([f["status"] for f in data["findings"]],
                             ["guidance_available", "missing_evidence", "scope_blocked"])
            self.assertTrue(md.exists())

    def test_zap_fixture_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            _, js, *_ = run_report(ROOT / "data/raw/scans/zap-example.json", ROOT / "data/raw/owasp/cards.json",
                               d, Settings(), format_="zap")
            row = json.loads(js.read_text(encoding="utf-8"))["findings"][0]
            self.assertEqual(row["guidance"][0]["id"], "OWASP-XSS-ENCODE")
            self.assertIn("#/site/0/alerts/0/instances/0", row["source_ref"])

    def test_invalid_ai_plan_writes_no_report(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("rag.pipeline.VectorStore") as store, patch("rag.pipeline.gemini_plan") as llm:
                store.return_value.scores.return_value = [("OWASP-SQLI-PARAM", 0.9)]
                llm.return_value = {"items": [{"finding_id": "F-001", "guidance_ids": ["fake"]}]}
                with self.assertRaises(ValueError):
                    run_report(ROOT / "data/raw/scans/example.json", ROOT / "data/raw/owasp/cards.json",
                               d, Settings(), mode="gemini", index_path=d)
                self.assertFalse((Path(d) / "report.md").exists())


if __name__ == "__main__":
    unittest.main()
