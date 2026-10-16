"""A finding with several tool-supplied CWEs: in scope only if all sit in one Top 10 category."""
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from rag.config import Settings
from rag.loader import load_cards
from rag.official_report import build_corpus_report
from rag.parsers.native import parse_burp
from rag.pipeline import run_report
from rag.report_builder import md_text
from rag.retriever import retrieve
from rag.schemas import Document, Finding
from rag.top10 import classify, cwe_label, enforce, finding_cwes

# Structure of a Burp XML export. PortSwigger lists CWE-89, CWE-94 and CWE-116 for SQL injection.
BURP_SQLI = """<?xml version="1.0"?>
<!DOCTYPE issues [
<!ELEMENT issues (issue*)>
<!ATTLIST issues burpVersion CDATA "">
]>
<issues burpVersion="SYNTHETIC">
  <issue>
    <serialNumber>1</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="192.0.2.10">https://shop.example.test</host>
    <path><![CDATA[/catalog/filter]]></path>
    <location><![CDATA[/catalog/filter [category parameter]]]></location>
    <severity>High</severity>
    <confidence>Firm</confidence>
    <vulnerabilityClassifications><![CDATA[<ul>
<li><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89: SQL Injection</a></li>
<li><a href="https://cwe.mitre.org/data/definitions/94.html">CWE-94: Code Injection</a></li>
<li><a href="https://cwe.mitre.org/data/definitions/116.html">CWE-116: Improper Encoding or Escaping of Output</a></li>
<li><a href="https://capec.mitre.org/data/definitions/66.html">CAPEC-66: SQL Injection</a></li>
</ul>]]></vulnerabilityClassifications>
    <issueDetail><![CDATA[SYNTHETIC: two boolean payloads in the category parameter gave different responses.]]></issueDetail>
  </issue>
</issues>"""

SHEET_TEXT = """# {title}

## Primary Defenses

{body} Use parameterized queries and validate input against an allow-list before it reaches the interpreter.
"""


def finding(cwes, cwe="unknown", evidence=("scanner-provided evidence",)):
    return Finding("F", "Tool issue", cwe, "high", "https://example.test/", evidence, "test", "input#/0",
                   details={"cwes": cwes})


class MultiCweScopeTests(unittest.TestCase):
    def test_burp_sqli_with_three_cwes_in_a05_is_in_scope(self):
        f = parse_burp(BURP_SQLI.encode(), "burp.xml")[0]
        self.assertEqual(f.cwe, "unknown")  # the parser still never picks one CWE
        self.assertEqual(f.details["cwes"], ["CWE-89", "CWE-94", "CWE-116"])
        scope = classify(f)
        self.assertEqual(scope["status"], "in_scope")
        self.assertEqual([c["id"] for c in scope["categories"]], ["A05:2025"])
        self.assertEqual(scope["cwes"], ["CWE-89", "CWE-94", "CWE-116"])
        self.assertIn("Cả 3 CWE", scope["reason"])
        self.assertEqual(cwe_label(f), "CWE-89, CWE-94, CWE-116")

    def test_demo_report_attaches_sqli_card_to_burp_issue(self):
        with tempfile.TemporaryDirectory() as d:
            scan = Path(d) / "burp.xml"
            scan.write_text(BURP_SQLI, encoding="utf-8")
            md, js, *_ = run_report(scan, ROOT / "data/raw/owasp/cards.json", Path(d) / "out", Settings(),
                                    format_="burp")
            row = json.loads(js.read_text(encoding="utf-8"))["findings"][0]
            self.assertEqual(row["status"], "guidance_available")
            self.assertEqual([g["id"] for g in row["guidance"]], ["OWASP-SQLI-PARAM"])
            self.assertIn(md_text("cwe: CWE-89, CWE-94, CWE-116 (công cụ gắn nhiều CWE)"), md.read_text(encoding="utf-8"))

    def test_cwes_spanning_two_categories_stay_out_of_scope(self):
        f = finding(["CWE-79", "CWE-16"])  # A05 and A02, as in a Nessus "PHP Multiple Vulnerabilities" item
        scope = classify(f)
        self.assertEqual(scope["status"], "unknown")
        self.assertIn("A02:2025, A05:2025", scope["reason"])
        self.assertEqual(retrieve(f, load_cards(ROOT / "data/raw/owasp/cards.json")), [])

    def test_one_unmapped_cwe_blocks_the_whole_finding(self):
        scope = classify(finding(["CWE-89", "CWE-119"]))
        self.assertEqual(scope["status"], "unmapped")
        self.assertIn("CWE-119", scope["reason"])

    def test_malformed_cwe_lists_are_treated_as_absent(self):
        for bad in ["CWE-89", ["89", "CWE-94"], [89], ["CWE-89", None], []]:
            with self.subTest(bad=bad):
                f = finding(bad)
                self.assertEqual(finding_cwes(f), [])
                self.assertEqual(classify(f)["status"], "unknown")

    def test_single_cwe_field_wins_over_list(self):
        self.assertEqual(finding_cwes(finding(["CWE-89", "CWE-94"], cwe="CWE-79")), ["CWE-79"])

    def test_enforce_on_exported_rows_uses_the_list(self):
        guidance = [{"id": "OWASP-SQLI-PARAM"}]
        rows = [{"id": "A", "cwe": "unknown", "kind": "scanner_alert", "evidence": ["e"], "guidance": list(guidance),
                 "details": {"cwes": ["CWE-89", "CWE-94", "CWE-116"]}},
                {"id": "B", "cwe": "unknown", "kind": "scanner_alert", "evidence": ["e"], "guidance": list(guidance),
                 "details": {"cwes": ["CWE-89", "CWE-16"]}}]
        report = enforce({"findings": rows})
        self.assertEqual(report["findings"][0]["guidance"], guidance)
        self.assertEqual(report["findings"][1]["guidance"], [])
        self.assertEqual(report["findings"][1]["status"], "scope_blocked")


class OwaspModeMultiCweTests(unittest.TestCase):
    """build_corpus_report with a fake retriever and a fake model: no E5, no Gemini."""

    def test_query_preference_and_guidance_use_every_cwe(self):
        documents = [Document(name, SHEET_TEXT.format(title=name[:-3], body=f"Guidance from {name[:-3]}."), "sha-" + name)
                     for name in ("Other_Cheat_Sheet.md", "SQL_Injection_Prevention_Cheat_Sheet.md")]
        queries = []

        def get_results(query):
            queries.append(query)
            # The unrelated sheet scores higher; the curated SQLi sheet must still be offered first.
            return [{"source": d.source, "start": 0, "end": len(d.text), "score": score}
                    for d, score in zip(documents, (0.95, 0.80))]

        class FakeModel:
            def __init__(self):
                self.prompts = []

            def generate(self, prompt, *, system, schema):
                self.prompts.append(json.loads(prompt))
                return json.dumps({"source_ids": ["S1"]})

        model = FakeModel()
        f = parse_burp(BURP_SQLI.encode(), "burp.xml")[0]
        report = build_corpus_report([f], Settings(), documents, get_results, corpus_sha256="c", scan_sha256="s",
                                     llm=model)
        row = report["findings"][0]
        self.assertTrue(queries[0].startswith("CWE-89 CWE-94 CWE-116 SQL injection"))
        self.assertEqual(row["retrieval"][0]["source"], "SQL_Injection_Prevention_Cheat_Sheet.md")
        self.assertEqual(model.prompts[0]["finding"]["cwe"], "CWE-89, CWE-94, CWE-116")
        self.assertEqual(row["status"], "guidance_available")
        self.assertEqual(row["guidance"][0]["cwe"], "CWE-89, CWE-94, CWE-116")
        self.assertEqual(row["guidance"][0]["source"], "SQL_Injection_Prevention_Cheat_Sheet.md")

    def test_model_output_outside_the_candidates_is_rejected(self):
        documents = [Document("SQL_Injection_Prevention_Cheat_Sheet.md",
                              SHEET_TEXT.format(title="SQL Injection Prevention", body="Guidance."), "sha")]
        results = [{"source": documents[0].source, "start": 0, "end": len(documents[0].text), "score": 0.9}]
        f = parse_burp(BURP_SQLI.encode(), "burp.xml")[0]
        for answer in ({"source_ids": ["S9"]}, {"source_ids": ["S1", "S1"]}, {"source_ids": ["S1"] * 4},
                       {"source_ids": ["S1"], "advice": "free text"}, {"ids": ["S1"]}):
            with self.subTest(answer=answer):
                class Model:
                    def generate(self, prompt, *, system, schema):
                        return json.dumps(answer)

                row = build_corpus_report([f], Settings(), documents, lambda q: results, corpus_sha256="c",
                                          scan_sha256="s", llm=Model())["findings"][0]
                self.assertEqual((row["generation_status"], row["guidance"]), ("rejected_output", []))

    def test_out_of_scope_list_never_reaches_retrieval_or_model(self):
        calls = []
        f = replace(finding(["CWE-79", "CWE-16"]), id="X")
        report = build_corpus_report([f], Settings(), [], lambda q: calls.append(q) or [], corpus_sha256="c",
                                     scan_sha256="s", llm=None)
        self.assertEqual(calls, [])
        self.assertEqual(report["findings"][0]["status"], "scope_blocked")
        self.assertEqual(report["generation_calls"], 0)


if __name__ == "__main__":
    unittest.main()
