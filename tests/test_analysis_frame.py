"""The AI must reason inside the frame the code computed, and the report must show it."""
import json
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from rag.analysis import enrich_report
from rag.config import Settings
from rag.official_report import build_corpus_report
from rag.parsers.native import parse_nessus, parse_nmap
from rag.pipeline import run_report
from rag.report_builder import render_markdown

SECTIONS = ("observations", "potential_impacts", "limitations")


def nmap_db(content=None):
    return parse_nmap(content or (
        b'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
        b'<address addr="192.0.2.40" addrtype="ipv4"/><ports><port protocol="tcp" portid="3306">'
        b'<state state="open"/><service name="mysql" product="MariaDB" version="11.4"/>'
        b'<script id="mysql-empty-password" output="&#xa;root account has empty password"/>'
        b'</port></ports></host></nmaprun>'), "n.xml")[-1]


def nessus_db():
    return parse_nessus(
        b'<NessusClientData_v2><Report name="SYNTHETIC"><ReportHost name="192.0.2.40">'
        b'<ReportItem port="5432" svc_name="postgresql" protocol="tcp" severity="4" pluginID="10483" '
        b'pluginName="PostgreSQL Default Unpassworded Account" pluginFamily="Databases">'
        b'<description>SYNTHETIC</description><plugin_output>SYNTHETIC login without password.</plugin_output>'
        b'</ReportItem></ReportHost></Report></NessusClientData_v2>', "n.nessus")[0]


class FakeLLM:
    """Answers generation and review calls; records every prompt it was given."""

    def __init__(self, *, database_specific=True, same_text=False):
        self.prompts = []
        self.reviews = []
        self.review_system = []
        self.review_schema = []
        self.database_specific = database_specific
        self.same_text = same_text

    def generate(self, prompt, *, system, schema):
        payload = json.loads(prompt)
        if "analysis" in payload:
            self.reviews.append(payload)
            self.review_system.append(system)
            self.review_schema.append(schema)
            return json.dumps({"supported": True, "no_remediation": True,
                               "appropriately_uncertain": True,
                               "database_specific": self.database_specific})
        self.prompts.append(payload)
        sources = payload["sources"]
        source_id = next(iter(sources))
        # A templated model repeats itself; a model that follows the input differs per record.
        flavour = ["Không có mục bằng chứng nào cho thấy dữ liệu bị đọc hoặc bị sửa trong lần chạy này.",
                   "Chưa xác định được phạm vi ảnh hưởng từ bằng chứng do công cụ cung cấp."][len(self.prompts) % 2]
        text = ("Bản ghi này cho thấy một quan sát giống hệt nhau ở mọi phát hiện trong đầu vào."
                if self.same_text else
                f"{flavour} Công cụ ghi nhận: {sources.get('M1', '')[:90].strip()}")
        claim = {"text_vi": text, "citations": [{"source_id": source_id, "quote": sources[source_id][:60]}]}
        return json.dumps({section: [dict(claim)] for section in SECTIONS})


def corpus_report(findings):
    return build_corpus_report(findings, Settings(), [], lambda _: [], corpus_sha256="c", scan_sha256="s")


class AnalysisFrameTests(unittest.TestCase):
    def test_frame_is_attached_and_the_ai_receives_it(self):
        row = nmap_db()
        report = corpus_report([row])
        llm = FakeLLM()
        enrich_report(report, Settings(), llm=llm)
        frame = report["findings"][0]["db_frame"]
        self.assertEqual((frame["relevance"], frame["engine"], frame["control"]),
                         ("server_db", "MySQL/MariaDB", "authentication"))
        sent = llm.prompts[0]["sources"]["K1"]
        self.assertIn("không do AI suy đoán", sent)
        self.assertIn("máy chủ CSDL", sent)
        self.assertIn("Xác thực", sent)
        self.assertEqual(report["db_scope"]["summary"]["by_relevance"], {"server_db": 1})
        self.assertIn("database_specific", llm.review_schema[0]["required"])
        self.assertIn("K1", llm.review_system[0])
        self.assertEqual(llm.reviews[0]["sources"]["K1"], llm.prompts[0]["sources"]["K1"])

    def test_review_must_confirm_the_database_frame(self):
        row = nmap_db()
        report = corpus_report([row])
        enrich_report(report, Settings(), llm=FakeLLM(database_specific=False))
        self.assertEqual(report["findings"][0]["ai_analysis"]["status"], "rejected_output")
        self.assertNotIn("Điều kiện áp dụng", json.dumps(report["findings"][0]["ai_analysis"], ensure_ascii=False))

    def test_summary_sources_carry_the_frame_of_each_record(self):
        report = corpus_report([nmap_db(), nessus_db()])
        llm = FakeLLM()
        enrich_report(report, Settings(), llm=llm)
        summary_prompt = llm.prompts[-1]["sources"]
        self.assertIn("phạm vi CSDL theo code: server_db/máy chủ CSDL", summary_prompt["F1"])
        self.assertIn("engine PostgreSQL", summary_prompt["F2"])
        self.assertIn("K1", summary_prompt)
        self.assertIn("MySQL/MariaDB", summary_prompt["K1"])
        self.assertIn("PostgreSQL", summary_prompt["K1"])
        self.assertIn("Tổng số bản ghi: 2", summary_prompt["TOTAL"])
        self.assertEqual(report["db_scope"]["summary"]["by_engine"], {"MySQL/MariaDB": 1, "PostgreSQL": 1})

    def test_report_markdown_shows_the_frame_and_the_variety_check(self):
        report = corpus_report([nmap_db(), nessus_db()])
        enrich_report(report, Settings(), llm=FakeLLM())
        text = render_markdown(report)
        self.assertIn("Phạm vi CSDL nhận diện từ đầu vào", text)
        self.assertIn("Phạm vi CSDL: máy chủ CSDL; engine: MySQL/MariaDB", text)
        self.assertIn("Kiểm tra trùng lặp văn bản đặc thù", text)
        self.assertEqual(report["prose_check"]["status"], "ok")
        self.assertEqual(report["prose_check"]["duplicate_groups"], [])

    def test_identical_generated_prose_is_flagged_in_the_report(self):
        report = corpus_report([nmap_db(), nessus_db()])
        enrich_report(report, Settings(), llm=FakeLLM(same_text=True))
        self.assertEqual(report["prose_check"]["status"], "duplicate_prose")
        self.assertEqual(report["prose_check"]["duplicate_groups"], [["NMAP-0-0-S0", "NESSUS-0-0"]])
        self.assertIn("phát hiện nhóm bản ghi có diễn giải AI gần giống nhau", render_markdown(report))

    def test_frame_is_data_and_never_becomes_evidence(self):
        row = nmap_db()
        report = corpus_report([row])
        enrich_report(report, Settings(), llm=FakeLLM())
        stored = report["findings"][0]
        self.assertEqual(tuple(stored["evidence"]), asdict(row)["evidence"])
        self.assertNotIn("K1", " ".join(stored["evidence"]))
        self.assertEqual(report["findings"][0]["db_frame"]["rule"], "nmap-mysql-empty-password")


class CardsModeAnalysisTests(unittest.TestCase):
    """The cards (gemini) branch must also write prose from the input, not a template."""

    def test_cards_mode_report_carries_analysis_frame_and_check(self):
        from test_analysis_frame import FakeLLM
        with tempfile.TemporaryDirectory() as tmp:
            with patch("rag.pipeline.VectorStore") as store, \
                 patch("rag.pipeline.gemini_plan") as plan, \
                 patch("rag.analysis.GeminiLLM", return_value=FakeLLM()):
                store.return_value.scores.return_value = [("OWASP-SQLI-PARAM", 0.9), ("OWASP-XSS-ENCODE", 0.9)]
                plan.return_value = {"items": [{"finding_id": fid, "guidance_ids": []}
                                               for fid in ("F-001", "F-002", "F-003")]}
                md_path, json_path, _ = run_report(
                    ROOT / "data/raw/scans/example.json", ROOT / "data/raw/owasp/cards.json",
                    Path(tmp) / "out", Settings(), mode="gemini", index_path=tmp)
            report = json.loads(Path(json_path).read_text(encoding="utf-8"))
            row = report["findings"][0]
            self.assertEqual(row["ai_analysis"]["status"], "ai_reviewed")
            self.assertEqual(row["db_frame"]["relevance"], "app_db")
            self.assertEqual(report["mode"], "gemini-constrained-analysis")
            # Only the SQL injection record concerns a database; XSS and the unknown record do not.
            self.assertEqual(report["db_scope"]["summary"]["by_relevance"],
                             {"app_db": 1, "unrelated": 2})
            self.assertIn("prose_check", report)
            text = Path(md_path).read_text(encoding="utf-8")
            self.assertIn("Phạm vi CSDL nhận diện từ đầu vào", text)
            self.assertIn("Kiểm tra trùng lặp văn bản", text)


if __name__ == "__main__":
    unittest.main()
