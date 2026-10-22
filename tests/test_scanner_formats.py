import json
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from rag.config import Settings
from rag.parsers import load_findings, parse_zap
from rag.parsers.native import parse_burp, parse_nuclei, parse_sqlmap_log, safe_xml
from rag.pipeline import run_report

FIXTURES = ROOT / "tests/fixtures/scanners"
CASES = {"zap": "zap.json", "burp": "burp.xml", "nuclei": "nuclei.jsonl",
         "sqlmap-log": "sqlmap.log", "nessus": "nessus.nessus", "nmap": "nmap.xml"}


class ScannerFormatTests(unittest.TestCase):
    def test_all_six_formats_roundtrip_normalized_without_metadata_loss(self):
        with tempfile.TemporaryDirectory() as d:
            for format_, filename in CASES.items():
                with self.subTest(format=format_):
                    findings = load_findings(FIXTURES / filename, format_)
                    self.assertEqual(len(findings), 1)
                    p = Path(d) / (format_ + ".json")
                    p.write_text(json.dumps({"schema_version": 1, "tool": "imported",
                                              "findings": [asdict(f) for f in findings]}), encoding="utf-8")
                    self.assertEqual(load_findings(p), findings)

    def test_six_formats_integrate_with_report_without_ai(self):
        with tempfile.TemporaryDirectory() as d:
            for format_, filename in CASES.items():
                with self.subTest(format=format_):
                    _, js, *_ = run_report(FIXTURES / filename, ROOT / "data/raw/owasp/cards.json",
                                       Path(d) / format_, Settings(), format_=format_)
                    report = json.loads(js.read_text(encoding="utf-8"))
                    self.assertEqual(len(report["findings"]), 1)
                    if format_ == "nmap":
                        self.assertEqual(report["findings"][0]["kind"], "observation")
                        self.assertEqual(report["findings"][0]["guidance"], [])

    def test_burp_base64_and_native_solution_preserved(self):
        f = load_findings(FIXTURES / "burp.xml", "burp")[0]
        self.assertIn("HTTP/1.1 200 OK", f.evidence[1])
        self.assertEqual(f.details["confidence"], "Tentative")
        self.assertEqual(f.details["scanner_solution"], "SCANNER ADVICE ONLY")

    def test_burp_html_classifications_and_multiple_cwes(self):
        content = (FIXTURES / "burp.xml").read_text()
        content = content.replace('<cwe>79</cwe>', '<![CDATA[<a>CWE-79: XSS</a><a>CWE-80: Other</a>]]>')
        f = parse_burp(content.encode(), "x.xml")[0]
        self.assertEqual(f.details["cwes"], ["CWE-79", "CWE-80"])
        self.assertEqual(f.cwe, "unknown")

    def test_zap_uses_response_even_without_evidence_field(self):
        data = json.loads((FIXTURES / "zap.json").read_text())
        instance = data["site"][0]["alerts"][0]["instances"][0]
        instance["evidence"] = ""
        instance["response-body"] = "SYNTHETIC observed content"
        f = parse_zap(data, "zap.json")[0]
        self.assertTrue(f.evidence)
        self.assertEqual(f.details["raw_instance"]["attack"], "DEMO marker")

    def test_nuclei_request_alone_not_response_evidence(self):
        row = json.loads((FIXTURES / "nuclei.jsonl").read_text().splitlines()[0])
        row.pop("response")
        row.pop("extracted-results")
        f = parse_nuclei(json.dumps(row), "file.jsonl")[0]
        self.assertEqual(f.evidence, ())
        self.assertIn("request", f.details["raw_result"])
        self.assertEqual(parse_nuclei(json.dumps({**row, "matcher-status": False}), "x"), [])

    def test_xml_entities_and_external_dtd_rejected_even_utf16(self):
        for xml in ['<!DOCTYPE issues [<!ENTITY x "payload">]><issues>&x;</issues>',
                    '<!DOCTYPE issues SYSTEM "https://example.test/external.dtd"><issues/>']:
            for encoding in ["utf-8", "utf-16"]:
                with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                    safe_xml(xml.encode(encoding), "issues")

    def test_bad_xml_base64_jsonl_and_wrong_format_rejected(self):
        with self.assertRaises(ValueError):
            safe_xml(b"<issues>", "issues")
        content = b'<issues><issue><name>x</name><requestresponse><response base64="true">@@</response></requestresponse></issue></issues>'
        with self.assertRaises(ValueError):
            parse_burp(content, "x")
        with self.assertRaises(ValueError):
            parse_nuclei('not JSON', "x")
        with self.assertRaises(ValueError):
            load_findings(FIXTURES / "nmap.xml", "burp")

    def test_sqlmap_heuristics_not_accepted_as_final_finding(self):
        with self.assertRaises(ValueError):
            parse_sqlmap_log("[WARNING] heuristic test suggests parameter might be injectable", "x")
        self.assertEqual(parse_sqlmap_log("all tested parameters do not appear to be injectable", "x"), [])
        with self.assertRaises(ValueError):
            parse_sqlmap_log("Parameter: q (GET)\n    Type: boolean-based blind\n", "x")

    def test_sqlmap_no_invented_severity_or_target(self):
        f = load_findings(FIXTURES / "sqlmap.log", "sqlmap-log")[0]
        self.assertEqual(f.severity, "unknown")
        self.assertIn("target URL not established", f.location)
        self.assertEqual(f.details["parameter"], "q")
        self.assertEqual(f.details["method"], "GET")

    def test_sqlmap_dbs_and_output_host_captured_without_leaking_windows_user_path(self):
        sample = (
            (FIXTURES / "sqlmap.log").read_text(encoding="utf-8")
            + "\n[11:08:18] [INFO] the back-end DBMS is MySQL\n"
              "back-end DBMS: MySQL >= 5.1 (MariaDB fork)\n"
              "available databases [2]:\n[*] dvwa\n[*] information_schema\n"
              "[11:08:19] [INFO] fetched data logged to text files under "
              "'C:\\Users\\DemoUser\\AppData\\Local\\sqlmap\\output\\192.0.2.55'\n"
        )
        f = parse_sqlmap_log(sample, "scan.txt")[0]
        self.assertEqual(f.location, "host=192.0.2.55 (sqlmap output log); parameter=q (GET)")
        self.assertNotIn("DemoUser", f.location)
        self.assertEqual(len(f.evidence), 2)
        self.assertIn("dvwa", f.evidence[1])

    def test_utf16_powershell_redirection_supported_in_parser_and_web_detect(self):
        from rag.web_server import detect_format
        raw_log = (FIXTURES / "sqlmap.log").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as d:
            for enc, bom in [("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")]:
                p = Path(d) / f"sqlmap_{enc}.txt"
                p.write_bytes(bom + raw_log.encode(enc))
                with self.subTest(encoding=enc):
                    self.assertEqual(detect_format(p), "sqlmap-log")
                    f = load_findings(p, "sqlmap-log")[0]
                    self.assertEqual((f.cwe, f.details["parameter"]), ("CWE-89", "q"))


if __name__ == "__main__":
    unittest.main()
