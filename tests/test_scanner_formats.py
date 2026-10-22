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
        self.assertEqual(len(f.evidence), 1)
        self.assertIn("dvwa", f.evidence[0])

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

    def test_sqlmap_full_telemetry_heuristic_xss_lab_context_and_multilayer_owasp(self):
        from rag.loader import load_documents
        from rag.official_report import blocks, preferred_sources, source_candidates
        from rag.report_view import evidence_profile, extract_scan_context

        synthetic_full = (
            " ___ ___[']_____ ___ ___  {1.10.6#pip}\n"
            "[*] starting @ 11:07:25 /2026-10-20/\n"
            "[11:07:26] [INFO] checking if the target is protected by some kind of WAF/IPS\n"
            "[11:07:26] [WARNING] GET parameter 'id' does not appear to be dynamic\n"
            "[11:07:27] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks\n"
            "for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y\n"
            "[11:07:27] [WARNING] reflective value(s) found and filtering out\n"
            "[11:08:02] [INFO] GET parameter 'id' appears to be 'OR boolean-based blind' injectable (with --not-string=\"Me\")\n"
            "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N\n"
            "sqlmap identified the following injection point(s) with a total of 146 HTTP(s) requests:\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: OR boolean-based blind - WHERE or HAVING clause\n"
            "    Payload: id=1' OR NOT 1=1#&Submit=Submit\n\n"
            "    Type: error-based\n"
            "    Title: MySQL >= 5.1 AND error-based (EXTRACTVALUE)\n"
            "    Payload: id=1' AND EXTRACTVALUE(1,CONCAT(0x5c,1))-- a&Submit=Submit\n"
            "---\n"
            "web server operating system: Linux Debian 9 (stretch)\n"
            "web application technology: Apache 2.4.25\n"
            "back-end DBMS: MySQL >= 5.1 (MariaDB fork)\n"
            "available databases [2]:\n"
            "[*] dvwa\n"
            "[*] information_schema\n"
            "[11:08:19] [INFO] fetched data logged to text files under 'C:\\Users\\DemoLabUser\\AppData\\Local\\sqlmap\\output\\198.51.100.42'\n"
            "[*] ending @ 11:08:19 /2026-10-20/\n"
        )
        parsed = parse_sqlmap_log(synthetic_full, "lab.log")
        self.assertEqual([f.id for f in parsed], ["SQLMAP-0", "SQLMAP-OBS-0"])
        sqli, xss_obs = parsed
        self.assertEqual((sqli.kind, sqli.cwe, xss_obs.kind, xss_obs.cwe),
                         ("scanner_alert", "CWE-89", "observation", "CWE-79"))
        self.assertNotIn("DemoLabUser", json.dumps([asdict(f) for f in parsed]))

        rep_stub = {"findings": [asdict(f) for f in parsed], "input_format": "sqlmap-log"}
        ctx = extract_scan_context(rep_stub)
        self.assertIn("DVWA", ctx["application_hint"])
        self.assertEqual(ctx["schemas"], {"application": ["dvwa"], "system": ["information_schema"]})
        self.assertEqual(len(ctx["telemetry_lines"]), 1)
        self.assertTrue(any("Debian 9" in n for n in ctx["eol_notes"]))
        self.assertEqual(evidence_profile(asdict(sqli))["tier"], "exploited_in_log")
        self.assertEqual(evidence_profile(asdict(xss_obs))["tier"], "heuristic")

        docs = load_documents(ROOT / "data/raw/owasp/official/CheatSheetSeries-master/cheatsheets").documents
        by_name = {d.source: d for d in docs}
        for name in ("SQL_Injection_Prevention_Cheat_Sheet.md", "Query_Parameterization_Cheat_Sheet.md", "Error_Handling_Cheat_Sheet.md"):
            doc = by_name[name]
            for b in blocks(doc):
                self.assertEqual(doc.text[b["start"]:b["end"]], b["text"])
        hits = [{"source": n, "start": 0, "end": len(by_name[n].text), "score": sc}
                for n, sc in [("SQL_Injection_Prevention_Cheat_Sheet.md", 0.91),
                              ("Query_Parameterization_Cheat_Sheet.md", 0.89),
                              ("Error_Handling_Cheat_Sheet.md", 0.86)]]
        cands = source_candidates(hits, docs, preferred_sources(sqli), finding=sqli)
        top5_sections = [c["section"] for c in cands[:5]]
        self.assertTrue(any("Defense Option 1" in s for s in top5_sections))
        self.assertTrue(any("Using PHP with PHP Data Objects" in s for s in top5_sections))
        self.assertTrue(any("Least Privilege" in s for s in top5_sections))
        self.assertTrue(any("Allow-list Input Validation" in s for s in top5_sections))
        self.assertTrue(any("Error Handling Cheat Sheet / Objective" in s for s in top5_sections))

        complete_pentest_log = (
            "Target URL: http://198.51.100.42/vulnerabilities/sqli/?id=1&Submit=Submit\n"
            "Authentication Context: Authenticated HTTP Cookie session (PHPSESSID=[REDACTED]; security=low)\n"
            + synthetic_full
            + "current user: 'root@localhost'\n"
            + "current database: 'dvwa'\n"
            + "current user is DBA: True\n"
            + "Database: dvwa\n[2 tables]\n+-----------+\n| guestbook |\n| users     |\n+-----------+\n"
        )
        full_parsed = parse_sqlmap_log(complete_pentest_log, "pentest_full.log")
        full_ctx = extract_scan_context({"findings": [asdict(f) for f in full_parsed], "input_format": "sqlmap-log"})
        self.assertEqual(full_ctx["repro_gaps"], [])
        self.assertIn("root@localhost", full_ctx["db_identity"])
        self.assertEqual(full_ctx["tables_by_db"], {"dvwa": ["guestbook", "users"]})
        self.assertIn("PHPSESSID=[REDACTED]", evidence_profile(asdict(full_parsed[0]))["note_vi"])

        # Multi-file bundle (Nmap DB port + mysql-empty-password + sqlmap DB exploitation) -> single unified PDF report
        import base64
        import tempfile
        import time
        from rag.web_server import JobManager

        nmap_ec2_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<nmaprun scanner="nmap" args="nmap -Pn -sV -p 80,3306 --script mysql-empty-password -oX nmap_csdl.xml 198.51.100.42" '
            'startstr="Thu Oct 22 10:00:00 2026" version="7.95">\n'
            '  <host><address addr="198.51.100.42" addrtype="ipv4"/>\n'
            '    <ports>\n'
            '      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.25"/></port>\n'
            '      <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MariaDB" version="10.1.48"/>\n'
            '        <script id="mysql-empty-password" output="&#xa;  root account has empty password&#xa;"/>\n'
            '      </port>\n'
            '    </ports>\n'
            '  </host>\n'
            '</nmaprun>\n'
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as tmp_dir:
            mgr = JobManager(tmp_dir, demo=True)
            try:
                job = mgr.submit_bundle({
                    "bundle_version": 1,
                    "files": [
                        {"filename": "nmap_csdl.xml", "format": "auto", "content_b64": base64.b64encode(nmap_ec2_xml).decode()},
                        {"filename": "sqlmap_csdl.txt", "format": "auto", "content_b64": base64.b64encode(complete_pentest_log.encode("utf-8")).decode()},
                    ],
                })
                deadline = time.time() + 15
                while time.time() < deadline:
                    cur = mgr.get(job["id"])
                    if cur["status"] in {"completed", "partial", "failed"}:
                        break
                    time.sleep(0.1)
                self.assertEqual(cur["status"], "completed", cur.get("error"))
                out_json = json.loads((Path(tmp_dir) / job["id"] / "output/report.json").read_text(encoding="utf-8"))
                out_pdf = (Path(tmp_dir) / job["id"] / "output/report.pdf").read_bytes()
                self.assertTrue(out_pdf.startswith(b"%PDF-"))
                merged_cwes = {r["cwe"] for r in out_json["findings"]}
                self.assertIn("CWE-89", merged_cwes)
                self.assertIn("CWE-1393", merged_cwes)
                merged_ctx = extract_scan_context(out_json)
                self.assertEqual(merged_ctx["repro_gaps"], [])
            finally:
                mgr.close()


if __name__ == "__main__":
    unittest.main()
