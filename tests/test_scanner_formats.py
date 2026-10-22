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
            "CVSS: 8.1 (High) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n"
            + synthetic_full.replace("[y/N] N", "[y/N] Y").replace("level (1) and risk (1)", "level (5) and risk (3)")
            + "current user: 'app@localhost'\n"
            + "current database: 'dvwa'\n"
            + "current user is DBA: False\n"
            + "Database: dvwa\n[2 tables]\n+-----------+\n| guestbook |\n| users     |\n+-----------+\n"
            + "\nHTTP request [#11]:\nGET /vulnerabilities/sqli/?id=1%27%20OR%20NOT%205290%3D5290%23&Submit=Submit HTTP/1.1\nHost: 198.51.100.42\nCookie: PHPSESSID=[REDACTED]; security=low\n\nHTTP response [#11] (200 OK):\nServer: Apache/2.4.25 (Debian)\n\n<pre>ID: 1' OR NOT 5290=5290#<br />First name: admin<br />Surname: admin</pre>\n"
            + "\nHTTP request [#24]:\nGET /vulnerabilities/sqli/?id=1%27%20AND%20EXTRACTVALUE(2172,CONCAT(0x5c,0x71787a7a71))--%20cWfP&Submit=Submit HTTP/1.1\nHost: 198.51.100.42\nCookie: PHPSESSID=[REDACTED]; security=low\n\nHTTP response [#24] (200 OK):\nServer: Apache/2.4.25 (Debian)\n\n<pre>XPATH syntax error: '\\qxzzq1qzxbbq'</pre>\n"
            + "\nHTTP request [#38]:\nGET /vulnerabilities/sqli/?id=1%27%20AND%20(SELECT%201156%20FROM%20(SELECT(SLEEP(5)))VtpK)--%20pXlg&Submit=Submit HTTP/1.1\nHost: 198.51.100.42\nCookie: PHPSESSID=[REDACTED]; security=low\n\nHTTP response [#38] (200 OK):\nServer: Apache/2.4.25 (Debian)\nX-Observed-Delay: >=5000ms\n\n<pre>ID: 1' AND (SELECT 1156 FROM (SELECT(SLEEP(5)))VtpK)-- pXlg<br />First name: admin</pre>\n"
            + "\nHTTP request [#52]:\nGET /vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20CONCAT(0x71787a7a71),NULL%23&Submit=Submit HTTP/1.1\nHost: 198.51.100.42\nCookie: PHPSESSID=[REDACTED]; security=low\n\nHTTP response [#52] (200 OK):\nServer: Apache/2.4.25 (Debian)\n\n<pre>First name: qxzzqGFxZnmIu...qzxbbq</pre>\n"
        )
        full_parsed = parse_sqlmap_log(complete_pentest_log, "pentest_full.log")
        self.assertEqual(full_parsed[0].severity, "high")
        self.assertEqual(full_parsed[0].details["cvss_score"], "8.1")
        self.assertEqual(full_parsed[0].details["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N")
        self.assertEqual(len(full_parsed[0].details["http_messages"]), 4)
        self.assertTrue(full_parsed[0].details["scan_telemetry"]["tested_all_parameters"])
        full_ctx = extract_scan_context({"findings": [asdict(f) for f in full_parsed], "input_format": "sqlmap-log"})
        self.assertEqual(full_ctx["repro_gaps"], [])
        self.assertIn("app@localhost", full_ctx["db_identity"])
        self.assertEqual(full_ctx["tables_by_db"], {"dvwa": ["guestbook", "users"]})
        self.assertIn("8.1", evidence_profile(asdict(full_parsed[0]))["note_vi"])

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

    def test_non_sqlmap_scanners_have_zero_sqlmap_or_dvwa_or_php_bias(self):
        import tempfile
        from unittest.mock import patch
        from rag.loader import load_documents
        from rag.official_report import preferred_sources, source_candidates
        from rag.parsers import parse_zap
        from rag.parsers.native import parse_nessus, parse_nuclei
        from rag.pdf_report import render_pdf
        from rag.report_view import extract_scan_context
        from rag.top10 import classify

        docs = load_documents(ROOT / "data/raw/owasp/official/CheatSheetSeries-master/cheatsheets").documents
        by_name = {d.source: d for d in docs}
        sqli_hits = [{"source": n, "start": 0, "end": len(by_name[n].text), "score": sc}
                     for n, sc in [("SQL_Injection_Prevention_Cheat_Sheet.md", 0.91),
                                   ("Query_Parameterization_Cheat_Sheet.md", 0.89),
                                   ("Error_Handling_Cheat_Sheet.md", 0.86)]]

        # 1) OWASP ZAP on Java Spring + PostgreSQL selects Java Prepared Statement (zero PHP, zero sqlmap, zero DVWA).
        zap_doc = {
            "@version": "2.15.0",
            "@generated": "Thu, 22 Oct 2026 09:30:00",
            "site": [{
                "@name": "https://api.enterprise.example",
                "alerts": [{
                    "pluginid": "40018",
                    "alert": "SQL Injection - PostgreSQL",
                    "riskcode": "3",
                    "confidence": "3",
                    "cweid": "89",
                    "desc": "SQL injection in Spring Boot JDBC repository backed by PostgreSQL 16.",
                    "solution": "Use PreparedStatement.",
                    "instances": [{
                        "uri": "https://api.enterprise.example/v1/orders?customerId=42",
                        "method": "GET",
                        "param": "customerId",
                        "evidence": "org.postgresql.util.PSQLException: ERROR: syntax error at or near \"'\"",
                    }],
                }],
            }],
        }
        zap_finding = parse_zap(zap_doc, "zap_java_pg.json")[0]
        java_cands = source_candidates(sqli_hits, docs, preferred_sources(zap_finding), finding=zap_finding)
        java_top5 = [c["section"] for c in java_cands[:5]]
        self.assertTrue(any("Using Java built-in feature" in s for s in java_top5))
        self.assertFalse(any("PHP" in s for s in java_top5))

        # 2) Stack-agnostic SQLi scan with NO language clues falls back to language-neutral Introduction (NOT PHP!).
        neutral_doc = {
            "site": [{
                "@name": "https://portal.corp.example",
                "alerts": [{
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "riskcode": "3",
                    "cweid": "89",
                    "instances": [{"uri": "https://portal.corp.example/items?id=7", "method": "GET", "param": "id", "evidence": "SQL syntax error"}],
                }],
            }],
        }
        neutral_finding = parse_zap(neutral_doc, "zap_neutral.json")[0]
        neutral_top5 = [c["section"] for c in source_candidates(sqli_hits, docs, preferred_sources(neutral_finding), finding=neutral_finding)[:5]]
        self.assertTrue(any("Query Parameterization Cheat Sheet / Introduction" in s for s in neutral_top5))
        self.assertFalse(any("PHP" in s for s in neutral_top5))

        # Render full PDF for ZAP Java/PostgreSQL scan and verify ZERO leaked mention of sqlmap / DVWA / PHP anywhere.
        zap_report = {
            "schema_version": 1,
            "generated_at": "2026-10-22T09:35:00+00:00",
            "mode": "ollama-top10-analysis-extractive",
            "model": "ollama/qwen3:4b",
            "input_format": "zap",
            "input_filename": "zap_java_pg.json",
            "scan_sha256": "c" * 64,
            "knowledge_sha256": "d" * 64,
            "findings": [{**asdict(zap_finding), "owasp_top10": classify(zap_finding), "guidance": []}],
            "limitations": [],
        }
        zap_ctx = extract_scan_context(zap_report)
        self.assertEqual(zap_ctx["repro_gaps"], [])
        self.assertIsNone(zap_ctx["lab"])
        rendered_texts = []
        orig_para = __import__("reportlab.platypus", fromlist=["Paragraph"]).Paragraph
        with tempfile.TemporaryDirectory() as tmp_d:
            with patch("reportlab.platypus.Paragraph", side_effect=lambda t, *a, **k: (rendered_texts.append(str(t)), orig_para(t, *a, **k))[1]):
                render_pdf(zap_report, Path(tmp_d) / "zap.pdf")
        joined = "\n".join(rendered_texts).lower()
        self.assertIn("owasp zap", joined)
        self.assertNotIn("sqlmap", joined)
        self.assertNotIn("dvwa", joined)

        # 3) Nuclei JSONL (MongoDB unauthenticated) & Nessus XML preserve CVSS vector + non-MySQL DB hardening sections.
        nuclei_line = json.dumps({
            "template-id": "mongodb-unauth",
            "type": "tcp",
            "matched-at": "198.51.100.88:27017",
            "timestamp": "2026-10-22T10:15:00Z",
            "info": {
                "name": "MongoDB Unauthenticated Access",
                "severity": "high",
                "classification": {
                    "cwe-id": ["CWE-306"],
                    "cvss-score": 7.5,
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                },
            },
            "extracted-results": ["databases: admin, customers"],
        })
        nuc_finding = parse_nuclei(nuclei_line, "nuclei_mongo.jsonl")[0]
        self.assertEqual(nuc_finding.details["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        db_hits = [{"source": "Database_Security_Cheat_Sheet.md", "start": 0, "end": len(by_name["Database_Security_Cheat_Sheet.md"].text), "score": 0.90}]
        mongo_top5 = [c["section"] for c in source_candidates(db_hits, docs, {"Database_Security_Cheat_Sheet.md"}, finding=nuc_finding)[:5]]
        self.assertTrue(any("MongoDB" in s for s in mongo_top5))

        nessus_xml = (
            b'<?xml version="1.0"?><NessusClientData_v2><Report name="db-audit">'
            b'<ReportHost name="198.51.100.99"><HostProperties>'
            b'<tag name="HOST_START">Thu Oct 22 10:00:00 2026</tag>'
            b'<tag name="operating-system">Microsoft Windows Server 2022</tag>'
            b'</HostProperties>'
            b'<ReportItem port="1433" svc_name="mssql" protocol="tcp" severity="3" pluginID="99901" '
            b'pluginName="Microsoft SQL Server Weak Authentication" pluginFamily="Databases">'
            b'<cwe>521</cwe><cvss3_base_score>8.8</cvss3_base_score>'
            b'<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</cvss3_vector>'
            b'<plugin_output>Login sa accepted weak password over TCP/1433 cleartext transport.</plugin_output>'
            b'</ReportItem></ReportHost></Report></NessusClientData_v2>'
        )
        nes_finding = parse_nessus(nessus_xml, "mssql_audit.nessus")[0]
        self.assertEqual(nes_finding.details["cvss_score"], "8.8")
        self.assertEqual(nes_finding.details["cvss_vector"], "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        mssql_top5 = [c["section"] for c in source_candidates(db_hits, docs, {"Database_Security_Cheat_Sheet.md"}, finding=nes_finding)[:5]]
        self.assertTrue(any("Hardening a Microsoft SQL Server" in s for s in mssql_top5))
        self.assertTrue(any("Implementing Transport Layer Protection" in s for s in mssql_top5))

    def test_sqlmap_scope_rule_and_parameter_aware_http_selection(self):
        from dataclasses import asdict
        from rag.parsers.native import parse_sqlmap_log
        from rag.report_view import extract_scan_context

        header_and_block = (
            "Target URL: http://198.51.100.42/app/item?id=1&Submit=Submit\n"
            "Authentication Context: Authenticated HTTP Cookie session (SID=[REDACTED])\n"
            "CVSS: 8.1 (High) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n"
            "Pentest Scope Rule: Isolated Lab Deep DB PoC (--dbs, --tables; NO --dump)\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)\n"
            "    Payload: id=1' OR NOT 1111=1111-- abcd&Submit=Submit\n\n"
            "    Type: error-based\n"
            "    Title: MySQL >= 5.1 AND error-based (EXTRACTVALUE)\n"
            "    Payload: id=1' AND EXTRACTVALUE(1,CONCAT(0x5c,0x71))-- efgh&Submit=Submit\n"
            "---\n"
            "back-end DBMS: MySQL >= 5.1\n\n"
        )
        curated_log = (
            header_and_block
            + "HTTP request [#101]:\nGET /app/item?id=1&Submit=Submit%20OR%20NOT%201%3D1 HTTP/1.1\nHost: 198.51.100.42\n\n"
            + "HTTP response [#101] (200 OK):\nContent-Type: text/html\n\nOK\n\n"
            + "HTTP request [#202]:\nGET /app/item?id=1%27%20AND%20EXTRACTVALUE%281%2C1%29--%20x&Submit=Submit HTTP/1.1\nHost: 198.51.100.42\n\n"
            + "HTTP response [#202] (200 OK):\nContent-Type: text/html\n\nXPATH syntax error\n"
        )
        parsed = parse_sqlmap_log(curated_log, "scope_check.txt")
        tel = parsed[0].details["scan_telemetry"]
        self.assertIn("NO --dump", tel["scope_rule"])
        self.assertEqual(tel["unmatched_http_ids"], ["#101"])
        ctx = extract_scan_context({"findings": [asdict(f) for f in parsed]})
        self.assertIn("NO --dump", ctx["scope_rule"])
        self.assertTrue(any("#101" in g for g in ctx["repro_gaps"]))

        # When raw >8 HTTP exchanges are appended, selector prefers true `id` payloads over `Submit` noise.
        noise_chunks = "".join(
            f"HTTP request [#{n}]:\nGET /app/item?id=1&Submit=Submit%20OR%20{n}%3D{n} HTTP/1.1\nHost: 198.51.100.42\n\n"
            f"HTTP response [#{n}] (200 OK):\nContent-Type: text/html\n\nOK\n\n"
            for n in range(1, 10)
        )
        true_chunks = (
            "HTTP request [#51]:\nGET /app/item?id=1%27%20OR%20NOT%209227%3D9227--%20x&Submit=Submit HTTP/1.1\nHost: 198.51.100.42\n\n"
            "HTTP response [#51] (200 OK):\nContent-Type: text/html\n\nOK\n\n"
            "HTTP request [#52]:\nGET /app/item?id=1%27%20AND%20EXTRACTVALUE%281%2C1%29--%20x&Submit=Submit HTTP/1.1\nHost: 198.51.100.42\n\n"
            "HTTP response [#52] (200 OK):\nContent-Type: text/html\n\nXPATH\n"
        )
        parsed_raw = parse_sqlmap_log(header_and_block + noise_chunks + true_chunks, "raw_traffic_check.txt")
        picked_ids = [m["id"] for m in parsed_raw[0].details["http_messages"]]
        self.assertEqual(picked_ids, ["#51", "#52"])
        self.assertNotIn("unmatched_http_ids", parsed_raw[0].details["scan_telemetry"])


if __name__ == "__main__":
    unittest.main()
