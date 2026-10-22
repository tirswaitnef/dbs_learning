import base64
import json
import sys
import tempfile
import time
import unittest
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rag.dbsec_report import prepare_dbsec_report, render_dbsec_markdown
from rag.parsers import load_findings
from rag.pdf_report import render_pdf
from rag.report_view import META_FIELDS
from rag.top10 import classify
from rag.web_server import JobManager, LocalServer


class CourseworkReportAndWebTests(unittest.TestCase):
    def test_official_10_section_template_strict_non_invented_severity_and_states(self):
        # Raw sqlmap log WITHOUT CVSS header -> must stay `Chưa xác định` (zero invented severity/score!)
        raw_sqlmap = (
            "Target URL: http://198.51.100.55/vulnerabilities/sqli/?id=1&Submit=Submit\n"
            "[11:21:57] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks\n"
            "[11:21:57] [WARNING] reflective value(s) found and filtering out\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: error-based\n"
            "    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)\n"
            "    Payload: id=1' AND EXTRACTVALUE(5879,CONCAT(0x5c,0x7170787671,1))-- nWty&Submit=Submit\n"
            "---\n"
            "web application technology: Apache 2.4.25, PHP 7.0.33\n"
            "back-end DBMS: MySQL >= 5.1 (MariaDB fork)\n"
            "current user: 'app@localhost'\n"
            "current database: 'dvwa'\n"
            "current user is DBA: False\n"
            "available databases [2]:\n"
            "[*] dvwa\n"
            "[*] information_schema\n"
            "Database: dvwa\n"
            "[2 tables]\n"
            "+-----------+\n"
            "| guestbook |\n"
            "| users     |\n"
            "+-----------+\n"
            "HTTP request [#239]:\n"
            "GET /vulnerabilities/sqli/?id=1%27%20AND%20EXTRACTVALUE%285879%2C1%29--%20nWty&Submit=Submit HTTP/1.1\n"
            "Host: 198.51.100.55\n"
            "Cookie: PHPSESSID=supersecretcookie123; security=low\n\n"
            "HTTP response [#239] (200 OK):\n"
            "HTTP/1.1 200 OK\n"
            "<pre>XPATH syntax error: '\\qpxvq1'</pre>\n"
            "############################################################################\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            log_file = tmp_p / "raw_sqlmap.txt"
            log_file.write_text(raw_sqlmap, encoding="utf-8")
            parsed = load_findings(log_file, "sqlmap-log")
            rows = []
            for f in parsed:
                row = {
                    "id": f.id,
                    "title": f.title,
                    "cwe": f.cwe,
                    "severity": f.severity,
                    "tool": f.tool,
                    "location": f.location,
                    "kind": f.kind,
                    "evidence": list(f.evidence),
                    "details": dict(f.details),
                    "guidance": [],
                }
                row["owasp_top10"] = classify(row)
                if f.cwe == "CWE-89":
                    row["guidance"] = [{
                        "section": "Query Parameterization Cheat Sheet / Using PHP PDO",
                        "title": "Query Parameterization Cheat Sheet",
                        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
                        "excerpt": (
                            "Use PDO prepared statements with bound parameters:\n"
                            "```php\n"
                            "$stmt = $dbh->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');\n"
                            "$stmt->bindParam(':id', $id, PDO::PARAM_INT);\n"
                            "$stmt->execute();\n"
                            "```\n"
                        ),
                    }]
                rows.append(row)

            report = {
                "schema_version": 1,
                "generated_at": "2026-10-22T10:30:00+00:00",
                "mode": "ollama-top10-analysis-extractive",
                "model": "ollama/qwen2.5:7b",
                "input_format": "sqlmap-log",
                "input_filename": "raw_sqlmap.txt",
                "scan_sha256": "e" * 64,
                "knowledge_sha256": "f" * 64,
                "findings": rows,
                "report_metadata": {
                    "report_id": "RPT-DBSEC-TEST-01",
                    "project_name": "Đề tài Kiểm thử Bảo mật CSDL",
                },
            }

            model = prepare_dbsec_report(report)
            # Table 4.1 must strictly mirror each record's native severity with zero invented High/Critical/Medium/Low
            matrix_dict = {sev: (c, t, ins) for sev, c, t, ins in model["matrix_rows"]}
            for named_sev in ("Critical", "High", "Medium", "Low"):
                self.assertEqual(matrix_dict[named_sev], (0, 0, 0))
            self.assertEqual(matrix_dict["Informational"], (0, 1, 0))
            self.assertEqual(matrix_dict["Chưa xác định"], (1, 0, 0))

            md = render_dbsec_markdown(report)
            for heading in (
                "# BÁO CÁO KIỂM THỬ BẢO MẬT CSDL VÀ ĐỀ XUẤT REMEDIATION THEO OWASP",
                "## 1. Thông tin chung",
                "## 2. Đánh giá dữ liệu đầu vào",
                "### 2.1. Nguồn dữ liệu",
                "### 2.2. Chất lượng dữ liệu",
                "## 3. Phương pháp phân tích",
                "## 4. Tóm tắt kết quả",
                "### 4.1. Tổng quan phát hiện",
                "### 4.2. Nhận xét tổng quan",
                "## 5. Danh sách phát hiện",
                "## 6. Phân tích chi tiết phát hiện",
                "#### 6.1. Trạng thái phát hiện",
                "#### 6.2. Vị trí và thành phần bị ảnh hưởng",
                "#### 6.3. Bằng chứng",
                "#### 6.4. Phân loại OWASP",
                "#### 6.5. Đánh giá mức độ nghiêm trọng",
                "#### 6.6. Nguyên nhân",
                "#### 6.7. Ảnh hưởng tiềm tàng",
                "## 7. Đề xuất remediation",
                "#### 7.1. Mục tiêu khắc phục",
                "#### 7.2. Biện pháp đề xuất",
                "#### 7.3. Cơ sở của đề xuất",
                "#### 7.4. Ưu tiên khắc phục",
                "#### 7.5. Kế hoạch kiểm tra lại",
                "## 8. Giới hạn và độ tin cậy của báo cáo",
                "### 8.1. Giới hạn",
                "### 8.2. Những nội dung cần xác minh",
                "### 8.3. Độ tin cậy",
                "## 9. Kết luận",
                "## 10. Phụ lục",
            ):
                self.assertIn(heading, md)

            # Target IP kept verbatim; cookie redacted; PDO safe code extracted from RAG; retest honest
            self.assertIn("198.51.100.55", md)
            self.assertNotIn("supersecretcookie123", md)
            self.assertIn("[REDACTED]", md)
            self.assertIn("$stmt->bindParam(':id'", md)
            self.assertIn("**Kết quả kiểm tra:** Chưa thực hiện", md)
            self.assertIn("không khẳng định hệ thống đã an toàn", md)
            self.assertIn("A05:2025 - Injection", md)
            self.assertNotIn("A05:2025 - A05:2025", md)

            rendered_paras = []
            orig_para = __import__("reportlab.platypus", fromlist=["Paragraph"]).Paragraph
            with patch("reportlab.platypus.Paragraph", side_effect=lambda t, *a, **k: (rendered_paras.append(str(t)), orig_para(t, *a, **k))[1]):
                pdf_path = render_pdf(report, tmp_p / "coursework.pdf")
            self.assertTrue(pdf_path.is_file() and pdf_path.read_bytes().startswith(b"%PDF-"))
            pdf_txt = __import__("html").unescape("\n".join(rendered_paras))
            self.assertIn("RPT-DBSEC-TEST-01", pdf_txt)
            self.assertIn("F-01:", pdf_txt)
            self.assertIn("F-02:", pdf_txt)
            self.assertIn("E-01", pdf_txt)
            self.assertIn("$stmt->bindParam", pdf_txt)

    def test_web_ui_rebrand_and_multifile_bundle_export_end_to_end(self):
        # Verify zero AuditNote / audit-trail leftovers in UI or backend modules
        for rel in (
            "src/rag/web/index.html",
            "src/rag/web/app.js",
            "src/rag/web/style.css",
            "src/rag/web_server.py",
            "src/rag/dbsec_report.py",
            "src/rag/pdf_report.py",
            "src/rag/llm.py",
        ):
            content = (ROOT / rel).read_text(encoding="utf-8")
            for legacy in ("AuditNote", "auditnote", "audit-log", "bao-cao-pentest"):
                self.assertNotIn(legacy, content, f"Legacy string {legacy!r} found in {rel}")

        html_src = (ROOT / "src/rag/web/index.html").read_text(encoding="utf-8")
        for field_id in (
            "meta-report_id",
            "meta-project_name",
            "meta-target_object",
            "meta-dbms_override",
            "meta-assessment_period",
            "meta-retest_status",
            "meta-retest_evidence",
            "meta-force_fresh_ai",
        ):
            self.assertIn(field_id, html_src)
            self.assertIn(field_id.removeprefix("meta-"), META_FIELDS)

        # End-to-end HTTP test of multi-file bundle I-01 + I-02 + I-03 (including missing evidence & unmapped CWE)
        zap_bytes = json.dumps({
            "@version": "2.15.0",
            "site": [{
                "@name": "http://203.0.113.20:8080",
                "alerts": [{
                    "pluginid": "40018",
                    "alert": "SQL Injection - PostgreSQL",
                    "riskcode": "3",
                    "cweid": "89",
                    "instances": [{
                        "uri": "http://203.0.113.20:8080/orders?sort=price",
                        "method": "GET",
                        "param": "sort",
                        "evidence": "PSQLException: syntax error at or near",
                    }],
                }],
            }],
        }).encode("utf-8")

        nmap_bytes = (
            '<?xml version="1.0"?>'
            '<nmaprun scanner="nmap" args="nmap -sV -p 5432 203.0.113.20">'
            '<host><address addr="203.0.113.20" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="5432">'
            '<state state="open"/><service name="postgresql" product="PostgreSQL DB" version="15.2"/>'
            '</port></ports></host></nmaprun>'
        ).encode("utf-8")

        norm_bytes = json.dumps({
            "schema_version": 1,
            "tool": "custom-db-check",
            "findings": [{
                "id": "NOEV-1",
                "title": "Unverified DB Config Check",
                "cwe": "CWE-9999",
                "severity": "low",
                "location": "203.0.113.20:5432",
                "evidence": [],
            }],
        }).encode("utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            mgr = JobManager(Path(tmp) / "jobs", demo=True)
            srv = LocalServer(("127.0.0.1", 0), mgr)
            port = srv.server_address[1]
            import threading
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                base = f"http://127.0.0.1:{port}"
                with opener.open(f"{base}/") as r0:
                    cookie_hdr = r0.headers.get("Set-Cookie", "").split(";", 1)[0]
                    home_html = r0.read().decode("utf-8")
                    self.assertIn("DBSec OWASP", home_html)

                cfg_req = urllib.request.Request(f"{base}/api/config", headers={"Cookie": cookie_hdr})
                with opener.open(cfg_req) as rc:
                    cfg = json.loads(rc.read().decode("utf-8"))
                tok = cfg["token"]

                qs = urllib.parse.urlencode({
                    "bundle": "1",
                    "filename": "zap.json + nmap.xml + check.json",
                    "format": "auto",
                    "note": "Phạm vi kiểm thử Lab PostgreSQL nội bộ",
                    "metadata": json.dumps({"project_name": "Kiểm thử Đa công cụ CSDL"}),
                })
                bundle_body = json.dumps({
                    "bundle_version": 1,
                    "files": [
                        {"filename": "zap_pg.json", "format": "auto", "content_b64": base64.b64encode(zap_bytes).decode()},
                        {"filename": "nmap_pg.xml", "format": "auto", "content_b64": base64.b64encode(nmap_bytes).decode()},
                        {"filename": "noev.json", "format": "auto", "content_b64": base64.b64encode(norm_bytes).decode()},
                    ],
                }).encode("utf-8")
                post_req = urllib.request.Request(
                    f"{base}/api/jobs?{qs}",
                    data=bundle_body,
                    method="POST",
                    headers={
                        "Cookie": cookie_hdr,
                        "X-App-Token": tok,
                        "Content-Type": "application/json; charset=utf-8",
                    },
                )
                with opener.open(post_req) as rp:
                    created = json.loads(rp.read().decode("utf-8"))
                jid = created["id"]

                for _ in range(40):
                    with opener.open(urllib.request.Request(f"{base}/api/jobs/{jid}", headers={"Cookie": cookie_hdr})) as rj:
                        cur = json.loads(rj.read().decode("utf-8"))
                    if cur["status"] in {"completed", "partial", "failed"}:
                        break
                    time.sleep(0.1)
                self.assertEqual(cur["status"], "completed")
                self.assertEqual(cur["summary"]["confirmed_findings"], 1)
                self.assertEqual(cur["summary"]["tentative_findings"], 1)
                self.assertEqual(cur["summary"]["insufficient_findings"], 1)

                with opener.open(urllib.request.Request(f"{base}/api/jobs/{jid}/md", headers={"Cookie": cookie_hdr})) as rmd:
                    disp_md = rmd.headers.get("Content-Disposition", "")
                    md_body = rmd.read().decode("utf-8")
                self.assertIn(f"bao-cao-bao-mat-csdl-{jid[:8]}.md", disp_md)
                self.assertIn("| I-01 | `zap_pg.json` |", md_body)
                self.assertIn("| I-02 | `nmap_pg.xml` |", md_body)
                self.assertIn("| I-03 | `noev.json` |", md_body)
                self.assertIn("**Danh mục:** Chưa xác định", md_body)
                self.assertIn("Chưa đủ dữ liệu", md_body)
                self.assertIn("Có dấu hiệu", md_body)
                self.assertIn("Đã xác nhận", md_body)

                with opener.open(urllib.request.Request(f"{base}/api/jobs/{jid}/pdf", headers={"Cookie": cookie_hdr})) as rpdf:
                    disp_pdf = rpdf.headers.get("Content-Disposition", "")
                    pdf_bytes = rpdf.read()
                self.assertIn(f"bao-cao-bao-mat-csdl-{jid[:8]}.pdf", disp_pdf)
                self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
            finally:
                srv.shutdown()
                srv.server_close()
                mgr.close()

    def test_cross_input_dynamic_generation_zero_hardcoding_across_distinct_scans(self):
        """Prove every section dynamically adapts to input facts with zero false error/cookie/SQL/GRANT assumptions."""
        from rag.dbsec_report import render_dbsec_markdown
        from rag.top10 import classify

        # 1) Blind time-based SQLi with NO SQL syntax error in HTTP response and NO cookies/secrets
        blind_row = {
            "id": "BLIND-1",
            "title": "Blind SQL Injection",
            "cwe": "CWE-89",
            "severity": "unknown",
            "tool": "sqlmap",
            "location": "http://198.51.100.88/search?q=book",
            "kind": "scanner_alert",
            "evidence": ["Parameter: q (GET)\n    Type: time-based blind\n    Payload: q=book' AND SLEEP(5)-- -"],
            "details": {
                "parameter": "q",
                "method": "GET",
                "techniques": ["time-based blind"],
                "request": "GET /search?q=book%27%20AND%20SLEEP%285%29--%20- HTTP/1.1\nHost: 198.51.100.88",
                "response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>Results: 0</html>",
            },
            "guidance": [],
            "ai_analysis": {
                "status": "ai_reviewed",
                "claims": {
                    "observations": [
                        {"text_vi": "Công cụ sqlmap xác nhận độ trễ phản hồi 5 giây lặp lại ổn định trên tham số q."},
                        {"text_vi": "Phản hồi HTTP 200 không trả về chuỗi lỗi cú pháp CSDL trực tiếp."},
                        {"text_vi": "Điểm tiêm nằm trên truy vấn tìm kiếm GET không đính kèm cookie phiên."},
                    ],
                    "potential_impacts": [
                        {"text_vi": "Nếu kẻ tấn công tự động hóa khai thác mù theo thời gian, dữ liệu nhạy cảm trong bảng có thể bị dò từng ký tự."}
                    ],
                    "limitations": [
                        {"text_vi": "Chưa liệt kê danh sách bảng do kiểm thử dừng ở bước chứng minh độ trễ an toàn."}
                    ],
                },
            },
        }
        blind_row["owasp_top10"] = classify(blind_row)
        md_blind = render_dbsec_markdown({
            "schema_version": 1,
            "mode": "ollama-top10-analysis-extractive",
            "model": "ollama/qwen2.5:7b",
            "input_format": "sqlmap-log",
            "input_filename": "blind_sqli.txt",
            "scan_sha256": "11223344" * 8,
            "knowledge_sha256": "99887766" * 8,
            "findings": [blind_row],
        })
        self.assertIn("time-based blind", md_blind)
        self.assertNotIn("để lộ trực tiếp thông báo ngoại lệ CSDL ra phản hồi HTTP", md_blind)
        self.assertNotIn("[REDACTED]", md_blind)
        # All 3 Ollama observations + potential impact + limitation surface dynamically
        self.assertIn("độ trễ phản hồi 5 giây", md_blind)
        self.assertIn("Phản hồi HTTP 200 không trả về chuỗi lỗi cú pháp CSDL trực tiếp.", md_blind)
        self.assertIn("Điểm tiêm nằm trên truy vấn tìm kiếm GET", md_blind)
        self.assertIn("dò từng ký tự", md_blind)

        # 2) Pure TLS/network finding with native Medium severity + code-only TLS Cheat Sheet block (ZERO SQL/GRANT)
        tls_row = {
            "id": "NESSUS-TLS-1",
            "title": "Database TLS Weak Cipher Suites Accepted",
            "cwe": "CWE-327",
            "severity": "medium",
            "tool": "nessus",
            "location": "203.0.113.77:3306",
            "kind": "scanner_alert",
            "evidence": ["Accepted cipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA on port 3306/tcp"],
            "details": {
                "port": 3306,
                "protocol": "tcp",
                "description": "Remote MySQL port accepts deprecated 3DES cipher suites",
                "solution": "Disable weak 3DES ciphers in mysqld TLS configuration",
                "cvss_score": "5.3",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            },
            "guidance": [{
                "section": "Transport Layer Protection Cheat Sheet / Only Support Strong Ciphers",
                "title": "Transport Layer Protection Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                "source_excerpt": "```nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\n```",
            }],
        }
        tls_row["owasp_top10"] = classify(tls_row)
        md_tls = render_dbsec_markdown({
            "schema_version": 1,
            "mode": "demo-no-ai",
            "model": "none",
            "input_format": "nessus",
            "input_filename": "db_tls.nessus",
            "scan_sha256": "55667788" * 8,
            "knowledge_sha256": "99887766" * 8,
            "findings": [tls_row],
        })
        self.assertIn("nhãn mức độ nghiêm trọng gốc đầy đủ trên toàn bộ phát hiện", md_tls)
        self.assertNotIn("nhãn mức độ nghiêm trọng / điểm CVSS gốc trên các bản ghi do công cụ dòng lệnh không tự gán điểm", md_tls)
        self.assertNotIn("tham số ràng buộc", md_tls)
        self.assertNotIn("lỗi cú pháp CSDL", md_tls)
        self.assertNotIn("GRANT", md_tls)
        self.assertIn("TLS 1.2/1.3", md_tls)
        self.assertIn("5.3", md_tls)

        # 3) Clean zero-finding scan
        md_clean = render_dbsec_markdown({
            "schema_version": 1,
            "mode": "demo-no-ai",
            "model": "none",
            "input_format": "nmap",
            "input_filename": "clean_scan.xml",
            "scan_sha256": "abcdef12" * 8,
            "knowledge_sha256": "not_used",
            "findings": [],
        })
        self.assertIn("Không ghi nhận cảnh báo lỗ hổng trong dữ liệu đầu vào", md_clean)
        self.assertNotIn("GRANT", md_clean)
        self.assertNotIn("nhật ký kiểm thử lại (retest) sau khi triển khai khắc phục", md_clean)

    def test_ai_pentest_report_reader_unmapped_cwe_classifier_nmap_and_zap_xml(self):
        """Verify direct Pentest Report AI reading (PDF/MD), AI unknown-CWE classification, ZAP XML & deep Nmap DB rules."""
        from rag.ai_ingest import (
            extract_findings_from_report_with_ai,
            extract_pentest_text,
            resolve_unmapped_findings_with_ai,
        )
        from rag.config import Settings
        from rag.parsers import load_findings
        from rag.parsers.native import parse_nmap
        from rag.pdf_report import render_pdf
        from rag.web_server import detect_format

        pentest_md = (
            "# Báo cáo Pentest Hệ thống CSDL Bán hàng\n"
            "Target: http://198.51.100.90/products?cat=books\n"
            "DBMS: PostgreSQL 15.4\n\n"
            "## 1. SQL Injection tại tham số cat\n"
            "Severity: High\n"
            "Payload thử nghiệm `cat=books' UNION SELECT current_user,version()--` trả về trực tiếp `postgres` trong bảng HTML.\n\n"
            "## 2. Tài khoản Redis nội bộ không mật khẩu\n"
            "Kết nối tới 198.51.100.90:6379 thực thi lệnh `INFO server` thành công mà không cần `AUTH`.\n"
        )

        class _MockReportReaderLLM:
            def generate(self, prompt, *, system="", schema=None):
                return json.dumps({
                    "metadata": {
                        "project_name": "Pentest Hệ thống CSDL Bán hàng",
                        "target_object": "http://198.51.100.90",
                        "dbms_override": "PostgreSQL 15.4; Redis",
                        "assessment_period": "",
                        "allowed_scope": "",
                    },
                    "findings": [
                        {
                            "title": "SQL Injection tại tham số cat",
                            "cwe": "CWE-89",
                            "severity": "high",
                            "state": "confirmed",
                            "location": "http://198.51.100.90/products?cat=books",
                            "parameter": "cat",
                            "method": "GET",
                            "tool": "manual-pentest",
                            "native_solution": "",
                            "evidence_quotes": [
                                "Payload thử nghiệm `cat=books' UNION SELECT current_user,version()--` trả về trực tiếp `postgres`",
                                "THIS QUOTE WAS HALLUCINATED BY MODEL AND MUST BE STRIPPED",
                            ],
                        },
                        {
                            "title": "Tài khoản Redis nội bộ không mật khẩu",
                            "cwe": "CWE-306",
                            "severity": "unknown",
                            "state": "confirmed",
                            "location": "198.51.100.90:6379",
                            "evidence_quotes": [
                                "Kết nối tới 198.51.100.90:6379 thực thi lệnh `INFO server` thành công"
                            ],
                        },
                    ],
                }, ensure_ascii=False)

        extracted_findings, extracted_meta = extract_findings_from_report_with_ai(
            pentest_md,
            "pentest_ec2.md",
            Settings(llm_provider="ollama", ollama_model="qwen2.5:7b"),
            llm=_MockReportReaderLLM(),
        )
        self.assertEqual(len(extracted_findings), 2)
        self.assertEqual(extracted_meta["project_name"], "Pentest Hệ thống CSDL Bán hàng")
        # Hallucinated second quote MUST be stripped deterministically while real verbatim quote survives
        self.assertEqual(len(extracted_findings[0].evidence), 1)
        self.assertEqual(extracted_findings[0].severity, "high")
        self.assertEqual(extracted_findings[1].cwe, "CWE-306")
        self.assertEqual(extracted_findings[1].severity, "unknown")

        # Unmapped custom NSE script (`ssl-enum-ciphers` on 3306) auto-classified by AI without hand-written rule
        raw_nmap = (
            b'<?xml version="1.0"?><nmaprun scanner="nmap" startstr="2026-10-22 09:00">'
            b'<host><status state="up"/><address addr="198.51.100.90" addrtype="ipv4"/><ports>'
            b'<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
            b'<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MariaDB"/>'
            b'<script id="mysql-databases"><elem>dvwa</elem><elem>information_schema</elem></script>'
            b'<script id="mysql-brute" output="&#xa;  Accounts:&#xa;    audit_lab:123456 - Valid credentials"/>'
            b'</port></ports>'
            b'<hostscript><script id="custom-db-tls-audit" output=" TLSv1.0 with 3DES cipher accepted on 3306"/></hostscript></host>'
            b'<runstats><finished timestr="2026-10-22 09:02"/></runstats></nmaprun>'
        )
        nmap_parsed = parse_nmap(raw_nmap, "ec2_db.xml")
        brute_alert = [f for f in nmap_parsed if f.details.get("scanner_rule") == "nmap-mysql-brute"][0]
        self.assertEqual(brute_alert.cwe, "CWE-521")
        self.assertEqual(brute_alert.details["scan_telemetry"]["databases"], ["dvwa", "information_schema"])

        class _MockUnmappedClassifierLLM:
            def generate(self, prompt, *, system="", schema=None):
                payload = json.loads(prompt)
                out = []
                for rec in payload["unmapped_records"]:
                    if "3DES cipher accepted" in rec["evidence"]:
                        out.append({
                            "id": rec["id"],
                            "is_weakness": True,
                            "state": "confirmed",
                            "cwe": "CWE-327",
                            "dbms": "MariaDB",
                            "quote": "TLSv1.0 with 3DES cipher accepted on 3306",
                        })
                    else:
                        out.append({
                            "id": rec["id"],
                            "is_weakness": False,
                            "state": "tentative",
                            "cwe": "unknown",
                            "dbms": "",
                            "quote": "",
                        })
                return json.dumps({"classifications": out})

        enriched_nmap = resolve_unmapped_findings_with_ai(
            nmap_parsed,
            Settings(llm_provider="ollama", ollama_model="qwen2.5:7b"),
            llm=_MockUnmappedClassifierLLM(),
        )
        host_tls = [f for f in enriched_nmap if f.id == "NMAP-H0-S0"][0]
        self.assertEqual((host_tls.cwe, host_tls.kind), ("CWE-327", "scanner_alert"))
        plain_http = [f for f in enriched_nmap if f.id == "NMAP-0-0"][0]
        self.assertEqual((plain_http.cwe, plain_http.kind), ("unknown", "observation"))

        # Verify ZAP XML (<OWASPZAPReport>) + PDF Pentest Report detection
        zap_xml = (
            b'<?xml version="1.0"?><OWASPZAPReport version="2.16.0" generated="Thu, 22 Oct 2026 09:15:00">'
            b'<site name="http://198.51.100.90" host="198.51.100.90" port="80" ssl="false"><alerts>'
            b'<alertitem><pluginid>40019</pluginid><alert>SQL Injection - MySQL</alert>'
            b'<riskcode>3</riskcode><confidence>2</confidence><cweid>89</cweid>'
            b'<desc>SQLi confirmed</desc><solution>Use prepared statements</solution>'
            b'<instances><instance><uri>http://198.51.100.90/vulnerabilities/sqli/?id=1</uri>'
            b'<method>GET</method><param>id</param><evidence>MariaDB server version</evidence>'
            b'<requestheader>GET /vulnerabilities/sqli/?id=1 HTTP/1.1\r\nCookie: PHPSESSID=secret999</requestheader>'
            b'</instance></instances></alertitem></alerts></site></OWASPZAPReport>'
        )
        with tempfile.TemporaryDirectory() as tmp:
            zx_path = Path(tmp) / "zap_ec2.xml"
            zx_path.write_bytes(zap_xml)
            self.assertEqual(detect_format(zx_path), "zap")
            zx_findings = load_findings(zx_path, "zap")
            self.assertEqual(len(zx_findings), 1)
            self.assertEqual((zx_findings[0].cwe, zx_findings[0].severity, zx_findings[0].details.get("dbms")), ("CWE-89", "high", "MySQL"))

            md_path = Path(tmp) / "pentest_report.md"
            md_path.write_text(pentest_md, encoding="utf-8")
            self.assertEqual(detect_format(md_path), "pentest-report")
            self.assertEqual(len(load_findings(md_path, "pentest-report")), 2)

            pdf_path = Path(tmp) / "sample_pentest.pdf"
            render_pdf({"findings": [], "input_filename": "sample"}, pdf_path)
            self.assertEqual(detect_format(pdf_path), "pentest-report")
            pdf_txt = extract_pentest_text(pdf_path)
            self.assertTrue(len(pdf_txt) > 30)


if __name__ == "__main__":
    unittest.main()
