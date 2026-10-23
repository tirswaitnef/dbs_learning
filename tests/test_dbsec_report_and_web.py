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
                # Passive Nmap service/banner observations belong in Section 3, not the finding/triage counters.
                self.assertEqual(cur["summary"]["tentative_findings"], 0)
                self.assertEqual(cur["summary"]["insufficient_findings"], 1)

                # Default `/md` serves the 6-section `Template báo cáo pentest gọn.pdf` Markdown
                with opener.open(urllib.request.Request(f"{base}/api/jobs/{jid}/md", headers={"Cookie": cookie_hdr})) as rmd:
                    disp_md = rmd.headers.get("Content-Disposition", "")
                    md_body = rmd.read().decode("utf-8")
                self.assertIn(f"bao-cao-bao-mat-csdl-{jid[:8]}.md", disp_md)
                for sec_h in (
                    "## 1. Tóm tắt",
                    "## 2. Chi tiết phát hiện",
                    "## 3. Quan sát (chưa phải lỗ hổng)",
                    "## 4. Kết quả âm tính",
                    "## 5. Giới hạn & việc cần xác minh",
                    "## 6. Phụ lục",
                ):
                    self.assertIn(sec_h, md_body)
                self.assertNotIn("Quy tắc điền", md_body)
                # Passive Nmap open port goes strictly into Section 3 without CWE; Nmap command recorded in Section 6
                sec3_md = md_body.split("## 3. Quan sát (chưa phải lỗ hổng)", 1)[1].split("## 4. Kết quả âm tính", 1)[0]
                self.assertIn("PostgreSQL DB 15.2", sec3_md)
                self.assertNotIn("CWE-", sec3_md)
                self.assertIn("nmap -sV -p 5432 203.0.113.20", md_body)
                self.assertIn("I-01 zap_pg.json", md_body)
                self.assertIn("I-02 nmap_pg.xml", md_body)
                self.assertIn("I-03 noev.json", md_body)

                # Secondary `?profile=full` serves the 10-section Full Audit Markdown
                with opener.open(urllib.request.Request(f"{base}/api/jobs/{jid}/md?profile=full", headers={"Cookie": cookie_hdr})) as rmd_full:
                    md_full_body = rmd_full.read().decode("utf-8")
                self.assertIn("| I-01 | `zap_pg.json` |", md_full_body)
                self.assertIn("| I-02 | `nmap_pg.xml` |", md_full_body)
                self.assertIn("| I-03 | `noev.json` |", md_full_body)
                self.assertIn("**Danh mục:** Chưa xác định", md_full_body)
                self.assertIn("Chưa đủ dữ liệu", md_full_body)
                self.assertIn("Có dấu hiệu", md_full_body)
                self.assertIn("Đã xác nhận", md_full_body)

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

    def test_universal_ai_first_reads_modified_sqlmap_nmap_on_text_and_arbitrary_web_scans(self):
        """Prove Ollama directly reads ANY tool output format (modified sqlmap, nmap -oN text, custom JSON) without rigid regex dependence."""
        import base64
        from rag.config import Settings
        from rag.official_report import run_corpus_report
        from rag.web_server import JobManager

        # 1) Non-standard sqlmap console snippet starting with `[10:15:02] [INFO]` (NO `Parameter: ... (GET)` block!)
        #    on an unfamiliar REST API target `POST https://shop-erp.example.test/api/v2/orders/search` (`Oracle 19c`)
        modified_sqlmap_console = (
            "[10:15:02] [INFO] testing connection to target URL 'https://shop-erp.example.test/api/v2/orders/search'\n"
            "[10:15:09] [INFO] JSON parameter 'sortBy' appears to be 'Oracle AND error-based' injectable\n"
            "POST /api/v2/orders/search HTTP/1.1\n"
            "Host: shop-erp.example.test\n"
            "Content-Type: application/json\n\n"
            "{\"sortBy\": \"created_at' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--\"}\n"
            "HTTP/1.1 500 Internal Server Error\n"
            "ORA-20000: Oracle Text error: DRG-11701: thesaurus Oracle Database 19c Enterprise Edition does not exist\n"
            "[10:15:14] [INFO] back-end DBMS operating version: Oracle Database 19c\n"
            "[10:15:16] [INFO] current user: 'ERP_APP'\n"
            "[10:15:18] [INFO] schemas discovered: ERP_CORE, HR_RECORDS\n"
        ).encode("utf-8")

        # 2) Plain-text `nmap -oN` output (NOT XML!) + custom internal Python scanner JSON
        nmap_normal_text = (
            "# Nmap 7.95 scan initiated Thu Oct 22 10:30:00 2026\n"
            "Nmap scan report for 203.0.113.77\n"
            "PORT     STATE SERVICE    VERSION\n"
            "5432/tcp open  postgresql PostgreSQL DB 16.2\n"
            "| pgsql-brute:\n"
            "|   postgres:postgres => Valid credentials\n"
        ).encode("utf-8")

        custom_web_json = json.dumps({
            "scanner_engine": "internal-graphql-sec-check-v3",
            "endpoint": "https://api-portal.example.test/graphql",
            "issue_found": "GraphQL argument `customerCode` leaked SQLite syntax error: near \"'\": syntax error",
        }, ensure_ascii=False).encode("utf-8")

        class _UniversalAIReaderMock:
            def generate(self, prompt, *, system="", schema=None):
                props = (schema or {}).get("properties") or {}
                data = json.loads(prompt)
                if "findings" in props and "metadata" in props:
                    txt = data["input_text"]
                    if "Oracle Database 19c" in txt:
                        return json.dumps({
                            "metadata": {
                                "tool_name": "sqlmap (custom JSON session)",
                                "project_name": "",
                                "target_object": "https://shop-erp.example.test/api/v2/orders/search",
                                "dbms_override": "Oracle Database 19c",
                                "assessment_period": "10:15:02 - 10:15:18",
                                "allowed_scope": "",
                                "databases": ["ERP_CORE", "HR_RECORDS"],
                                "db_user": "ERP_APP",
                            },
                            "findings": [{
                                "title": "SQL Injection error-based trên tham số JSON sortBy (POST /api/v2/orders/search)",
                                "cwe": "CWE-89",
                                "severity": "unknown",
                                "state": "confirmed",
                                "location": "https://shop-erp.example.test/api/v2/orders/search",
                                "parameter": "sortBy",
                                "method": "POST",
                                "tool": "sqlmap",
                                "request_snippet": "POST /api/v2/orders/search HTTP/1.1\nHost: shop-erp.example.test",
                                "response_snippet": "ORA-20000: Oracle Text error: DRG-11701: thesaurus Oracle Database 19c Enterprise Edition does not exist",
                                "evidence_quotes": [
                                    "JSON parameter 'sortBy' appears to be 'Oracle AND error-based' injectable",
                                    "ORA-20000: Oracle Text error: DRG-11701: thesaurus Oracle Database 19c Enterprise Edition does not exist",
                                ],
                            }],
                        }, ensure_ascii=False)
                    if "PostgreSQL DB 16.2" in txt:
                        return json.dumps({
                            "metadata": {
                                "tool_name": "Nmap -oN",
                                "project_name": "",
                                "target_object": "203.0.113.77:5432",
                                "dbms_override": "PostgreSQL 16.2",
                                "assessment_period": "Thu Oct 22 10:30:00 2026",
                                "allowed_scope": "",
                            },
                            "findings": [{
                                "title": "Mật khẩu mặc định postgres:postgres trên dịch vụ PostgreSQL 5432/tcp",
                                "cwe": "CWE-521",
                                "severity": "unknown",
                                "state": "confirmed",
                                "location": "203.0.113.77:5432/tcp",
                                "tool": "Nmap",
                                "evidence_quotes": ["postgres:postgres => Valid credentials"],
                            }],
                        }, ensure_ascii=False)
                    return json.dumps({
                        "metadata": {
                            "tool_name": "internal-graphql-sec-check-v3",
                            "project_name": "",
                            "target_object": "https://api-portal.example.test/graphql",
                            "dbms_override": "SQLite",
                            "assessment_period": "",
                            "allowed_scope": "",
                        },
                        "findings": [{
                            "title": "Rò rỉ lỗi cú pháp SQLite qua tham số GraphQL customerCode",
                            "cwe": "CWE-89",
                            "severity": "unknown",
                            "state": "confirmed",
                            "location": "https://api-portal.example.test/graphql",
                            "parameter": "customerCode",
                            "tool": "internal-graphql-sec-check-v3",
                            "evidence_quotes": ["GraphQL argument `customerCode` leaked SQLite syntax error"],
                        }],
                    }, ensure_ascii=False)
                if "source_ids" in props:
                    cands = data.get("candidates") or []
                    return json.dumps({"source_ids": [cands[0]["source_id"]] if cands else []})
                if "supported" in props:
                    return json.dumps({
                        "supported": True,
                        "no_remediation": True,
                        "appropriately_uncertain": True,
                        "database_specific": True,
                    })
                if "observations" in props:
                    sources = data["sources"]
                    sid = next(iter(sources))
                    quote = sources[sid].strip().splitlines()[0][:80]
                    c = {"text_vi": "AI đã phân tích trực tiếp dữ liệu đầu vào từ mục tiêu mới.", "citations": [{"source_id": sid, "quote": quote}]}
                    return json.dumps({"observations": [c], "potential_impacts": [c], "limitations": [c]}, ensure_ascii=False)
                return json.dumps({"items": [{"finding_id": it["finding_id"], "guidance_ids": [it["candidates"][0]["id"]] if it["candidates"] else []} for it in data]})

        class _FakeEncoder:
            model_name = "intfloat/multilingual-e5-small"
            revision = None

            def embed_documents(self, texts):
                return [[1.0, 0.2, 0.1] for _ in texts]

            def embed_query(self, text):
                return [1.0, 0.2, 0.1]

        from rag.document_store import ingest_documents
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            raw_cs = tmp_dir / "cs"
            raw_cs.mkdir()
            (raw_cs / "SQL_Injection_Prevention_Cheat_Sheet.md").write_text(
                "# SQL Injection Prevention Cheat Sheet\n\nUse prepared statements with bind variables on Oracle, PostgreSQL, and SQLite.\n",
                encoding="utf-8",
            )
            (raw_cs / "Database_Security_Cheat_Sheet.md").write_text(
                "# Database Security Cheat Sheet\n\nChange default postgres administrative credentials immediately and restrict network access.\n",
                encoding="utf-8",
            )
            store_dir = tmp_dir / "store"
            settings = Settings(llm_provider="ollama", ollama_model="qwen2.5:7b")
            ingest_documents(raw_cs, store_dir, settings, embedder=_FakeEncoder())

            def runner(scan_path, out_dir, job, progress):
                with unittest.mock.patch("rag.official_report.OllamaLLM", return_value=_UniversalAIReaderMock()), \
                     unittest.mock.patch("rag.embeddings.E5Embedding", return_value=_FakeEncoder()):
                    return run_corpus_report(
                        scan_path,
                        out_dir,
                        settings,
                        raw_directory=raw_cs,
                        store_directory=store_dir,
                        format_=job["format"],
                        offline=True,
                        progress=progress,
                        report_metadata=job.get("report_metadata"),
                        display_filename=job["filename"],
                    )

            mgr = JobManager(tmp_dir / "jobs", settings_loader=lambda: settings, runner=runner)
            try:
                # Single modified sqlmap file starting with `[10:15:02] [INFO]` -> 100% read by AI!
                j1 = mgr.submit(modified_sqlmap_console, "sqlmap_oracle_rest.log", "auto")
                for _ in range(60):
                    cur1 = mgr.get(j1["id"])
                    if cur1["status"] in {"completed", "partial", "failed"}:
                        break
                    import time
                    time.sleep(0.03)
                self.assertEqual(cur1["status"], "completed", msg=cur1.get("error"))
                md1 = (tmp_dir / "jobs" / j1["id"] / "output" / "dbsec_report.md").read_text(encoding="utf-8")
                self.assertIn("Oracle Database 19c", md1)
                self.assertIn("https://shop-erp.example.test/api/v2/orders/search", md1)
                self.assertIn("ORA-20000", md1)
                self.assertIn("Chưa xác định", md1)

                # Multi-file bundle of `nmap -oN` text + custom GraphQL JSON -> both read directly by AI!
                j2 = mgr.submit_bundle({
                    "bundle_version": 1,
                    "files": [
                        {"filename": "nmap_text_scan.txt", "format": "auto", "content_b64": base64.b64encode(nmap_normal_text).decode("ascii")},
                        {"filename": "custom_graphql_scan.json", "format": "auto", "content_b64": base64.b64encode(custom_web_json).decode("ascii")},
                    ],
                })
                for _ in range(60):
                    cur2 = mgr.get(j2["id"])
                    if cur2["status"] in {"completed", "partial", "failed"}:
                        break
                    import time
                    time.sleep(0.03)
                self.assertEqual(cur2["status"], "completed", msg=cur2.get("error"))
                md2 = (tmp_dir / "jobs" / j2["id"] / "output" / "dbsec_report.md").read_text(encoding="utf-8")
                trace2 = json.loads((tmp_dir / "jobs" / j2["id"] / "output" / "ai_trace.json").read_text(encoding="utf-8"))
                self.assertIn("203.0.113.77:5432", md2)
                self.assertIn("https://api-portal.example.test/graphql", md2)
                self.assertTrue(any("Đọc & phân tích trực tiếp tệp đầu vào bằng AI" in e["step"] for e in trace2["entries"]))
            finally:
                mgr.executor.shutdown(wait=True)

    def test_compact_vs_full_profile_caps_dedup_http_minify_and_3_page_budget(self):
        """Regression test ensuring 1 real finding + 1 tentative note renders in 2–4 crisp pages with zero bloat."""
        from pypdf import PdfReader
        from rag.analysis import compress_report_post_extract

        class _CompressMockLLM:
            def generate(self, prompt, *, system="", schema=None):
                payload = json.loads(prompt)
                return json.dumps({
                    "items": [
                        {
                            "id": it["id"],
                            "summary_vi": "Sử dụng truy vấn tham số hóa (Prepared Statements / PDO bindParam) để tách biệt dữ liệu đầu vào khỏi câu lệnh SQL.",
                        }
                        for it in payload.get("items", [])
                    ]
                }, ensure_ascii=False)

        f1 = {
            "id": "AI-01",
            "title": "SQL Injection in GET parameter 'id' via boolean-based blind (OR clause with NOT)",
            "cwe": "CWE-89",
            "severity": "high",
            "tool": "ai-extracted",
            "location": "http://198.51.100.79/vulnerabilities/sqli/?id=1&Submit=Submit (parameter=id, GET)",
            "kind": "scanner_alert",
            "evidence": [
                "Parameter: id (GET)\n    Type: boolean-based blind\n    Payload: id=1' OR NOT 5452=5452-- -&Submit=Submit",
                "    Type: error-based\n    Payload: id=1' AND EXTRACTVALUE(5879,CONCAT(0x5c,0x7170787671,1))-- nWty&Submit=Submit",
                "    Type: time-based blind\n    Payload: id=1' AND SLEEP(2)-- -&Submit=Submit",
            ],
            "details": {
                "techniques": ["boolean-based blind", "error-based", "time-based blind", "UNION query"],
                "dbms": "MySQL >= 5.0.12",
                "http_messages": [
                    {
                        "id": "#1008",
                        "request": "GET /vulnerabilities/sqli/?id=1&Submit=Submit%60%29%20OR%20NOT%205452%3D5452%23 HTTP/1.1\nCache-Control: no-cache\nUser-Agent: sqlmap/1.10\nAccept-Encoding: gzip,deflate\nConnection: close\nHost: 198.51.100.79",
                        "response": "HTTP/1.1 200 OK\nCache-Control: no-cache\n<pre>ID: 1</pre>",
                    },
                    {
                        "id": "#239",
                        "request": "GET /vulnerabilities/sqli/?id=1%27%20AND%20EXTRACTVALUE%285879%2C1%29--%20nWty&Submit=Submit HTTP/1.1\nCache-Control: no-cache\nCookie: PHPSESSID=topsecret999; security=low\nUser-Agent: sqlmap/1.10\nAccept-Encoding: gzip,deflate\nConnection: close\nHost: 198.51.100.79",
                        "response": "HTTP/1.1 200 OK\nDate: Thu, 22 Oct 2026 04:22:09 GMT\nServer: Apache/2.4.25 (Debian)\nCache-Control: no-store, no-cache\nContent-Type: text/html; charset=UTF-8\n[... HTML giao dien DVWA rut gon ...]\n<pre>XPATH syntax error: '\\qpxvq1qpjxq'</pre>",
                    },
                    {
                        "id": "#3838",
                        "request": "GET /vulnerabilities/sqli/?id=1&Submit=Submit%2CSLEEP%282%29 HTTP/1.1\nHost: 198.51.100.79",
                        "response": "HTTP/1.1 200 OK\n<pre>ID: 1</pre>",
                    },
                ],
                "scan_telemetry": {
                    "dbms": "MySQL >= 5.1 (MariaDB fork)",
                    "web_tech": "Apache 2.4.25, PHP 7.0.33",
                    "os_banner": "Linux Debian 9 (stretch)",
                    "scan_start": "11:21:57 /2026-10-22/ to 11:28:12 /2026-10-22/",
                    "scan_end": "2026-10-22 11:28:12",
                    "current_user": "app@localhost",
                    "current_db": "dvwa",
                    "is_dba": False,
                    "databases": ["dvwa", "information_schema"],
                    "tables_by_db": {"dvwa": ["guestbook", "users"]},
                    "auth_context": "Cookie phiên đã đăng nhập (security=low)",
                    "unmatched_http_ids": ["#1008", "#3838"],
                },
            },
            "guidance": [
                {"section": "Injection Prevention Cheat Sheet / Defense Option 1: Prepared Statements", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html", "source_excerpt": "Prepared statements ensure that an attacker is not able to change the intent of a query."},
                {"section": "Query Parameterization Cheat Sheet / Using PHP with PHP Data Objects", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html", "source_excerpt": "Example PHP PDO:\n```php\n$stmt = $dbh->prepare('SELECT first_name FROM users WHERE user_id = :id');\n$stmt->bindParam(':id', $id, PDO::PARAM_INT);\n```"},
                {"section": "SQL Injection Prevention Cheat Sheet / Additional Defenses / Least Privilege", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "source_excerpt": "Minimize database privileges assigned to every application account."},
                {"section": "SQL Injection Prevention Cheat Sheet / Additional Defenses / Allow-list Input Validation", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "source_excerpt": "Input validation acts as a secondary defense."},
                {"section": "Error Handling Cheat Sheet / Objective", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html", "source_excerpt": "Return generic error messages to users and log details server-side."},
            ],
        }
        f1["owasp_top10"] = classify(f1)

        f2 = {
            "id": "SQLMAP-OBS-1",
            "title": "Heuristic XSS indicator",
            "cwe": "CWE-79",
            "severity": "info",
            "tool": "sqlmap",
            "location": "http://198.51.100.79/vulnerabilities/sqli/?id=1&Submit=Submit",
            "kind": "observation",
            "evidence": ["[11:21:57] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable"],
            "details": {"parameter": "id", "method": "GET", "confidence": "heuristic"},
            "guidance": [],
        }
        f2["owasp_top10"] = classify(f2)

        rep = {
            "schema_version": 1,
            "generated_at": "2026-10-23T01:40:00+00:00",
            "mode": "ollama-top10-analysis-extractive",
            "model": "ollama/qwen3:4b",
            "input_format": "sqlmap-log",
            "input_filename": "sqlmap_csdl_chuan_pentest.txt",
            "scan_sha256": "a201fb99" * 8,
            "knowledge_sha256": "830a0090" * 8,
            "findings": [f1, f2],
            "report_metadata": {
                "target_object": "http://198.51.100.79/vulnerabilities/sqli/?id=1&Submit=Submit; http://198.51.100.79/vulnerabilities/sqli/?id=1&Submit=Submit (parameter=id, GET)"
            },
        }
        compress_report_post_extract(rep, llm=_CompressMockLLM())

        m_comp = prepare_dbsec_report(rep, profile="compact")
        m_full = prepare_dbsec_report(rep, profile="full")

        # Hard caps in compact mode: max 2 evidences & max 2 OWASP refs per finding
        self.assertLessEqual(len(m_comp["findings"][0]["evidences"]), 2)
        self.assertLessEqual(len(m_comp["findings"][0]["rem_refs"]), 2)
        self.assertEqual(len(m_full["findings"][0]["rem_refs"]), 5)

        # Wrong-parameter packets (#1008, #3838) excluded; #239 proof kept & boilerplate HTTP headers stripped
        ev_snippets = "\n".join(e["snippet"] for e in m_comp["findings"][0]["evidences"])
        self.assertIn("#239", ev_snippets)
        self.assertIn("XPATH syntax error", ev_snippets)
        self.assertNotIn("[Request #1008]", ev_snippets)
        self.assertNotIn("[Request #3838]", ev_snippets)
        self.assertNotIn("Cache-Control:", ev_snippets)
        self.assertNotIn("Accept-Encoding:", ev_snippets)
        self.assertNotIn("topsecret999", ev_snippets)

        md_comp = render_dbsec_markdown(rep, profile="compact")
        self.assertNotIn("ai-extracted", md_comp)

        with tempfile.TemporaryDirectory() as tmp:
            p_comp = render_pdf(rep, Path(tmp) / "compact.pdf", profile="compact")
            p_full = render_pdf(rep, Path(tmp) / "full.pdf", profile="full")
            rc = PdfReader(str(p_comp))
            rf = PdfReader(str(p_full))
            self.assertGreaterEqual(len(rc.pages), 2)
            self.assertLessEqual(len(rc.pages), 4)
            self.assertLess(len(rc.pages), len(rf.pages))
            full_pdf_text = "\n".join(pg.extract_text() for pg in rc.pages)
            self.assertNotIn("ai-extracted", full_pdf_text)
            # General Info table rendered ONCE only (not duplicated between cover page and Section 1)
            self.assertEqual(full_pdf_text.count("Mã báo cáo"), 1)

    def test_compact_pentest_template_all_6_sections_and_all_6_mandatory_rules(self):
        """Verify 100% fidelity to `Template báo cáo pentest gọn.pdf` (6 sections + all 6 mandatory rules)."""
        from pypdf import PdfReader
        from rag.compact_pentest_template import prepare_compact_pentest, render_compact_pentest_markdown

        # Same bug reported across 2 scanner rows with different SQLi techniques + passive Nmap port + negative Submit probe
        row_sqli_a = {
            "id": "SCAN-01A",
            "title": "SQL Injection in GET parameter 'id' (error-based EXTRACTVALUE)",
            "cwe": "CWE-89",
            "severity": "high",
            "tool": "sqlmap",
            "location": "http://198.51.100.79/vulnerabilities/sqli/?id=1&Submit=Submit",
            "kind": "scanner_alert",
            "evidence": ["Parameter: id (GET)\n    Type: error-based\n    Payload: id=1' AND EXTRACTVALUE(1,1)-- -"],
            "details": {
                "parameter": "id",
                "method": "GET",
                "techniques": ["error-based", "boolean-based blind"],
                "http_messages": [
                    {
                        "id": "#239",
                        "request": "GET /vulnerabilities/sqli/?id=1%27%20AND%20EXTRACTVALUE%281%2C1%29--%20-&Submit=Submit HTTP/1.1\nCookie: PHPSESSID=secret777; security=low\nHost: 198.51.100.79",
                        "response": "HTTP/1.1 200 OK\nServer: Apache/2.4.25 (Debian)\n<pre>XPATH syntax error: '\\qpxvq1qpjxq'</pre>",
                    },
                ],
                "scan_telemetry": {
                    "dbms": "MySQL >= 5.1 (MariaDB fork)",
                    "web_tech": "Apache 2.4.25 (Debian), PHP 7.0.33",
                    "current_user": "app@localhost",
                    "current_db": "dvwa",
                    "is_dba": False,
                    "databases": ["dvwa", "information_schema"],
                    "tables_by_db": {"dvwa": ["guestbook", "users"]},
                    "non_dynamic_parameters": ["Submit"],
                    "unmatched_http_ids": ["#1008", "#3838"],
                },
            },
            "guidance": [
                {
                    "title": "SQL Injection Prevention Cheat Sheet",
                    "section": "SQL Injection Prevention Cheat Sheet / Defense Option 1: Prepared Statements",
                    "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    "source_excerpt": "Use prepared statements with parameterized queries:\n```php\n$stmt = $dbh->prepare('SELECT first_name FROM users WHERE user_id = :id');\n$stmt->bindParam(':id', $id, PDO::PARAM_INT);\n```",
                }
            ],
        }
        row_sqli_b = {
            "id": "SCAN-01B",
            "title": "SQL Injection in GET parameter 'id' (UNION query & time-based blind)",
            "cwe": "CWE-89",
            "severity": "high",
            "tool": "sqlmap",
            "location": "http://198.51.100.79/vulnerabilities/sqli/?id=1&Submit=Submit",
            "kind": "scanner_alert",
            "evidence": ["Parameter: id (GET)\n    Type: UNION query\n    Type: time-based blind"],
            "details": {
                "parameter": "id",
                "method": "GET",
                "techniques": ["UNION query", "time-based blind"],
            },
            "guidance": [],
        }
        row_open_port = {
            "id": "NMAP-PORT-80",
            "title": "Service observation: http on 198.51.100.79:80/tcp",
            "cwe": "unknown",
            "severity": "unknown",
            "tool": "Nmap",
            "location": "198.51.100.79:80/tcp",
            "kind": "observation",
            "evidence": ["Open port 80/tcp Apache httpd 2.4.25 ((Debian))"],
            "details": {
                "service": {"name": "http", "product": "Apache httpd", "version": "2.4.25", "extrainfo": "(Debian)"},
                "scan_telemetry": {"cli_hint": "nmap -sV -p 80,3306 198.51.100.79"},
            },
            "guidance": [],
        }
        row_no_proof = {
            "id": "MANUAL-NOEV",
            "title": "Kiểm tra tham số không kèm bằng chứng",
            "cwe": "CWE-89",
            "severity": "unknown",
            "tool": "custom-check",
            "location": "http://198.51.100.79/profile",
            "kind": "scanner_alert",
            "evidence": [],
            "details": {},
            "guidance": [],
        }

        rep = {
            "schema_version": 1,
            "generated_at": "2026-10-23T08:00:00+00:00",
            "input_format": "sqlmap-log",
            "input_filename": "pentest_bundle.txt",
            "scan_sha256": "deadbeef" * 8,
            "findings": [row_sqli_a, row_sqli_b, row_open_port, row_no_proof],
            "report_metadata": {},
        }

        m = prepare_compact_pentest(rep)
        md = render_compact_pentest_markdown(rep)

        # Rule 1: 1 bug = 1 F-xx entry (row_sqli_a + row_sqli_b consolidated into F-01; row_no_proof becomes F-02; row_open_port in Section 3!)
        self.assertEqual([f["id"] for f in m["findings"]], ["F-01", "F-02"])
        self.assertIn("4 kỹ thuật", m["findings"][0]["description"])

        # Rule 2: Banner / open port strictly in Section 3 without CWE; finding with empty evidence gets OWASP / CWE = 'Chưa xác định'
        self.assertTrue(any("Apache" in ob["observation"] for ob in m["observations"]))
        self.assertEqual(m["findings"][1]["owasp_cwe_short"], "Chưa xác định")
        sec3 = md.split("## 3. Quan sát (chưa phải lỗ hổng)", 1)[1].split("## 4. Kết quả âm tính", 1)[0]
        self.assertNotIn("CWE-", sec3)

        # Rule 3: Never invent CVSS; write 'Chưa xác định' when absent
        self.assertEqual(m["findings"][0]["sev_cvss_display"], "High (CVSS: Chưa xác định)")
        self.assertEqual(m["findings"][1]["sev_cvss_display"], "Chưa xác định")

        # Rule 4: Max 2 evidence blocks + 1 primary remediation + 1 OWASP Cheat Sheet source URL per finding
        self.assertLessEqual(len(m["findings"][0]["evidences"]), 2)
        self.assertIn("SQL_Injection_Prevention_Cheat_Sheet.html", m["findings"][0]["remediation_source_url"])
        self.assertNotIn("secret777", md)

        # Rule 5: Negative results recorded in Section 4 (`Submit` not injectable)
        sec4 = md.split("## 4. Kết quả âm tính", 1)[1].split("## 5. Giới hạn & việc cần xác minh", 1)[0]
        self.assertIn("Submit", sec4)
        self.assertIn("không injectable", sec4)

        # Rule 6: Limitations once in Section 5, CLI command + SHA-256 in Section 6, 'Quy tắc điền' strictly omitted
        self.assertNotIn("Quy tắc điền", md)
        self.assertIn("nmap -sV -p 80,3306 198.51.100.79", md)
        self.assertIn("deadbeef" * 8, md)

        with tempfile.TemporaryDirectory() as tmp:
            pdf_out = render_pdf(rep, Path(tmp) / "compact_template.pdf")
            reader = PdfReader(str(pdf_out))
            self.assertGreaterEqual(len(reader.pages), 2)
            self.assertLessEqual(len(reader.pages), 3)
            all_text = "\n".join(pg.extract_text() for pg in reader.pages)
            self.assertIn(f"Page 1 of {len(reader.pages)}", all_text)
            self.assertNotIn("Quy tắc điền", all_text)
            for req_h in (
                "1. Tóm tắt",
                "2. Chi tiết phát hiện",
                "3. Quan sát (chưa phải lỗ hổng)",
                "4. Kết quả âm tính",
                "5. Giới hạn & việc cần xác minh",
                "6. Phụ lục",
            ):
                self.assertIn(req_h, all_text)

    def test_assistant_chatbot_multiturn_qa_pasted_scan_and_report_followup(self):
        """End-to-end test for `/api/chat` & `/api/threads`: standalone Q&A -> pasted scan -> grounded F-01 follow-up."""
        import http.cookiejar
        import threading
        import time
        import urllib.request

        with tempfile.TemporaryDirectory() as tmp:
            mgr = JobManager(Path(tmp) / "jobs", demo=True)
            srv = LocalServer(("127.0.0.1", 0), mgr)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                cj = http.cookiejar.CookieJar()
                opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
                base = f"http://127.0.0.1:{port}"

                with opener.open(f"{base}/") as r_home:
                    home_html = r_home.read().decode("utf-8")
                self.assertIn("chat-app", home_html)
                self.assertIn("starter-grid", home_html)

                with opener.open(f"{base}/api/config") as r_cfg:
                    cfg = json.loads(r_cfg.read().decode("utf-8"))
                tok = cfg["token"]
                headers = {"X-App-Token": tok, "Content-Type": "application/json; charset=utf-8"}

                # Turn 1: Standalone security question without any file uploaded
                req1 = urllib.request.Request(
                    f"{base}/api/chat",
                    data=json.dumps({"message": "Cách phòng chống SQL Injection bằng PHP PDO Prepared Statements?"}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with opener.open(req1) as resp1:
                    c1 = json.loads(resp1.read().decode("utf-8"))
                tid = c1["thread"]["id"]
                self.assertIn("PDO::ATTR_EMULATE_PREPARES", c1["reply"]["text"])
                self.assertGreaterEqual(len(c1["reply"]["suggestions"]), 2)

                # Turn 2: Paste raw sqlmap log directly into the exact same chat thread
                pasted_log = (
                    "Target URL: http://198.51.100.79/vulnerabilities/sqli/?id=1&Submit=Submit\n"
                    "[11:22:01] [WARNING] GET parameter 'Submit' does not seem to be dynamic\n"
                    "---\n"
                    "Parameter: id (GET)\n"
                    "    Type: error-based\n"
                    "    Title: MySQL >= 5.1 AND error-based\n"
                    "    Payload: id=1' AND EXTRACTVALUE(1,1)-- -\n"
                    "---\n"
                    "back-end DBMS: MySQL >= 5.1 (MariaDB fork)\n"
                    "current user: 'app@localhost'\n"
                    "current database: 'dvwa'\n"
                )
                req2 = urllib.request.Request(
                    f"{base}/api/chat",
                    data=json.dumps({"thread_id": tid, "message": pasted_log}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with opener.open(req2) as resp2:
                    c2 = json.loads(resp2.read().decode("utf-8"))
                auto_jid = c2["auto_job"]["id"]
                for _ in range(80):
                    with opener.open(urllib.request.Request(f"{base}/api/jobs/{auto_jid}", headers={"X-App-Token": tok})) as rj:
                        st = json.loads(rj.read().decode("utf-8"))
                    if st["status"] in {"completed", "partial", "failed"}:
                        break
                    time.sleep(0.05)
                self.assertEqual(st["status"], "completed")

                # Turn 3: Follow-up question grounded directly on the newly analyzed report (`F-01`)
                req3 = urllib.request.Request(
                    f"{base}/api/chat",
                    data=json.dumps({"thread_id": tid, "message": "Giải thích chi tiết lỗ hổng F-01 trong báo cáo vừa phân tích"}).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with opener.open(req3) as resp3:
                    c3 = json.loads(resp3.read().decode("utf-8"))
                self.assertIn("F-01", c3["reply"]["text"])
                self.assertIn("app@localhost", c3["reply"]["text"])

                with opener.open(urllib.request.Request(f"{base}/api/threads", headers={"X-App-Token": tok})) as rt:
                    threads = json.loads(rt.read().decode("utf-8"))
                self.assertTrue(any(th["id"] == tid and len(th["messages"]) >= 5 for th in threads))

                # Real DELETE /api/threads/<id> cleans up the thread and terminal unreferenced job folder
                del_req = urllib.request.Request(
                    f"{base}/api/threads/{tid}",
                    headers={"X-App-Token": tok},
                    method="DELETE",
                )
                with opener.open(del_req) as rdel:
                    del_res = json.loads(rdel.read().decode("utf-8"))
                self.assertEqual(del_res["deleted_threads"], 1)
                with opener.open(urllib.request.Request(f"{base}/api/threads", headers={"X-App-Token": tok})) as rt2:
                    threads_after = json.loads(rt2.read().decode("utf-8"))
                self.assertFalse(any(th["id"] == tid for th in threads_after))
            finally:
                srv.shutdown()
                srv.server_close()
                mgr.close()

    def test_pipeline_upgrades_nmap_cli_guard_zap_consolidation_quote_unquote_and_ui_cleanliness(self):
        from rag.analysis import _resolve_quote, redact
        from rag.compact_pentest_template import prepare_compact_pentest, render_compact_pentest_markdown
        from rag.web_server import JobManager, LocalServer
        import http.cookiejar
        import threading
        import urllib.request

        # 1. URL-encoded & HTML-escaped verbatim quote resolution + Windows double-backslash redaction
        raw_src = "GET /app/search?id=1%27%20UNION%20ALL%20SELECT%20NULL--%20- HTTP/1.1"
        encoded_match = _resolve_quote("1' UNION ALL SELECT NULL-- -", raw_src)
        self.assertIsNotNone(encoded_match)
        self.assertIn(encoded_match, raw_src)
        self.assertIn("%27", encoded_match)
        cleaned_cli = redact("nmap &#45;&#45;script=mysql-empty-password -oX C:\\\\Users\\\\DemoUser\\\\Desktop\\\\scan.xml")
        self.assertIn("--script=mysql-empty-password", cleaned_cli)
        self.assertNotIn("&#45;", cleaned_cli)
        self.assertNotIn("DemoUser", cleaned_cli)

        # 2. Nmap XML with --script=mysql-empty-password + unauthorized banner + NSE ERROR output
        nmap_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<nmaprun scanner="nmap" args="nmap -sV &#45;&#45;script=mysql-empty-password,mysql-users -p 22,80,3306 -oX C:\\\\Users\\\\DemoUser\\\\out.xml 198.51.100.55" version="7.95">'
            '<host><address addr="198.51.100.55" addrtype="ipv4"/>'
            '<ports>'
            '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"/></port>'
            '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.58"/></port>'
            '<port protocol="tcp" portid="3306"><state state="open"/>'
            '<service name="mysql" product="MariaDB" extrainfo="unauthorized"/>'
            '<script id="mysql-users" output="ERROR: Script execution failed (use -d to debug)"/>'
            '</port>'
            '</ports></host></nmaprun>'
        ).encode("utf-8")

        # 3. High-instance ZAP JSON (>110 URL instances across site-wide cookie/header rules + SQLi)
        zap_many = json.dumps({
            "@version": "2.17.0",
            "site": [{
                "@name": "http://198.51.100.55",
                "alerts": [
                    {
                        "pluginid": "10010",
                        "alert": "Cookie No HttpOnly Flag",
                        "riskcode": "1",
                        "cweid": "1004",
                        "instances": [
                            {"uri": f"http://198.51.100.55/page{i}.php", "method": "GET", "param": "PHPSESSID", "evidence": "Set-Cookie: PHPSESSID=abc"}
                            for i in range(65)
                        ],
                    },
                    {
                        "pluginid": "10021",
                        "alert": "X-Content-Type-Options Header Missing",
                        "riskcode": "1",
                        "cweid": "693",
                        "instances": [
                            {"uri": f"http://198.51.100.55/item{i}.php", "method": "GET", "param": "", "evidence": "HTTP/1.1 200 OK"}
                            for i in range(55)
                        ],
                    },
                ],
            }],
        }).encode("utf-8")

        # Verify UI has zero fake SaaS controls while retaining real views & history delete
        ui_html = (ROOT / "src/rag/web/index.html").read_text(encoding="utf-8")
        for forbidden_fake in ("Pro Plan", "$19", "Log out"):
            self.assertNotIn(forbidden_fake, ui_html)
        for real_feature in ("clear-history-btn", "collapse-history-btn", "view-owasp", "view-stats", "pdf-modal"):
            self.assertIn(real_feature, ui_html)

        with tempfile.TemporaryDirectory() as tmp:
            mgr = JobManager(Path(tmp) / "jobs", demo=True)
            j_nmap = mgr.submit(nmap_xml, "nmap_test.xml", "auto")
            j_zap = mgr.submit(zap_many, "zap_many.json", "auto")
            for jid in (j_nmap["id"], j_zap["id"]):
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    cur = mgr.get(jid)
                    if cur["status"] in {"completed", "partial", "failed"}:
                        break
                    time.sleep(0.1)
                self.assertEqual(mgr.get(jid)["status"], "completed", msg=mgr.get(jid).get("error"))

            nmap_job = mgr.get(j_nmap["id"])
            self.assertEqual(nmap_job["summary"]["findings"], 0)
            self.assertEqual(nmap_job["summary"]["findings_preview"], [])
            nmap_rep = json.loads((Path(tmp) / "jobs" / j_nmap["id"] / "output" / "report.json").read_text(encoding="utf-8"))
            nmap_model = prepare_compact_pentest(nmap_rep)
            nmap_md = render_compact_pentest_markdown(nmap_rep)
            self.assertEqual(len(nmap_model["findings"]), 0)
            self.assertIn("198.51.100.55", nmap_model["doc_title"])
            self.assertNotIn(":22", nmap_model["doc_title"])
            self.assertIn("mysql-empty-password", nmap_md)
            self.assertIn("mysql-users", nmap_md)
            self.assertIn("không ghi khối kết quả tương ứng", nmap_md)
            self.assertNotIn("không chấp nhận tài khoản rỗng", nmap_md)
            self.assertNotIn("nmap, Nmap", nmap_md)
            mgr.close()


if __name__ == "__main__":
    unittest.main()
