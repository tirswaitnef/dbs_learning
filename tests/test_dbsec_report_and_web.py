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


if __name__ == "__main__":
    unittest.main()
