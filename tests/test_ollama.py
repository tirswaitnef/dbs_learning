import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rag.analysis import enrich_report, generate_analysis, redact, validate
from rag.config import Settings, _read_env_file, load_settings
from rag.document_store import ingest_documents
from rag.llm import OllamaLLM, check_ollama, llm_plan
from rag.official_report import run_corpus_report
from rag.pipeline import run_report
from rag.qa import answer_from_results
from rag.schemas import Card, Finding
from rag.web_server import JobManager, LocalServer, safe_error


@contextmanager
def mock_ollama_server(*, installed_models=("qwen2.5:7b",), reject_think_once=False):
    state = {"requests": [], "rejected_think": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _json(self, code, data):
            raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/api/tags":
                self._json(200, {"models": [{"name": m} for m in installed_models]})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            state["requests"].append(body)
            model = body.get("model", "")
            if reject_think_once and "think" in body and not state["rejected_think"]:
                state["rejected_think"] = True
                return self._json(400, {"error": "unknown field think"})
            matched = model in installed_models or (":" not in model and f"{model}:latest" in installed_models)
            if not matched:
                return self._json(404, {"error": f"model '{model}' not found"})
            user_prompt = json.loads(body["messages"][-1]["content"])
            schema = body.get("format") or {}
            props = schema.get("properties") or {}
            if "source_ids" in props:
                cands = user_prompt.get("candidates") or []
                reply = {"source_ids": [cands[0]["source_id"]] if cands else []}
            elif "supported" in props:
                reply = {"supported": True, "no_remediation": True,
                         "appropriately_uncertain": True, "database_specific": True}
            elif "observations" in props:
                sources = user_prompt["sources"]
                sid = "E1" if "E1" in sources else next(iter(sources))
                quote = sources[sid].strip().splitlines()[0][:80]
                idx = len(state["requests"])
                claim = {
                    "text_vi": f"Bản ghi #{idx} ghi nhận dữ liệu kiểm thử từ nguồn đầu vào nhưng chưa được xác minh độc lập.",
                    "citations": [{"source_id": sid, "quote": quote}],
                }
                reply = {"observations": [claim], "potential_impacts": [], "limitations": [claim]}
            elif "statements" in props:
                ctx = user_prompt["context"][0]
                reply = {"status": "answered", "statements": [{
                    "text": "Tài liệu nêu rõ cách giữ ngữ cảnh khi chia đoạn.",
                    "citations": [{"source_id": ctx["source_id"], "quote": ctx["text"]}],
                }]}
            else:
                reply = {"items": [{"finding_id": item["finding_id"],
                                    "guidance_ids": [item["candidates"][0]["id"]] if item["candidates"] else []}
                                   for item in user_prompt]}
            self._json(200, {"model": model, "done": True,
                             "message": {"role": "assistant", "content": json.dumps(reply, ensure_ascii=False)}})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", state
    finally:
        server.shutdown()
        server.server_close()


class OllamaIntegrationTests(unittest.TestCase):
    def test_settings_provider_resolution_and_utf8_bom_env(self):
        s_default = Settings()
        self.assertEqual(s_default.resolved_provider, "gemini")
        s_auto = Settings(ollama_model="qwen2.5:7b")
        self.assertEqual((s_auto.resolved_provider, s_auto.active_model, s_auto.model_label),
                         ("ollama", "qwen2.5:7b", "ollama/qwen2.5:7b"))
        with self.assertRaises(ValueError):
            Settings(llm_provider="unknown")
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_bytes("\ufeffLLM_PROVIDER=ollama\r\nOLLAMA_MODEL=qwen2.5:7b\r\nRAG_TOP_K=\r\n".encode("utf-8"))
            parsed = _read_env_file(env_path)
            self.assertEqual(parsed["LLM_PROVIDER"], "ollama")
            self.assertEqual(parsed["OLLAMA_MODEL"], "qwen2.5:7b")
            with patch("rag.config.ROOT", Path(tmp)), patch.dict(os.environ, {}, clear=False):
                os.environ.pop("LLM_PROVIDER", None)
                os.environ.pop("OLLAMA_MODEL", None)
                loaded = load_settings()
                self.assertEqual((loaded.resolved_provider, loaded.ollama_model, loaded.top_k),
                                 ("ollama", "qwen2.5:7b", 4))

    def test_ollama_chat_protocol_proxy_bypass_and_large_context(self):
        with mock_ollama_server(installed_models=("qwen2.5:latest",), reject_think_once=True) as (url, state):
            settings = Settings(llm_provider="ollama", ollama_base_url=url, ollama_model="qwen2.5")
            # Even with dead ZAP/Burp proxy env vars set, loopback Ollama calls succeed directly.
            with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9"}):
                status = check_ollama(settings)
                self.assertTrue(status["ok"])
                f = Finding("F1", "SQL Injection", "CWE-89", "high", "http://127.0.0.1/login", ("ev",), "zap", "ref")
                c = Card("C1", "CWE-89", "SQLi", "sec", "https://owasp.org/", "2026-10-01",
                         "rev", True, "ex", "guidance", "cond")
                plan = llm_plan([f], {"F1": [{"card_id": "C1"}]}, [c], settings)
                self.assertEqual(plan, {"items": [{"finding_id": "F1", "guidance_ids": ["C1"]}]})
                # First request tried think=False, got 400 on legacy server, retried cleanly without think.
                self.assertEqual(len(state["requests"]), 2)
                self.assertNotIn("think", state["requests"][1])
                self.assertEqual(state["requests"][1]["options"]["num_ctx"], 8192)
                # Large prompt automatically expands num_ctx >= 16384 so summary prompts never truncate.
                llm = OllamaLLM(settings)
                llm.generate(json.dumps([{"finding_id": "F1", "pad": "x" * 13000, "candidates": []}]),
                             system="select", schema={"type": "object", "properties": {"items": {"type": "array"}}})
                self.assertEqual(state["requests"][-1]["options"]["num_ctx"], 16384)

    def test_missing_ollama_model_gives_pull_hint(self):
        with mock_ollama_server(installed_models=("qwen3:8b",)) as (url, _):
            settings = Settings(llm_provider="ollama", ollama_base_url=url, ollama_model="qwen2.5:7b")
            status = check_ollama(settings)
            self.assertFalse(status["ok"])
            self.assertIn("ollama pull qwen2.5:7b", status["error"])
            self.assertIn("qwen3:8b", status["error"])
            llm = OllamaLLM(settings)
            with self.assertRaises(RuntimeError) as ctx:
                llm.generate("{}", system="s", schema={"type": "object"})
            self.assertIn("ollama pull qwen2.5:7b", safe_error(ctx.exception))

    def test_redaction_crlf_quotes_and_vietnamese_self_repair(self):
        # Nmap mysql-empty-password must keep the account name while real secrets stay redacted.
        self.assertEqual(redact("NSE mysql-empty-password: root account has empty password"),
                         "NSE mysql-empty-password: root account has empty password")
        self.assertIn("[REDACTED]", redact("password=supersecret&api_key=xyz123"))

        sources = {
            "M1": "Tên phát hiện do kiểm thử cung cấp: SQL Injection",
            "E1": redact("Parameter: id (GET)\r\n    Type: boolean-based blind"),
            "K1": "Phân loại CSDL do code thực hiện từ chính bản ghi này: không có dấu hiệu riêng về CSDL.",
        }
        # Multi-line evidence quoted with collapsed single space still matches exact tokens, invented text fails.
        good = {"observations": [{"text_vi": "Công cụ ghi nhận tham số id có dấu hiệu boolean-based blind.",
                                  "citations": [{"source_id": "E1",
                                                 "quote": "Parameter: id (GET) Type: boolean-based blind"}]}],
                "potential_impacts": [], "limitations": []}
        self.assertEqual(validate(good, sources), good)
        bad = {"observations": [{"text_vi": "Công cụ ghi nhận tham số id có dấu hiệu boolean-based blind.",
                                 "citations": [{"source_id": "E1", "quote": "Parameter: id (POST) boolean"}]}],
               "potential_impacts": [], "limitations": []}
        with self.assertRaises(ValueError):
            validate(bad, sources)

        # First draft leaks a CJK character; repair retry produces clean accented Vietnamese and passes review.
        drafts = [
            json.dumps({"observations": [{"text_vi": "Phát hiện SQL Injection 的 tại tham số id.",
                                          "citations": [{"source_id": "E1", "quote": "Parameter: id (GET)"}]}],
                        "potential_impacts": [], "limitations": []}, ensure_ascii=False),
            json.dumps(good, ensure_ascii=False),
            json.dumps({"supported": True, "no_remediation": True,
                        "appropriately_uncertain": True, "database_specific": True}),
        ]

        class FlakyLocalModel:
            def __init__(self):
                self.seen = []

            def generate(self, prompt, *, system, schema):
                self.seen.append(json.loads(prompt))
                return drafts.pop(0)

        flaky = FlakyLocalModel()
        res = generate_analysis(sources, flaky, task="test")
        self.assertEqual(res["status"], "ai_reviewed")
        self.assertIn("repair_note", flaky.seen[1])
        self.assertIn("previous_draft", flaky.seen[1])

        # Comma-joined bullet quotes snap onto exact verbatim source span; redundant prefixes are stripped.
        sources_e2 = {**sources, "E2": "available databases [2]:\n[*] dvwa\n[*] information_schema"}
        snapped = validate({
            "observations": [{"text_vi": "Điểm quan sát: Công cụ sqlmap ghi nhận danh sách CSDL gồm dvwa và information_schema.",
                              "citations": [{"source_id": "E2", "quote": "available databases [2]: dvwa, information_schema"}]}],
            "potential_impacts": [], "limitations": [],
        }, sources_e2)
        self.assertEqual(snapped["observations"][0]["text_vi"],
                         "Công cụ sqlmap ghi nhận danh sách CSDL gồm dvwa và information_schema.")
        self.assertEqual(snapped["observations"][0]["citations"][0]["quote"],
                         "available databases [2]:\n[*] dvwa\n[*] information_schema")

        # Quote present in M3/K1 but mistakenly labeled E1 by a small model snaps to its true source ID.
        sources_m3 = {**sources_e2, "M3": "Vị trí do kiểm thử cung cấp: host=192.0.2.55 (sqlmap output log); parameter=id (GET)"}
        relinked = validate({
            "observations": [{"text_vi": "Công cụ sqlmap ghi nhận tham số id tại host 192.0.2.55.",
                              "citations": [{"source_id": "E1", "quote": "host 192.0.2.55"}]}],
            "potential_impacts": [], "limitations": [],
        }, sources_m3)
        self.assertEqual(relinked["observations"][0]["citations"][0],
                         {"source_id": "M3", "quote": "host=192.0.2.55"})

    def test_qa_and_web_end_to_end_with_local_ollama_pdf(self):
        class FakeEmbedder:
            def embed_documents(self, texts):
                return [[1.0, 0.2, 0.1] for _ in texts]

            def embed_query(self, text):
                return [1.0, 0.2, 0.1]

        nmap_xml = (
            b'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
            b'<address addr="192.0.2.55" addrtype="ipv4"/><ports><port protocol="tcp" portid="3306">'
            b'<state state="open"/><service name="mysql" product="MariaDB" version="11.4"/>'
            b'<script id="mysql-empty-password" output="&#xa;root account has empty password"/>'
            b'</port></ports></host></nmaprun>'
        )

        with tempfile.TemporaryDirectory() as tmp, mock_ollama_server() as (ollama_url, _):
            tmp_path = Path(tmp)
            raw_dir = tmp_path / "cheatsheets"
            raw_dir.mkdir()
            (raw_dir / "Database_Security_Cheat_Sheet.md").write_text(
                "# Database Security Cheat Sheet\n\n## Authentication\n\n"
                "Always change default database administrative passwords and disable unauthenticated access "
                "before exposing any database instance on a network interface.\n",
                encoding="utf-8",
            )
            store_dir = tmp_path / "store"
            settings = Settings(llm_provider="ollama", ollama_base_url=ollama_url, ollama_model="qwen2.5:7b")
            ingest_documents(raw_dir, store_dir, settings, embedder=FakeEmbedder())

            # QA pipeline uses OllamaLLM automatically when settings resolve to ollama.
            qa_res = answer_from_results(
                "Overlap giúp gì?",
                [{"source": "a.md", "index": 0, "start": 0, "end": 37,
                  "text": "Overlap giữ một phần ngữ cảnh chung.", "score": 0.95, "metadata": {}}],
                settings,
            )
            self.assertEqual(qa_res.status, "answered")

            def custom_runner(scan_path, out_dir, job, progress):
                with patch("rag.embeddings.E5Embedding", return_value=FakeEmbedder()):
                    return run_corpus_report(
                        scan_path, out_dir, settings,
                        raw_directory=raw_dir, store_directory=store_dir,
                        format_=job["format"], offline=True, progress=progress,
                        report_metadata=job.get("report_metadata"), display_filename=job["filename"],
                    )

            manager = JobManager(tmp_path / "jobs", settings_loader=lambda: settings, runner=custom_runner)
            server = LocalServer(("127.0.0.1", 0), manager)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                req_home = urllib.request.Request(f"http://127.0.0.1:{port}/", headers={"Host": f"127.0.0.1:{port}"})
                cookie = opener.open(req_home).headers.get("Set-Cookie").split(";", 1)[0]
                req_cfg = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/config",
                    headers={"Host": f"127.0.0.1:{port}", "Cookie": cookie},
                )
                cfg = json.loads(opener.open(req_cfg).read().decode("utf-8"))
                self.assertEqual((cfg["provider"], cfg["model"], cfg["configured"]),
                                 ("ollama", "qwen2.5:7b", True))

                req_post = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/jobs?filename=nmap_csdl.xml&format=auto",
                    data=nmap_xml,
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Origin": f"http://127.0.0.1:{port}",
                        "Cookie": cookie,
                        "X-App-Token": cfg["token"],
                        "Content-Type": "application/octet-stream",
                    },
                    method="POST",
                )
                job = json.loads(opener.open(req_post).read().decode("utf-8"))
                for _ in range(50):
                    req_job = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/jobs/{job['id']}",
                        headers={"Host": f"127.0.0.1:{port}", "Cookie": cookie},
                    )
                    current = json.loads(opener.open(req_job).read().decode("utf-8"))
                    if current["status"] in {"completed", "partial", "failed"}:
                        break
                    time.sleep(0.05)
                self.assertEqual(current["status"], "completed")
                self.assertEqual(current["percent"], 100)
                self.assertEqual(current["step"], 6)
                self.assertGreaterEqual(len(current["events"]), 5)
                self.assertGreaterEqual(len(current["summary"]["findings_preview"]), 1)
                req_json = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/jobs/{job['id']}/json",
                    headers={"Host": f"127.0.0.1:{port}", "Cookie": cookie},
                )
                report_json = json.loads(opener.open(req_json).read().decode("utf-8"))
                self.assertEqual(report_json["mode"], "ollama-top10-analysis-extractive")
                self.assertEqual(report_json["model"], "ollama/qwen2.5:7b")

                req_pdf = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/jobs/{job['id']}/pdf",
                    headers={"Host": f"127.0.0.1:{port}", "Cookie": cookie},
                )
                resp_pdf = opener.open(req_pdf)
                pdf_bytes = resp_pdf.read()
                self.assertEqual(pdf_bytes[:4], b"%PDF")
                self.assertIn("attachment;", resp_pdf.headers.get("Content-Disposition", ""))

                req_pdf_inline = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/jobs/{job['id']}/pdf?inline=1",
                    headers={"Host": f"127.0.0.1:{port}", "Cookie": cookie},
                )
                resp_inline = opener.open(req_pdf_inline)
                self.assertEqual(resp_inline.read()[:4], b"%PDF")
                self.assertIn("inline;", resp_inline.headers.get("Content-Disposition", ""))
                self.assertIn("object-src 'self'", resp_inline.headers.get("Content-Security-Policy", ""))

                req_trace = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/jobs/{job['id']}/trace",
                    headers={"Host": f"127.0.0.1:{port}", "Cookie": cookie},
                )
                trace_json = json.loads(opener.open(req_trace).read().decode("utf-8"))
                self.assertGreaterEqual(trace_json["call_count"], 5)
                self.assertTrue(any("api/chat" in e["endpoint"] for e in trace_json["entries"]))
                self.assertTrue(all(e["system_prompt"] and e["user_prompt"] and e["raw_response"] for e in trace_json["entries"]))

                req_trace_txt = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/jobs/{job['id']}/trace-txt",
                    headers={"Host": f"127.0.0.1:{port}", "Cookie": cookie},
                )
                trace_txt = opener.open(req_trace_txt).read().decode("utf-8")
                self.assertIn("NHẬT KÝ LỆNH GỬI AI & PHẢN HỒI NGUYÊN VĂN", trace_txt)
                self.assertIn("SYSTEM PROMPT", trace_txt)
                self.assertIn("ASSISTANT RAW OUTPUT", trace_txt)
            finally:
                server.shutdown()
                server.server_close()
                manager.close()

    def test_reviewer_issues_cvss_consistency_ollama_retries_and_static_eol_provenance(self):
        from dataclasses import asdict
        from rag.analysis import input_sources
        from rag.db_scope import attach_db_scope
        from rag.parsers.native import parse_sqlmap_log
        from rag.pdf_report import render_pdf
        from rag.report_view import extract_scan_context
        from rag.top10 import classify

        # 1) Issue 2: monotonic runner num_ctx (no 16384 -> 8192 drop), retry on empty/truncated/timeout, and 600s .env floor.
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text("LLM_PROVIDER=ollama\nOLLAMA_MODEL=qwen3:4b\nOLLAMA_TIMEOUT=120\n", encoding="utf-8")
            with patch("rag.config.ROOT", Path(tmp)), patch.dict(os.environ, {}, clear=False):
                os.environ.pop("OLLAMA_TIMEOUT", None)
                s_floor = load_settings()
                self.assertEqual(s_floor.ollama_timeout, 600)

        with mock_ollama_server(installed_models=("qwen3:4b",)) as (url, state):
            llm = OllamaLLM(Settings(llm_provider="ollama", ollama_base_url=url, ollama_model="qwen3:4b"), sleep=lambda _: None)
            llm.generate(json.dumps([{"finding_id": "F1", "pad": "x" * 13000, "candidates": []}]), system="select", schema={"type": "object", "properties": {"items": {"type": "array"}}})
            llm.generate(json.dumps([{"finding_id": "F1", "candidates": []}]), system="select", schema={"type": "object", "properties": {"items": {"type": "array"}}})
            self.assertEqual(state["requests"][0]["options"]["num_ctx"], 16384)
            self.assertEqual(state["requests"][1]["options"]["num_ctx"], 16384)

        responses = [
            TimeoutError("simulated slow CPU generation"),
            json.dumps({"message": {"content": "   "}}),
            json.dumps({"message": {"content": '{"items": ['}}),
            json.dumps({"message": {"content": '{"items": []}'}}),
        ]

        class _FakeResp:
            def __init__(self, body):
                self._body = body.encode("utf-8")

            def read(self):
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        seen_payloads = []

        def fake_open(req, *, loopback, timeout):
            seen_payloads.append(json.loads(req.data.decode("utf-8")))
            nxt = responses.pop(0)
            if isinstance(nxt, Exception):
                raise nxt
            return _FakeResp(nxt)

        with patch("rag.llm._http_open", side_effect=fake_open):
            llm = OllamaLLM(
                Settings(llm_provider="ollama", ollama_base_url="http://127.0.0.1:11434", ollama_model="qwen3:4b"),
                max_retries=4,
                sleep=lambda _: None,
            )
            out = llm.generate("{}", system="sys", schema={"type": "object", "properties": {"items": {"type": "array"}}})
            self.assertEqual(json.loads(out), {"items": []})
            self.assertEqual(len(seen_payloads), 4)
            self.assertGreater(seen_payloads[-1]["options"]["temperature"], 0)
            self.assertGreaterEqual(seen_payloads[-1]["options"]["repeat_penalty"], 1.15)

        # 2) Issue 1 & Issue 3: CVSS/auth consistency guard + explicit static code rule provenance on EOL banners.
        pentest_log = (
            "Target URL: http://198.51.100.42/vulnerabilities/sqli/?id=1&Submit=Submit\n"
            "Authentication Context: Authenticated HTTP Cookie session (PHPSESSID=[REDACTED]; security=low)\n"
            "CVSS: 8.1 (High) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n"
            "[10:00:01] [INFO] the back-end DBMS is MySQL\n"
            "web server operating system: Linux Debian 9 (stretch)\n"
            "web application technology: Apache 2.4.25, PHP 7.0.33\n"
            "back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)\n"
            "Parameter: id (GET)\n"
            "    Type: error-based\n"
            "    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)\n"
            "    Payload: id=1' AND EXTRACTVALUE(2172,CONCAT(0x5c,0x71787a7a71))-- cWfP&Submit=Submit\n"
            "available databases [2]:\n[*] dvwa\n[*] information_schema\n"
            "current user: 'app@localhost'\n"
            "current database: 'dvwa'\n"
            "current user is DBA: False\n"
            "Database: dvwa\n[2 tables]\n+-----------+\n| guestbook |\n| users     |\n+-----------+\n"
        )
        parsed = parse_sqlmap_log(pentest_log, "pentest_full.txt")
        row = {**asdict(parsed[0]), "owasp_top10": classify(parsed[0]), "guidance": []}
        attach_db_scope({"findings": [row]})
        srcs, _ = input_sources(row)
        self.assertIn("CVSS từ đầu vào: 8.1 (vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)", srcs["M2"])
        self.assertIn("Ngữ cảnh xác thực đã cung cấp đầy đủ:", srcs["C1"])
        self.assertIn("Điểm và vector CVSS đã cung cấp sẵn từ đầu vào: 8.1", srcs["C1"])

        contradictory_draft = {
            "observations": [{
                "text_vi": "Công cụ sqlmap ghi nhận tham số id trên DVWA bị SQL Injection kiểu error-based.",
                "citations": [{"source_id": "C1", "quote": "SQL Injection duy nhất"}],
            }],
            "potential_impacts": [{
                "text_vi": "Nếu triển khai thực tế, kẻ tấn công có thể đọc dữ liệu trong các bảng guestbook và users.",
                "citations": [{"source_id": "C1", "quote": "dvwa (guestbook, users)"}],
            }],
            "limitations": [{
                "text_vi": "Log chưa lưu trữ đầy đủ thông tin xác thực (cookie) để tính toán vector CVSS chính xác cho lỗ hổng này.",
                "citations": [{"source_id": "C1", "quote": "Authenticated HTTP Cookie session"}],
            }],
        }
        with self.assertRaises(ValueError):
            validate(contradictory_draft, srcs)

        fixed_draft = {
            **contradictory_draft,
            "limitations": [{
                "text_vi": "Phép kiểm thử dừng ở mức liệt kê tên bảng trong schema dvwa, không trích xuất bản ghi dữ liệu và chưa kiểm chứng thủ công.",
                "citations": [{"source_id": "C1", "quote": "dừng ở mức cấu trúc bảng, không trích xuất bản ghi"}],
            }],
        }
        replies = [
            json.dumps(contradictory_draft, ensure_ascii=False),
            json.dumps(fixed_draft, ensure_ascii=False),
            json.dumps({"supported": True, "no_remediation": True, "appropriately_uncertain": True, "database_specific": True}),
        ]

        class _RepairModel:
            def generate(self, prompt, *, system, schema):
                return replies.pop(0)

        repaired = generate_analysis(srcs, _RepairModel(), task="test")
        self.assertEqual(repaired["status"], "ai_reviewed")
        self.assertNotIn("cookie", repaired["claims"]["limitations"][0]["text_vi"].lower())

        report_obj = {
            "schema_version": 1,
            "generated_at": "2026-10-22T00:00:00+00:00",
            "mode": "ollama-top10-analysis-extractive",
            "model": "ollama/qwen3:4b",
            "input_format": "sqlmap-log",
            "input_filename": "sqlmap_csdl_chuan_pentest.txt",
            "scan_sha256": "a" * 64,
            "knowledge_sha256": "b" * 64,
            "findings": [{**row, "ai_analysis": repaired}],
            "ai_summary": repaired,
            "limitations": [],
        }
        ctx = extract_scan_context(report_obj)
        self.assertTrue(any("Banner đầu vào 'Debian 9'" in n and "quy tắc đối chiếu tĩnh trong code dự án" in n for n in ctx["eol_notes"]))
        self.assertTrue(any("Banner đầu vào 'Apache 2.4.25'" in n and "không do AI suy đoán" in n for n in ctx["eol_notes"]))

        with tempfile.TemporaryDirectory() as pdf_dir:
            rendered_paragraphs = []
            orig_para = __import__("reportlab.platypus", fromlist=["Paragraph"]).Paragraph

            def spy_paragraph(text, *args, **kwargs):
                rendered_paragraphs.append(str(text))
                return orig_para(text, *args, **kwargs)

            with patch("reportlab.platypus.Paragraph", side_effect=spy_paragraph):
                pdf_file = render_pdf(report_obj, Path(pdf_dir) / "out.pdf")
            self.assertTrue(pdf_file.read_bytes().startswith(b"%PDF-"))
            full_pdf_text = __import__("html").unescape("\n".join(rendered_paragraphs))
            self.assertIn("8.1 — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", full_pdf_text)
            self.assertNotIn("các công cụ như sqlmap/nmap không xuất điểm CVSS", full_pdf_text)
            for forbidden in ("SHA-256", "Model AI", "ollama/qwen3:4b", "AUDITNOTE |", "scanner_alert", "[K1]", "[C1]", "[F1]"):
                self.assertNotIn(forbidden, full_pdf_text)
            for expected_sec in (
                "1. Tóm tắt điều hành",
                "2. Phạm vi và Phương pháp kiểm thử",
                "3. Tổng hợp phát hiện theo Danh mục OWASP",
                "4. Chi tiết các phát hiện",
                "5. Phân loại mức độ rủi ro",
                "6. Khuyến nghị khắc phục",
                "7. Phụ lục",
                "W-001:",
                "— Kết thúc Báo cáo —",
            ):
                self.assertIn(expected_sec, full_pdf_text)

    def test_pentest_polish_xss_decision_and_public_ip_redaction(self):
        from rag.parsers.native import parse_sqlmap_log
        from rag.pentest_polish import prepare_pentest_view, render_pentest_markdown

        raw_log = (
            "Target URL: http://8.8.4.4/vulnerabilities/sqli/?id=1&Submit=Submit\n"
            "Authentication Context: Authenticated HTTP Cookie session (PHPSESSID=secretcookie999; security=low)\n"
            "CVSS: 8.1 (High) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n"
            "[11:21:57] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: error-based\n"
            "    Title: MySQL >= 5.1 AND error-based (EXTRACTVALUE)\n"
            "    Payload: id=1' AND EXTRACTVALUE(1,CONCAT(0x5c,0x71))-- abcd&Submit=Submit\n"
            "---\n"
            "back-end DBMS: MySQL >= 5.1\n"
            "[LOCAL_PENTESTER_HOME]\\AppData\\Local\\sqlmap\\output\\8.8.4.4\n"
        )
        rows = [f.__dict__ for f in parse_sqlmap_log(raw_log, "check.txt")]
        for r in rows:
            r["owasp_top10"] = {"status": "in_scope", "categories": [{"id": "A05:2025", "title": "Injection"}], "reason": ""}
            r["guidance"] = []
        base_report = {"schema_version": 1, "generated_at": "2026-10-22T00:00:00+00:00", "findings": rows, "report_metadata": {}}

        # Default `drop`: unverified observation excluded; public IP kept verbatim while cookies/local paths stay redacted
        view_drop = prepare_pentest_view(base_report)
        self.assertEqual([e["pentest_id"] for e in view_drop["entries"]], ["W-001"])
        self.assertEqual(view_drop["dropped_observations"], 1)
        md_drop = render_pentest_markdown(base_report)
        self.assertIn("8.8.4.4", md_drop)
        self.assertNotIn("target-app.local", md_drop)
        self.assertNotIn("secretcookie999", md_drop)
        self.assertNotIn("AppData", md_drop)

        # Manual `confirm`: verified Reflected XSS promoted cleanly to W-002 (Medium, CVSS 6.1)
        base_confirm = {**base_report, "report_metadata": {"xss_decision": "confirm", "xss_poc": "GET /vulnerabilities/sqli/?id=1<svg/onload=alert(1)> -> alert(1)"}}
        view_confirm = prepare_pentest_view(base_confirm)
        self.assertEqual([e["pentest_id"] for e in view_confirm["entries"]], ["W-001", "W-002"])
        self.assertEqual(view_confirm["entries"][1]["severity_key"], "medium")
        self.assertEqual(view_confirm["entries"][1]["cvss_score"], "6.1")

    def test_db_focused_corpus_pruned_and_runtime_cached(self):
        from rag.official_report import PREFERRED, load_corpus_runtime

        cs_dir = ROOT / "data/raw/owasp/official/CheatSheetSeries-master/cheatsheets"
        files = {p.name: p for p in cs_dir.glob("*.md")}
        self.assertEqual(len(files), 25)
        self.assertLess(sum(p.stat().st_size for p in files.values()), 700_000)
        for preferred_set in PREFERRED.values():
            for sheet in preferred_set:
                self.assertIn(sheet, files)
        for off_topic in (
            "Drone_Security_Cheat_Sheet.md",
            "Automotive_Security_Cheat_Sheet.md",
            "Mobile_Application_Security_Cheat_Sheet.md",
            "Browser_Extension_Vulnerabilities_Cheat_Sheet.md",
        ):
            self.assertNotIn(off_topic, files)

        with tempfile.TemporaryDirectory() as tmp:
            import numpy as np

            class _MiniEmbedder:
                model_name = "intfloat/multilingual-e5-small"
                revision = None

                def embed_documents(self, texts):
                    return np.ones((len(texts), 8), dtype=np.float32)

                def embed_query(self, text):
                    return np.ones((8,), dtype=np.float32)

            tmp_path = Path(tmp)
            raw_dir = tmp_path / "raw"
            raw_dir.mkdir()
            (raw_dir / "Database_Security_Cheat_Sheet.md").write_text(
                "# Database Security\n\n## Authentication\nUse strong dedicated database accounts.\n",
                encoding="utf-8",
            )
            store_dir = tmp_path / "store"
            settings = Settings()
            ingest_documents(raw_dir, store_dir, settings, embedder=_MiniEmbedder())
            init_calls = []

            def make_embedder(*_args, **_kwargs):
                init_calls.append(1)
                return _MiniEmbedder()

            with patch("rag.embeddings.E5Embedding", side_effect=make_embedder):
                rt1 = load_corpus_runtime(raw_dir, store_dir, settings, offline=True)
                rt2 = load_corpus_runtime(raw_dir, store_dir, settings, offline=True)
                self.assertIs(rt1, rt2)
                self.assertEqual(len(init_calls), 1)

    def test_peer_review_precision_scope_cvss_confirmed_vs_potential_packet_filter_and_retest(self):
        from rag.parsers import load_findings
        from rag.pdf_report import render_pdf
        from rag.pentest_polish import prepare_pentest_view, render_pentest_markdown, sanitize_raw_scan_text
        from rag.top10 import classify

        sample_log = (
            "Target URL: http://8.8.8.8/vulnerabilities/sqli/?id=1&Submit=Submit\n"
            "Authentication Context: Authenticated HTTP Cookie session (PHPSESSID=secretcookie777; security=low)\n"
            "Pentest Scope Rule: Isolated Lab Deep DB PoC (--level=5 --risk=3, -p id,Submit, [y/N] Y, --dbs, --current-user, --current-db, --is-dba, -D dvwa --tables, raw HTTP traffic capture; NO --dump)\n"
            "Analyst CVSS v3.1: 8.1 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\n"
            "[11:21:57] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks\n"
            "sqlmap identified the following injection point(s) with a total of 5340 HTTP(s) requests:\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)\n"
            "    Payload: id=1' OR NOT 9227=9227-- esvd&Submit=Submit\n\n"
            "    Type: error-based\n"
            "    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)\n"
            "    Payload: id=1' AND EXTRACTVALUE(5879,CONCAT(0x5c,0x7170787671,(SELECT (ELT(5879=5879,1))),0x71706a7871))-- nWty&Submit=Submit\n\n"
            "    Type: time-based blind\n"
            "    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)\n"
            "    Payload: id=1' AND (SELECT 8294 FROM (SELECT(SLEEP(2)))ZCWs)-- PfnW&Submit=Submit\n\n"
            "    Type: UNION query\n"
            "    Title: Generic UNION query (NULL) - 2 columns\n"
            "    Payload: id=1' UNION ALL SELECT CONCAT(0x7170787671,0x41,0x71706a7871),NULL-- -&Submit=Submit\n"
            "---\n"
            "web server operating system: Linux Debian 9 (stretch)\n"
            "web application technology: Apache 2.4.25\n"
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
            "Host: 8.8.8.8\n"
            "Cookie: PHPSESSID=secretcookie777; security=low\n\n"
            "HTTP response [#239] (200 OK):\n"
            "HTTP/1.1 200 OK\n"
            "<pre>XPATH syntax error: '\\qpxvq1qpjxq'</pre>\n"
            "############################################################################\n"
            "HTTP request [#1008]:\n"
            "GET /vulnerabilities/sqli/?id=1&Submit=Submit%27%20AND%201%3D1--%20abc HTTP/1.1\n"
            "Host: 8.8.8.8\n"
            "Cookie: PHPSESSID=secretcookie777; security=low\n\n"
            "HTTP response [#1008] (200 OK):\n"
            "HTTP/1.1 200 OK\n"
            "<pre>ID: 1</pre>\n"
            "############################################################################\n"
            "HTTP request [#5330]:\n"
            "GET /vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20table_name%2CNULL%20FROM%20INFORMATION_SCHEMA.TABLES--%20-&Submit=Submit HTTP/1.1\n"
            "Host: 8.8.8.8\n"
            "Cookie: PHPSESSID=secretcookie777; security=low\n\n"
            "HTTP response [#5330] (200 OK):\n"
            "HTTP/1.1 200 OK\n"
            "<pre>First name: qpxvqguestbookqpjxq</pre><pre>First name: qpxvqusersqpjxq</pre>\n"
            "############################################################################\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "scan.log"
            p.write_text(sample_log, encoding="utf-8")
            findings = load_findings(p, "sqlmap-log")
            rows = []
            for f in findings:
                d = {
                    "id": f.id, "title": f.title, "cwe": f.cwe, "severity": f.severity,
                    "tool": f.tool, "location": f.location, "kind": f.kind,
                    "evidence": list(f.evidence), "details": dict(f.details), "guidance": [],
                }
                d["owasp_top10"] = classify(d)
                rows.append(d)
            rep = {"schema_version": 1, "generated_at": "2026-10-22T00:00:00+00:00", "findings": rows, "report_metadata": {}}
            view = prepare_pentest_view(rep)
            # 1. Target IP preserved verbatim by default while session cookies stay redacted
            synced_log = sanitize_raw_scan_text(sample_log.encode("utf-8"), rep)
            self.assertIn("http://8.8.8.8/vulnerabilities/sqli/?id=1&Submit=Submit", synced_log)
            self.assertNotIn("target-app.local", synced_log)
            self.assertNotIn("secretcookie777", synced_log)
            # 2. Scope strictly scoped to SQL Injection on GET 'id', passive signals explicitly non-conclusive
            self.assertIn("SQL Injection", view["active_scope"])
            self.assertNotIn("Quản lý Phiên & Xác thực", view["active_scope"])
            self.assertIn("heuristic", view["passive_notes"])
            # 3. CVSS 8.1 explicitly explains PR:L vs PR:N
            e0 = view["entries"][0]
            self.assertIn("PR:L", e0["cvss_rationale"])
            self.assertIn("PR:N", e0["cvss_rationale"])
            # 4. Confirmed vs Potential impact separated & respects NO --dump boundary
            self.assertIn("guestbook, users", e0["confirmed_impact"])
            self.assertIn("không chạy --dump", e0["confirmed_impact"])
            self.assertIn("nguy cơ tiềm tàng", e0["potential_impact"])
            # 5. Packet filter keeps #239 & #5330 with captions and explains excluded #1008 on 'Submit'
            self.assertEqual([m["id"] for m in e0["http_exchanges"]], ["#239", "#5330"])
            self.assertIn("#1008", e0["excluded_http_note"])
            self.assertIn("Submit", e0["excluded_http_note"])
            # 6. Strict template compliance in both Vietnamese (`vi`) and English (`en`), plus contextual vs strict CVSS
            self.assertGreaterEqual(len(e0["retest_steps"]), 4)
            md_vi = render_pentest_markdown(rep)
            self.assertIn("## 1. Tóm tắt điều hành", md_vi)
            self.assertIn("## 4. Chi tiết các phát hiện", md_vi)
            self.assertIn("8.1 — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", md_vi)
            self.assertIn("— Kết thúc Báo cáo —", md_vi)
            self.assertNotIn("Retest / Verification", md_vi)
            pdf_out = render_pdf(rep, Path(tmp) / "out_vi.pdf")
            self.assertTrue(pdf_out.is_file() and pdf_out.stat().st_size > 5000)

            rep_en = {**rep, "report_metadata": {"report_lang": "en", "client": "ACME Corp", "prepared_by": "Student Tester"}}
            md_en = render_pentest_markdown(rep_en)
            for heading in (
                "# Web Application Penetration Testing Report",
                "## Table of Contents",
                "## 1. Executive Summary",
                "## 2. Scope and Methodology",
                "## 3. Findings Summary by OWASP Category",
                "## 4. Detailed Findings",
                "## 5. Risk Ratings",
                "## 6. Remediation Recommendations",
                "## 7. Appendix",
                "— End of Report —",
            ):
                self.assertIn(heading, md_en)
            pdf_en = render_pdf(rep_en, Path(tmp) / "out_en.pdf")
            self.assertTrue(pdf_en.is_file() and pdf_en.stat().st_size > 5000)

    def test_scan_hash_ai_cache_reuses_analysis_on_rerender_and_skips_dropped_observations(self):
        import numpy as np

        class _MiniEmbedder:
            model_name = "intfloat/multilingual-e5-small"
            revision = None

            def embed_documents(self, texts):
                arr = np.zeros((len(texts), 8), dtype=np.float32)
                arr[:, 0] = 1.0
                return arr

            def embed_query(self, text):
                arr = np.zeros((8,), dtype=np.float32)
                arr[0] = 1.0
                return arr

        llm_calls = []

        class _CountingLLM:
            def generate(self, prompt, *, system="", schema=None):
                llm_calls.append(prompt)
                data = json.loads(prompt)
                if "candidates" in data:
                    return json.dumps({"source_ids": [data["candidates"][0]["source_id"]]})
                if "analysis" in data:
                    return json.dumps({
                        "supported": True, "no_remediation": True,
                        "appropriately_uncertain": True, "database_specific": True,
                    })
                srcs = data["sources"]
                first_sid = next((k for k in srcs if k.startswith(("E", "F"))), next(iter(srcs)))
                quote = srcs[first_sid].splitlines()[0][:60]
                return json.dumps({
                    "observations": [{"text_vi": "Công cụ ghi nhận tham số id bị tiêm nhiễm SQL.", "citations": [{"source_id": first_sid, "quote": quote}]}],
                    "potential_impacts": [{"text_vi": "Nếu triển khai thực tế, kẻ tấn công có thể đọc dữ liệu ứng dụng.", "citations": [{"source_id": first_sid, "quote": quote}]}],
                    "limitations": [],
                }, ensure_ascii=False)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            raw_dir = tmp_p / "raw"
            raw_dir.mkdir()
            (raw_dir / "SQL_Injection_Prevention_Cheat_Sheet.md").write_text(
                "# SQL Injection Prevention\n\n## Defense Option 1: Prepared Statements\nUse parameterized queries with prepared statements for every SQL statement so user input is never concatenated into SQL code.\n",
                encoding="utf-8",
            )
            (raw_dir / "SQL_Injection_Prevention_Cheat_Sheet.meta.json").write_text(
                json.dumps({
                    "title": "SQL Injection Prevention Cheat Sheet",
                    "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    "cwe": "CWE-89",
                }),
                encoding="utf-8",
            )
            store_dir = tmp_p / "store"
            settings = Settings(llm_provider="ollama", ollama_model="qwen2.5:7b")
            ingest_documents(raw_dir, store_dir, settings, embedder=_MiniEmbedder())

            scan_file = tmp_p / "dvwa.log"
            scan_file.write_text(
                "Target URL: http://8.8.4.4/vulnerabilities/sqli/?id=1&Submit=Submit\n"
                "[11:21:57] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks\n"
                "---\n"
                "Parameter: id (GET)\n"
                "    Type: error-based\n"
                "    Title: MySQL >= 5.1 AND error-based\n"
                "    Payload: id=1' AND EXTRACTVALUE(1,1)-- a\n"
                "---\n"
                "back-end DBMS: MySQL >= 5.1\n",
                encoding="utf-8",
            )
            with patch("rag.embeddings.E5Embedding", return_value=_MiniEmbedder()), \
                 patch("rag.official_report.OllamaLLM", return_value=_CountingLLM()):
                out1 = tmp_p / "out1"
                run_corpus_report(
                    scan_file, out1, settings,
                    raw_directory=raw_dir, store_directory=store_dir,
                    format_="sqlmap-log", offline=True,
                    report_metadata={"xss_decision": "drop", "prepared_by": "Sinh viên A"},
                )
                first_call_count = len(llm_calls)
                # Only 1 source selection + 2 finding calls + 2 summary calls = 5 calls (0 wasted on dropped observation!)
                self.assertEqual(first_call_count, 5)

                # Re-exporting the exact same log with new cover metadata & unmasked IP uses SHA-256 AI cache -> ZERO extra LLM calls!
                out2 = tmp_p / "out2"
                run_corpus_report(
                    scan_file, out2, settings,
                    raw_directory=raw_dir, store_directory=store_dir,
                    format_="sqlmap-log", offline=True,
                    report_metadata={"xss_decision": "drop", "prepared_by": "Sinh viên B", "mask_public_ips": "false"},
                )
                self.assertEqual(len(llm_calls), first_call_count)
                md2 = (out2 / "pentest_report.md").read_text(encoding="utf-8")
                self.assertIn("Sinh viên B", md2)
                self.assertIn("8.8.4.4", md2)
                cached_trace = json.loads((out2 / "ai_trace.json").read_text(encoding="utf-8"))
                self.assertTrue(cached_trace["from_cache"])
                self.assertEqual(cached_trace["call_count"], 5)
                self.assertEqual(len(cached_trace["entries"]), 5)
                self.assertIn("SYSTEM PROMPT", (out2 / "ai_trace.txt").read_text(encoding="utf-8"))

                # Forcing fresh AI execution (`force_fresh_ai="true"`) runs live LLM calls again!
                out3 = tmp_p / "out3"
                run_corpus_report(
                    scan_file, out3, settings,
                    raw_directory=raw_dir, store_directory=store_dir,
                    format_="sqlmap-log", offline=True,
                    report_metadata={"xss_decision": "drop", "force_fresh_ai": "true"},
                )
                self.assertEqual(len(llm_calls), first_call_count + 5)
                live_trace = json.loads((out3 / "ai_trace.json").read_text(encoding="utf-8"))
                self.assertFalse(live_trace["from_cache"])
                self.assertEqual(live_trace["call_count"], 5)

    def test_web_trace_endpoint_and_multi_tool_flexibility(self):
        from dataclasses import asdict
        from rag.parsers import parse_zap
        from rag.parsers.native import parse_nuclei
        from rag.pentest_polish import prepare_pentest_view, render_pentest_markdown
        from rag.top10 import classify

        # 1) Real OWASP ZAP JSON with HTML `<p>` description/solution & raw_instance HTTP headers
        raw_zap = {
            "@version": "2.15.0",
            "@generated": "Thu, 22 Oct 2026 09:30:00",
            "site": [{
                "@name": "http://203.0.113.77:8080",
                "alerts": [{
                    "pluginid": "90022",
                    "alert": "Path Traversal",
                    "riskcode": "3",
                    "confidence": "3",
                    "cweid": "22",
                    "desc": "<p>Arbitrary file path supplied in file parameter reads local filesystem files.</p>",
                    "solution": "<p>Canonicalize file paths against an explicit base directory allowlist before reading files.</p>",
                    "instances": [{
                        "uri": "http://203.0.113.77:8080/download?file=../../etc/passwd",
                        "method": "GET",
                        "param": "file",
                        "attack": "../../etc/passwd",
                        "evidence": "root:x:0:0:root:/root:/bin/bash",
                        "requestHeader": "GET /download?file=..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\nHost: 203.0.113.77:8080",
                        "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/plain",
                        "responseBody": "root:x:0:0:root:/root:/bin/bash",
                    }],
                }],
            }],
        }
        zap_findings = parse_zap(raw_zap, "zap.json")
        zap_row = {**asdict(zap_findings[0]), "evidence": list(zap_findings[0].evidence)}
        zap_row["owasp_top10"] = classify(zap_row)
        zap_row["guidance"] = [{
            "id": "S1",
            "title": "File Upload Cheat Sheet",
            "section": "Input Validation / Path Traversal Prevention",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        }]
        zap_row["ai_analysis"] = {
            "status": "ai_reviewed",
            "claims": {
                "observations": [{"text_vi": "Công cụ ZAP ghi nhận tham số file tại /download đọc trực tiếp nội dung tệp /etc/passwd trên máy chủ."}],
                "potential_impacts": [{"text_vi": "Nếu ứng dụng chạy với quyền đọc rộng trên máy chủ, kẻ tấn công có thể đánh cắp tệp cấu hình và khóa bí mật nội bộ."}],
                "limitations": [],
            },
        }
        zap_report = {"schema_version": 1, "generated_at": "2026-10-22T09:00:00+00:00", "findings": [zap_row], "report_metadata": {"report_lang": "vi"}}
        view = prepare_pentest_view(zap_report)
        e0 = view["entries"][0]
        self.assertIn("203.0.113.77:8080", e0["url"])
        self.assertIn("GET /download?file=..%2F..%2Fetc%2Fpasswd HTTP/1.1", e0["request_text"])
        self.assertIn("HTTP/1.1 200 OK", e0["response_text"])
        self.assertIn("/etc/passwd", e0["description"])
        self.assertIn("khóa bí mật nội bộ", e0["impact_text"])
        self.assertIn("Canonicalize file paths", e0["remediation"]["text"])
        self.assertNotIn("<p>", e0["remediation"]["text"])
        self.assertIn("Path Traversal Prevention", e0["remediation"]["text"])
        md = render_pentest_markdown(zap_report)
        self.assertIn("A01:2025 Broken Access Control", md)
        self.assertNotIn("sqlmap", md.lower())
        self.assertNotIn("dvwa", md.lower())

        # 2) Real Nuclei JSONL with curl-command, native CVSS & native remediation
        nuc_line = json.dumps({
            "template-id": "ssrf-aws-metadata",
            "type": "http",
            "matched-at": "http://198.51.100.99/fetch?url=http://169.254.169.254/latest/meta-data/",
            "curl-command": "curl -X GET 'http://198.51.100.99/fetch?url=http://169.254.169.254/latest/meta-data/'",
            "response": "HTTP/1.1 200 OK\r\n\r\nami-id\niam/",
            "info": {
                "name": "Server-Side Request Forgery to Cloud Metadata",
                "severity": "critical",
                "remediation": "Validate outbound destination hosts against an explicit allowlist and block link-local metadata ranges.",
                "classification": {
                    "cwe-id": ["CWE-918"],
                    "cvss-score": 9.1,
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                },
            },
        })
        nuc_f = parse_nuclei(nuc_line, "nuclei.jsonl")[0]
        nuc_row = {**asdict(nuc_f), "evidence": list(nuc_f.evidence), "guidance": []}
        nuc_row["owasp_top10"] = classify(nuc_row)
        nuc_view = prepare_pentest_view({"schema_version": 1, "generated_at": "2026-10-22T09:00:00+00:00", "findings": [nuc_row], "report_metadata": {"report_lang": "en"}})
        ne0 = nuc_view["entries"][0]
        self.assertEqual(ne0["cvss_score"], "9.1")
        self.assertIn("curl -X GET", ne0["request_text"])
        self.assertIn("ami-id", ne0["response_text"])
        self.assertIn("Validate outbound destination hosts", ne0["remediation"]["text"])


if __name__ == "__main__":
    unittest.main()
