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
                pdf_bytes = opener.open(req_pdf).read()
                self.assertEqual(pdf_bytes[:4], b"%PDF")
            finally:
                server.shutdown()
                server.server_close()
                manager.close()


if __name__ == "__main__":
    unittest.main()
