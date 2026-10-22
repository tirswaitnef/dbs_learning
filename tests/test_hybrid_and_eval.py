import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rag.ai_ingest import _verify_explicit_severity, extract_findings_from_report_with_ai, read_bundle_with_ai
from rag.config import Settings
from rag.dbsec_report import prepare_dbsec_report, render_dbsec_markdown
from rag.document_store import ingest_documents
from rag.eval_benchmark import run_full_evaluation, run_guardrail_benchmark
from rag.hybrid import (
    BM25Index,
    expand_retrieval_queries,
    heading_path_at_offset,
    hybrid_search_store,
    tokenize_security_text,
)
from rag.official_report import run_corpus_report
from rag.parsers import parse_zap
from rag.schemas import Finding


class HybridRetrievalAndEvaluationTests(unittest.TestCase):
    def test_heading_aware_bm25_and_security_tokenizer(self):
        toks = tokenize_security_text("CWE-89 PDO::prepare PreparedStatement mysql_secure_installation bảo mật CSDL")
        for expected in ("cwe-89", "pdo::prepare", "pdo", "prepare", "preparedstatement", "prepared", "statement",
                         "mysql_secure_installation", "bao", "mat", "csdl"):
            self.assertIn(expected, toks)

        md = (
            "# Query Parameterization Cheat Sheet\n\n"
            "## Using PHP with PHP Data Objects\n"
            "```php\n"
            "# comment inside code fence must NOT overwrite heading\n"
            "$stmt = $dbh->prepare('SELECT id FROM users WHERE mail = :mail');\n"
            "```\n"
        )
        code_pos = md.index("$stmt")
        self.assertEqual(
            heading_path_at_offset(md, code_pos),
            "Query Parameterization Cheat Sheet / Using PHP with PHP Data Objects",
        )

    def test_hybrid_rrf_rescues_code_snippet_below_prose_threshold_and_rejects_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw_dir = Path(tmp) / "raw"
            raw_dir.mkdir()
            (raw_dir / "Query_Parameterization_Cheat_Sheet.md").write_text(
                "# Query Parameterization Cheat Sheet\n\n"
                "## Using PHP with PHP Data Objects\n"
                "$stmt = $dbh->prepare('SELECT name FROM customers WHERE id = :id');\n",
                encoding="utf-8",
            )
            (raw_dir / "Authentication_Cheat_Sheet.md").write_text(
                "# Authentication Cheat Sheet\n\n"
                "## General Guidelines\n"
                "Ensure login flows validate session state consistently across web pages.\n",
                encoding="utf-8",
            )
            (raw_dir / "Unrelated_Sheet.md").write_text(
                "# Unrelated Topic\n\n## Overview\nCompletely orthogonal prose without matching terms.\n",
                encoding="utf-8",
            )

            class _ControlledEmbedder:
                def embed_documents(self, texts):
                    vecs = []
                    for t in texts:
                        if "dbh->prepare" in t:
                            # Code block has slightly lower cosine similarity (0.68 < 0.75) than prose (0.80)
                            vecs.append([0.68, 0.7332121, 0.0])
                        elif "General Guidelines" in t:
                            vecs.append([0.80, 0.60, 0.0])
                        else:
                            vecs.append([0.10, 0.0, 0.9949874])
                    return np.asarray(vecs, dtype=np.float32)

                def embed_query(self, text):
                    return np.asarray([1.0, 0.0, 0.0], dtype=np.float32)

            cfg = Settings(embed_model="controlled-e5", min_score=0.75)
            store = ingest_documents(raw_dir, Path(tmp) / "store", cfg, embedder=_ControlledEmbedder())
            from rag.loader import load_documents
            docs = load_documents(raw_dir).documents

            hits = hybrid_search_store(
                store, docs, np.array([1.0, 0.0, 0.0], dtype=np.float32),
                "CWE-89 PHP PDO prepare parameterized query",
                min_score=0.75,
            )
            sources = [h["source"] for h in hits]
            self.assertEqual(sources[0], "Query_Parameterization_Cheat_Sheet.md")
            self.assertNotIn("Unrelated_Sheet.md", sources)

            finding = Finding("F-1", "SQLi in PHP login", "CWE-89", "unknown", "http://198.51.100.10/login.php", ("err",), "sqlmap", "s#1")
            expanded = expand_retrieval_queries(finding, "CWE-89 SQLi")
            self.assertTrue(any("PDO" in q for q in expanded))

    def test_severity_hallucination_clamped_while_explicit_severity_preserved(self):
        sqlmap_noise = (
            "sqlmap -u http://198.51.100.25/vuln.php?id=1 --cookie='PHPSESSID=abc; security=low' --level=5 --risk=3\n"
            "[12:01:02] [CRITICAL] connection timed out to target\n"
            "Parameter: id (GET)\n    Type: boolean-based blind\n"
        )
        for invented in ("critical", "high", "medium", "low", "informational"):
            self.assertEqual(_verify_explicit_severity(invented, sqlmap_noise), "unknown")

        self.assertEqual(_verify_explicit_severity("high", "Mức độ nghiêm trọng: Cao\nSQL Injection"), "high")
        self.assertEqual(_verify_explicit_severity("critical", "Severity: Critical (CVSS 9.8)"), "critical")
        self.assertEqual(_verify_explicit_severity("high", '{"riskcode": "3", "alert": "SQLi"}'), "high")
        self.assertEqual(_verify_explicit_severity("medium", "<severity>Medium</severity>"), "medium")

    def test_ai_cache_invalidates_when_vector_store_meta_corpus_sha_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            raw_dir = tmp_p / "raw"
            raw_dir.mkdir()
            sheet_file = raw_dir / "SQL_Injection_Prevention_Cheat_Sheet.md"
            sheet_file.write_text(
                "# SQL Injection Prevention Cheat Sheet\n\n"
                "## Defense Option 1: Prepared Statements (with Parameterized Queries)\n"
                "Parameterized queries ensure the database treats user input strictly as data and never executable SQL.\n",
                encoding="utf-8",
            )
            store_dir = tmp_p / "store"
            settings = Settings(ollama_model="qwen2.5:7b")

            class _UnitEmbedder:
                def embed_documents(self, texts):
                    return np.ones((len(texts), 8), dtype=np.float32)

                def embed_query(self, text):
                    return np.ones((8,), dtype=np.float32)

            ingest_documents(raw_dir, store_dir, settings, embedder=_UnitEmbedder())
            scan_file = tmp_p / "scan.log"
            scan_file.write_text(
                "Target URL: http://198.51.100.55/item.php?id=1\n"
                "Parameter: id (GET)\n"
                "    Type: error-based\n"
                "    Payload: id=1' AND EXTRACTVALUE(1,1)-- a\n",
                encoding="utf-8",
            )
            call_counter = []

            class _MockOllama:
                def generate(self, prompt, *, system="", schema=None):
                    call_counter.append(1)
                    data = json.loads(prompt)
                    if "input_text" in data:
                        return json.dumps({
                            "metadata": {
                                "project_name": "Cache Test",
                                "target_object": "http://198.51.100.55/item.php?id=1",
                                "dbms_override": "MySQL",
                                "assessment_period": "",
                                "allowed_scope": "",
                            },
                            "findings": [{
                                "title": "SQL Injection on id",
                                "cwe": "CWE-89",
                                "severity": "critical",  # Must also be clamped to 'unknown'!
                                "state": "confirmed",
                                "location": "http://198.51.100.55/item.php?id=1",
                                "evidence_quotes": ["Payload: id=1' AND EXTRACTVALUE(1,1)-- a"],
                            }],
                        })
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
                        "potential_impacts": [{"text_vi": "Nếu triển khai thực tế, kẻ tấn công có thể đọc dữ liệu.", "citations": [{"source_id": first_sid, "quote": quote}]}],
                        "limitations": [],
                    }, ensure_ascii=False)

            with patch("rag.embeddings.E5Embedding", return_value=_UnitEmbedder()), \
                 patch("rag.official_report.OllamaLLM", return_value=_MockOllama()):
                run_corpus_report(scan_file, tmp_p / "out1", settings, raw_directory=raw_dir, store_directory=store_dir, format_="sqlmap-log", offline=True)
                first_calls = len(call_counter)
                rep1 = json.loads((tmp_p / "out1" / "report.json").read_text(encoding="utf-8"))
                self.assertEqual(rep1["findings"][0]["severity"], "unknown")

                # Re-running with identical corpus uses cache
                run_corpus_report(scan_file, tmp_p / "out2", settings, raw_directory=raw_dir, store_directory=store_dir, format_="sqlmap-log", offline=True)
                self.assertEqual(len(call_counter), first_calls)

                # Updating OWASP corpus & re-ingesting changes vector_store.meta.json corpus_sha256 -> cache MUST invalidate!
                sheet_file.write_text(
                    sheet_file.read_text(encoding="utf-8") + "\nAlways bind every dynamic parameter strictly.\n",
                    encoding="utf-8",
                )
                ingest_documents(raw_dir, store_dir, settings, embedder=_UnitEmbedder())
                run_corpus_report(scan_file, tmp_p / "out3", settings, raw_directory=raw_dir, store_directory=store_dir, format_="sqlmap-log", offline=True)
                self.assertGreater(len(call_counter), first_calls)

    def test_zap_http_messages_and_bundle_cross_source_correlation_in_section_6_7(self):
        zap_payload = {
            "@version": "2.16.0",
            "site": [{
                "@name": "http://203.0.113.45:8080",
                "alerts": [{
                    "pluginid": "40018",
                    "alert": "SQL Injection - MySQL",
                    "riskcode": "3",
                    "confidence": "3",
                    "cweid": "89",
                    "instances": [{
                        "uri": "http://203.0.113.45:8080/orders?id=9",
                        "method": "GET",
                        "param": "id",
                        "evidence": "You have an error in your SQL syntax",
                        "request-header": "GET /orders?id=9' HTTP/1.1\r\nHost: 203.0.113.45:8080\r\nCookie: PHPSESSID=topsecret888\r\n",
                        "response-header": "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n",
                        "response-body": "You have an error in your SQL syntax",
                    }],
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p_nmap = Path(tmp) / "nmap_db.txt"
            p_zap = Path(tmp) / "zap_web.json"
            p_nmap.write_text("Host: 203.0.113.45\n3306/tcp open mysql MariaDB 10.11\n| mysql-empty-password: root account has empty password\n", encoding="utf-8")
            p_zap.write_text(json.dumps(zap_payload, ensure_ascii=False), encoding="utf-8")

            parsed_zap = parse_zap(zap_payload, "zap_web.json")
            self.assertEqual(len(parsed_zap[0].details["http_messages"]), 1)
            self.assertIn("GET /orders?id=9' HTTP/1.1", parsed_zap[0].details["http_messages"][0]["request"])

            class _BundleLLM:
                def generate(self, prompt, *, system="", schema=None):
                    if "mysql-empty-password" in prompt:
                        return json.dumps({
                            "metadata": {"project_name": "", "target_object": "203.0.113.45:3306", "dbms_override": "MariaDB 10.11", "assessment_period": "", "allowed_scope": ""},
                            "findings": [{
                                "title": "MySQL empty root password on 3306/tcp",
                                "cwe": "CWE-1393",
                                "severity": "unknown",
                                "state": "confirmed",
                                "location": "203.0.113.45:3306",
                                "tool": "Nmap",
                                "evidence_quotes": ["mysql-empty-password: root account has empty password"],
                            }],
                        })
                    return json.dumps({
                        "metadata": {"project_name": "Order Portal", "target_object": "http://203.0.113.45:8080", "dbms_override": "", "assessment_period": "", "allowed_scope": ""},
                        "findings": [{
                            "title": "SQL Injection on GET id",
                            "cwe": "CWE-89",
                            "severity": "high",
                            "state": "confirmed",
                            "location": "http://203.0.113.45:8080/orders?id=9",
                            "parameter": "id",
                            "method": "GET",
                            "tool": "OWASP ZAP",
                            "evidence_quotes": ["You have an error in your SQL syntax"],
                        }],
                    })

            findings, meta, sources = read_bundle_with_ai(
                [
                    {"path": str(p_nmap), "name": "nmap_db.txt", "format": "pentest-report"},
                    {"path": str(p_zap), "name": "zap_web.json", "format": "zap"},
                ],
                Settings(ollama_model="qwen2.5:7b"),
                llm=_BundleLLM(),
            )
            self.assertEqual(len(findings), 2)
            self.assertIn("I-01:", findings[1].details["cross_source_correlation"])
            self.assertEqual(findings[1].details["dbms"], "MariaDB 10.11")

            from rag.top10 import classify
            rep = {
                "mode": "ollama-top10-extractive",
                "model": "ollama/qwen2.5:7b",
                "scan_sha256": hashlib.sha256(b"bundle").hexdigest(),
                "input_sources": sources,
                "report_metadata": meta,
                "findings": [
                    {
                        "id": f.id, "title": f.title, "cwe": f.cwe, "severity": f.severity,
                        "location": f.location, "evidence": list(f.evidence), "tool": f.tool,
                        "source_ref": f.source_ref, "kind": f.kind, "details": f.details, "guidance": [],
                        "owasp_top10": classify(f),
                    }
                    for f in findings
                ],
            }
            md = render_dbsec_markdown(prepare_dbsec_report(rep))
            self.assertIn("Tương quan rủi ro liên nguồn", md)
            self.assertNotIn("topsecret888", md)
            self.assertIn("[REDACTED]", md)

    def test_quantitative_evaluation_suite_and_cli_script(self):
        guard = run_guardrail_benchmark()
        self.assertEqual(guard["f1"], 1.0)
        self.assertEqual(guard["hallucination_block_rate"], 1.0)

        res = run_full_evaluation(prefer_e5=False)
        methods = res["pruned_db_corpus"]["methods"]
        self.assertGreater(methods["hybrid_rrf"]["doc_mrr"], methods["dense_only"]["doc_mrr"])
        self.assertGreater(methods["hybrid_rrf"]["sec_mrr"], methods["dense_only"]["sec_mrr"])
        self.assertGreater(methods["bm25_heading"]["sec_mrr"], methods["bm25_plain"]["sec_mrr"])

        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/eval_rag.py"), "--offline-svd"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        self.assertIn("BÁO CÁO THỰC NGHIỆM ĐỊNH LƯỢNG HỆ THỐNG AI & HYBRID RAG", proc.stdout)


if __name__ == "__main__":
    unittest.main()
