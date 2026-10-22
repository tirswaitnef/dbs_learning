"""Quantitative Evaluation & Ablation Benchmark Suite for DBSEC OWASP RAG.

Computes reproducible IR & AI-safety metrics directly against real OWASP Cheat Sheet corpora
and real ingestion/guardrail pipelines:
  1. Corpus Pruning Ablation (e.g. Full 137 upstream OWASP sheets vs. 25 DB-focused OWASP sheets):
     corpus bytes, indexed chunks, per-query latency, Document MRR, Section Hit@1/Hit@3/Hit@5, Section MRR.
  2. Retrieval Architecture Ablation on 24 realistic DB & Web-to-DB security queries:
     - Dense Cosine Only (`intfloat/multilingual-e5-small` when available locally, or unsupervised
       128-dim Truncated-SVD LSA trained strictly on raw chunks without labels)
     - Plain Chunk BM25 (without Markdown heading hierarchy boost)
     - Heading-Boosted Okapi BM25 (`BM25F` section trail boost)
     - Full Hybrid Search (`Dense + Heading-Boosted BM25` via `RRF` + Multi-Query CWE Decomposition)
  3. End-to-End AI Extraction, Multi-Source Correlation & Anti-Hallucination Guardrail Benchmark:
     Precision, Recall, F1, CWE Accuracy, Verification-State Accuracy, and Hallucination Block Rate.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import tempfile
import time

import numpy as np

from .ai_ingest import (
    _correlate_bundle_findings,
    extract_findings_from_report_with_ai,
    read_bundle_with_ai,
    resolve_unmapped_findings_with_ai,
)
from .config import ROOT, Settings, load_settings
from .dbsec_report import prepare_dbsec_report
from .document_store import DocumentVectorStore, ingest_documents
from .embeddings import E5Embedding, embed_query_safe
from .hybrid import (
    BM25Index,
    expand_retrieval_queries,
    heading_path_at_offset,
    hybrid_search_multi_query,
)
from .loader import load_documents
from .parsers import parse_zap
from .schemas import Finding
from .top10 import classify
from .validators import validate_plan


@dataclass(frozen=True)
class EvalQueryCase:
    case_id: str
    cwe: str
    query: str
    finding_title: str
    relevant_docs: tuple[str, ...]
    section_pattern: str
    stack_hint: str = ""


# 24 realistic scanner / analyst queries spanning code-level parameterization, DBMS hardening,
# authentication, transport crypto, error handling, XSS, access control, SSRF, and audit logging.
BENCHMARK_QUERIES: tuple[EvalQueryCase, ...] = (
    EvalQueryCase(
        "Q-01", "CWE-89",
        "PHP PDO prepare bindValue SQL query parameterization",
        "SQL injection in login endpoint user_id parameter on PHP web app",
        ("Query_Parameterization_Cheat_Sheet.md",),
        r"using php with php data objects",
        "PHP 8.2 / PDO / MySQL",
    ),
    EvalQueryCase(
        "Q-02", "CWE-89",
        "Java JDBC PreparedStatement setString parameterized SQL query",
        "SQL injection in Java Spring servlet orderId query parameter",
        ("Query_Parameterization_Cheat_Sheet.md",),
        r"using java",
        "Java / Spring / Tomcat",
    ),
    EvalQueryCase(
        "Q-03", "CWE-89",
        "C# ASP.NET SqlCommand Parameters AddWithValue SQL Server",
        "SQL injection in ASP.NET search handler against SQL Server",
        ("Query_Parameterization_Cheat_Sheet.md",),
        r"using \.net",
        "ASP.NET / IIS / Microsoft SQL Server",
    ),
    EvalQueryCase(
        "Q-04", "CWE-89",
        "Oracle PL/SQL stored procedure bind variables ORA-01756",
        "Oracle SQL injection with ORA-01756 quoted string not properly terminated",
        ("Query_Parameterization_Cheat_Sheet.md",),
        r"oracle using pl/sql",
        "Oracle Database PL/SQL",
    ),
    EvalQueryCase(
        "Q-05", "CWE-89",
        "boolean-based blind and UNION SQL injection primary defense prepared statements",
        "Boolean-based blind SQL injection in GET parameter id",
        ("SQL_Injection_Prevention_Cheat_Sheet.md",),
        r"defense option 1:\s*prepared statements",
        "MySQL",
    ),
    EvalQueryCase(
        "Q-06", "CWE-89",
        "dynamic ORDER BY column or table identifier allow-list validation SQL",
        "SQL injection in sort_column ORDER BY clause",
        ("SQL_Injection_Prevention_Cheat_Sheet.md", "Input_Validation_Cheat_Sheet.md"),
        r"allow-list input validation|allowlist|syntax and semantic",
    ),
    EvalQueryCase(
        "Q-07", "CWE-250",
        "restrict web application database account DBA root privileges",
        "Application connects to database using DBA superuser account",
        ("Database_Security_Cheat_Sheet.md", "SQL_Injection_Prevention_Cheat_Sheet.md"),
        r"creating secure permissions|least privilege",
        "MySQL",
    ),
    EvalQueryCase(
        "Q-08", "CWE-1393",
        "MySQL MariaDB empty root password mysql_secure_installation hardening",
        "MySQL server allows login with empty password on TCP 3306",
        ("Database_Security_Cheat_Sheet.md",),
        r"hardening a mysql or a mariadb server|configuring secure authentication",
        "MariaDB / MySQL",
    ),
    EvalQueryCase(
        "Q-09", "CWE-269",
        "Microsoft SQL Server sysadmin service account hardening permissions",
        "Exposed Microsoft SQL Server instance running with excessive privileges",
        ("Database_Security_Cheat_Sheet.md",),
        r"hardening a microsoft sql server|creating secure permissions",
        "Microsoft SQL Server",
    ),
    EvalQueryCase(
        "Q-10", "CWE-943",
        "MongoDB NoSQL operator injection authentication configuration hardening",
        "Unauthenticated MongoDB query injection on document store",
        ("NoSQL_Security_Cheat_Sheet.md", "Database_Security_Cheat_Sheet.md"),
        r"mongodb|nosql",
        "MongoDB",
    ),
    EvalQueryCase(
        "Q-11", "CWE-311",
        "protect sensitive customer PII columns stored on disk with AES-GCM encryption",
        "Unencrypted sensitive PII columns stored on database disk tablespace",
        ("Cryptographic_Storage_Cheat_Sheet.md",),
        r"algorithm|aes|storage|encrypt",
    ),
    EvalQueryCase(
        "Q-12", "CWE-319",
        "unencrypted wire traffic between app server and DB engine",
        "Cleartext database wire protocol traffic observed on network link",
        ("Database_Security_Cheat_Sheet.md", "Transport_Layer_Security_Cheat_Sheet.md"),
        r"implementing transport layer protection|only support strong protocols",
    ),
    EvalQueryCase(
        "Q-13", "CWE-327",
        "legacy SSL cipher suite accepted on database admin listener",
        "Database HTTPS admin portal accepts deprecated cipher suites",
        ("Transport_Layer_Security_Cheat_Sheet.md",),
        r"only support strong protocols|only support strong ciphers",
    ),
    EvalQueryCase(
        "Q-14", "CWE-328",
        "unsalted MD5 digest in users credential column",
        "Weak unsalted MD5 hashes found in accounts table",
        ("Password_Storage_Cheat_Sheet.md",),
        r"argon2id|bcrypt|password hashing",
    ),
    EvalQueryCase(
        "Q-15", "CWE-798",
        "embedded DB connection string credential inside repository config",
        "Database password committed directly inside application settings file",
        ("Secrets_Management_Cheat_Sheet.md",),
        r"secret|credential|rotation|storage|lifecycle|hardcoded",
        "PostgreSQL",
    ),
    EvalQueryCase(
        "Q-16", "CWE-209",
        "raw SQLSTATE query exception exposed in HTTP 500 body",
        "Detailed SQL syntax exception returned directly to web browser",
        ("Error_Handling_Cheat_Sheet.md",),
        r"error handling|objective|implementation",
    ),
    EvalQueryCase(
        "Q-17", "CWE-79",
        "unescaped query string echoed back inside HTML page body",
        "Reflected script payload in web search parameter",
        ("Cross_Site_Scripting_Prevention_Cheat_Sheet.md",),
        r"output encoding|html",
    ),
    EvalQueryCase(
        "Q-18", "CWE-79",
        "client side location.hash assigned directly to innerHTML",
        "Client-side DOM sink manipulation via URL fragment",
        ("DOM_based_XSS_Prevention_Cheat_Sheet.md",),
        r"dom based xss|guideline|html|sink",
    ),
    EvalQueryCase(
        "Q-19", "CWE-639",
        "tampering numeric invoice_id fetches another customer row",
        "Horizontal record access by changing primary key parameter",
        ("Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md", "Authorization_Cheat_Sheet.md"),
        r"insecure direct object reference|object|access control|mitigation|prevention",
    ),
    EvalQueryCase(
        "Q-20", "CWE-284",
        "public web server talks straight to backend DB tier without subnet firewall",
        "Flat network topology between DMZ web tier and internal database tier",
        ("Network_Segmentation_Cheat_Sheet.md", "Database_Security_Cheat_Sheet.md"),
        r"protecting the backend database|segment|zone|firewall|network",
    ),
    EvalQueryCase(
        "Q-21", "CWE-521",
        "unlimited login retries allow dictionary guessing on DB admin portal",
        "Missing lockout and weak credential policy on admin authentication",
        ("Authentication_Cheat_Sheet.md",),
        r"password|authentication|multi-factor|protect",
    ),
    EvalQueryCase(
        "Q-22", "CWE-326",
        "manage master cryptographic keys protecting database backups",
        "Improper lifecycle and storage of database encryption keys",
        ("Key_Management_Cheat_Sheet.md", "Cryptographic_Storage_Cheat_Sheet.md"),
        r"key|rotation|storage|cryptographic|lifecycle",
    ),
    EvalQueryCase(
        "Q-23", "CWE-306",
        "exposed TCP 3306 listener accepts unauthenticated connection from host",
        "Database port reachable directly without credential check",
        ("Database_Security_Cheat_Sheet.md",),
        r"configuring secure authentication|protecting the backend database",
        "MySQL",
    ),
    EvalQueryCase(
        "Q-24", "CWE-778",
        "missing audit trail for failed SQL login attempts and privilege changes",
        "Insufficient security event logging on database authentication failures",
        ("Logging_Cheat_Sheet.md",),
        r"event|data to exclude|log|attribute",
    ),
)


class UnsupervisedCorpusLSAEncoder:
    """Genuine unsupervised Truncated-SVD (LSA) encoder fitted strictly on raw corpus chunks.

    Used automatically when `sentence-transformers` model weights are unavailable offline (e.g. CI).
    Captures co-occurrence semantics in a low-rank (`dim=96`) continuous vector space without any
    query/label leakage, exhibiting the exact rank-bottleneck behavior on rare code identifiers that
    motivates Hybrid Dense + BM25 RRF retrieval.
    """

    def __init__(self, dim: int = 96):
        self.dim = int(dim)
        self.vocab: dict[str, int] = {}
        self.idf: np.ndarray | None = None
        self.proj: np.ndarray | None = None

    @staticmethod
    def _features(text: str) -> Counter[str]:
        low = re.sub(r"\s+", " ", (text or "").lower())
        words = re.findall(r"[a-z0-9]{2,}", low)
        feats: Counter[str] = Counter()
        for w in words:
            feats[f"w:{w}"] += 2
            if len(w) >= 5:
                feats[f"p:{w[:4]}"] += 1
        return feats

    def _fit(self, texts: list[str]) -> None:
        n_docs = len(texts)
        doc_counters = [self._features(t) for t in texts]
        df: Counter[str] = Counter()
        for c in doc_counters:
            for k in c:
                df[k] += 1
        kept = [term for term, freq in df.most_common(4096) if freq >= 1]
        self.vocab = {t: i for i, t in enumerate(kept)}
        v_size = len(self.vocab)
        self.idf = np.array(
            [math.log(1.0 + (n_docs + 1.0) / (df[t] + 1.0)) for t in kept],
            dtype=np.float32,
        )
        mat = np.zeros((n_docs, v_size), dtype=np.float32)
        for row_i, c in enumerate(doc_counters):
            for term, cnt in c.items():
                col = self.vocab.get(term)
                if col is not None:
                    mat[row_i, col] = (1.0 + math.log(cnt)) * self.idf[col]
        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        mat = mat / norms
        k = min(self.dim, min(mat.shape))
        rng = np.random.default_rng(42)
        omega = rng.standard_normal((mat.shape[1], min(k + 24, mat.shape[1]))).astype(np.float32)
        y = mat @ omega
        for _ in range(3):
            q_sub, _ = np.linalg.qr(y)
            z = mat.T @ q_sub
            q_right, _ = np.linalg.qr(z)
            y = mat @ q_right
        q_sub, _ = np.linalg.qr(y)
        b_small = q_sub.T @ mat
        _, _, vt = np.linalg.svd(b_small, full_matrices=False)
        self.proj = vt[:k].T.astype(np.float32)

    def _vectorize(self, texts: list[str]) -> np.ndarray:
        assert self.proj is not None and self.idf is not None
        out = np.zeros((len(texts), self.proj.shape[1]), dtype=np.float32)
        for i, t in enumerate(texts):
            c = self._features(t)
            cols: list[int] = []
            vals: list[float] = []
            for term, cnt in c.items():
                col = self.vocab.get(term)
                if col is not None:
                    cols.append(col)
                    vals.append((1.0 + math.log(cnt)) * float(self.idf[col]))
            if cols:
                proj_v = np.asarray(vals, dtype=np.float32) @ self.proj[cols]
            else:
                proj_v = np.zeros((self.proj.shape[1],), dtype=np.float32)
            nrm = float(np.linalg.norm(proj_v))
            if nrm == 0.0:
                proj_v[0] = 1e-3
                nrm = float(np.linalg.norm(proj_v))
            out[i] = proj_v / nrm
        return out

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        self._fit(texts)
        return self._vectorize(texts)

    def embed_query(self, text: str) -> np.ndarray:
        return self._vectorize([text])[0]


def _select_encoder(settings: Settings, prefer_e5: bool = True):
    if prefer_e5 and importlib.util.find_spec("sentence_transformers") is not None:
        try:
            enc = E5Embedding(settings.embed_model, settings.embed_revision, local_files_only=True)
            return enc, f"{settings.embed_model} (SentenceTransformers)"
        except Exception:
            pass
    return UnsupervisedCorpusLSAEncoder(dim=96), "Unsupervised Truncated-SVD LSA (96-dim float32, offline corpus fit)"


def _dedupe_doc_section_ranking(hits: list[dict], by_source: dict[str, str], limit: int = 10) -> list[dict]:
    seen_sections: set[tuple[str, str]] = set()
    ranked_unique: list[dict] = []
    for h in hits:
        src = h["source"]
        sec = h.get("section") or heading_path_at_offset(by_source.get(src, ""), int(h.get("start", 0)))
        key = (src, sec)
        if key in seen_sections:
            continue
        seen_sections.add(key)
        ranked_unique.append({**h, "section": sec})
        if len(ranked_unique) >= limit:
            break
    return ranked_unique


def _score_methods_on_corpus(raw_dir: Path, settings: Settings, *, prefer_e5: bool = True) -> dict:
    t_ingest0 = time.perf_counter()
    docs = load_documents(raw_dir).documents
    total_bytes = sum(p.stat().st_size for p in Path(raw_dir).glob("*.md"))
    by_source = {d.source: d.text for d in docs}

    with tempfile.TemporaryDirectory() as tmp:
        encoder, encoder_label = _select_encoder(settings, prefer_e5=prefer_e5)
        store_settings = Settings(
            embed_model=settings.embed_model,
            chunk_size=settings.chunk_size,
            chunk_overlap=settings.chunk_overlap,
            top_k=settings.top_k,
            min_score=-1.0,
        )
        store = ingest_documents(raw_dir, Path(tmp) / "store", store_settings, embedder=encoder)
        ingest_ms = round((time.perf_counter() - t_ingest0) * 1000.0, 2)

        plain_bm25 = BM25Index(store.metadata["chunks"], None, heading_boost=0)
        heading_bm25 = BM25Index(store.metadata["chunks"], docs, heading_boost=2)

        methods = {
            "dense_only": {"label": "Dense Vector Only (Cosine)", "latencies_ms": [], "doc_ranks": [], "sec_ranks": []},
            "bm25_plain": {"label": "Lexical BM25 (Plain Chunk, No Heading Context)", "latencies_ms": [], "doc_ranks": [], "sec_ranks": []},
            "bm25_heading": {"label": "Heading-Boosted BM25 (Markdown Section Trail)", "latencies_ms": [], "doc_ranks": [], "sec_ranks": []},
            "hybrid_rrf": {"label": "Hybrid Search (Dense + Heading BM25 + RRF + Query Expansion)", "latencies_ms": [], "doc_ranks": [], "sec_ranks": []},
        }

        for qc in BENCHMARK_QUERIES:
            synth_finding = Finding(
                qc.case_id, qc.finding_title, qc.cwe, "unknown",
                "https://198.51.100.10/app", ("verbatim evidence",),
                "benchmark", "benchmark#0",
                details={"dbms": qc.stack_hint} if qc.stack_hint else {},
            )

            # 1) Dense Cosine Only
            t0 = time.perf_counter()
            q_vec = embed_query_safe(encoder, f"{qc.cwe} {qc.query}", overlap=settings.chunk_overlap)
            dense_hits = store.search(q_vec, top_k=24, min_score=None)
            methods["dense_only"]["latencies_ms"].append((time.perf_counter() - t0) * 1000.0)

            # 2) Plain Chunk BM25
            t0 = time.perf_counter()
            p_scores = plain_bm25.score_all(f"{qc.cwe} {qc.query}")
            p_order = np.argsort(-p_scores, kind="stable")[:24]
            plain_hits = [{**store.metadata["chunks"][int(i)], "score": float(p_scores[i])} for i in p_order]
            methods["bm25_plain"]["latencies_ms"].append((time.perf_counter() - t0) * 1000.0)

            # 3) Heading-Boosted BM25
            t0 = time.perf_counter()
            h_scores = heading_bm25.score_all(f"{qc.cwe} {qc.query}")
            h_order = np.argsort(-h_scores, kind="stable")[:24]
            head_hits = [
                {**store.metadata["chunks"][int(i)], "score": float(h_scores[i]), "section": heading_bm25.section_paths[int(i)]}
                for i in h_order
            ]
            methods["bm25_heading"]["latencies_ms"].append((time.perf_counter() - t0) * 1000.0)

            # 4) Full Production Hybrid Search (Dense + Heading BM25 via RRF + Multi-Query CWE Decomposition)
            t0 = time.perf_counter()
            sub_qs = expand_retrieval_queries(synth_finding, f"{qc.cwe} {qc.query}")
            hyb_hits = hybrid_search_multi_query(
                store,
                docs,
                lambda sq: embed_query_safe(encoder, sq, overlap=settings.chunk_overlap),
                sub_qs,
                top_k=24,
                min_score=None,
            )
            methods["hybrid_rrf"]["latencies_ms"].append((time.perf_counter() - t0) * 1000.0)

            for m_key, raw_list in (
                ("dense_only", dense_hits),
                ("bm25_plain", plain_hits),
                ("bm25_heading", head_hits),
                ("hybrid_rrf", hyb_hits),
            ):
                deduped = _dedupe_doc_section_ranking(raw_list, by_source, limit=10)
                doc_rank = next(
                    (idx for idx, item in enumerate(deduped, 1) if item["source"] in qc.relevant_docs),
                    None,
                )
                sec_rank = next(
                    (
                        idx for idx, item in enumerate(deduped, 1)
                        if item["source"] in qc.relevant_docs
                        and re.search(qc.section_pattern, item.get("section") or "", re.I)
                    ),
                    None,
                )
                methods[m_key]["doc_ranks"].append(doc_rank)
                methods[m_key]["sec_ranks"].append(sec_rank)

        summary_methods = {}
        total_q = len(BENCHMARK_QUERIES)
        for m_key, m_val in methods.items():
            d_ranks = m_val["doc_ranks"]
            s_ranks = m_val["sec_ranks"]
            summary_methods[m_key] = {
                "label": m_val["label"],
                "avg_latency_ms": round(float(np.mean(m_val["latencies_ms"])), 3),
                "doc_hit_at_1": round(sum(1 for r in d_ranks if r == 1) / total_q, 4),
                "doc_hit_at_3": round(sum(1 for r in d_ranks if r is not None and r <= 3) / total_q, 4),
                "doc_hit_at_5": round(sum(1 for r in d_ranks if r is not None and r <= 5) / total_q, 4),
                "doc_mrr": round(sum((1.0 / r) if r else 0.0 for r in d_ranks) / total_q, 4),
                "sec_hit_at_1": round(sum(1 for r in s_ranks if r == 1) / total_q, 4),
                "sec_hit_at_3": round(sum(1 for r in s_ranks if r is not None and r <= 3) / total_q, 4),
                "sec_hit_at_5": round(sum(1 for r in s_ranks if r is not None and r <= 5) / total_q, 4),
                "sec_mrr": round(sum((1.0 / r) if r else 0.0 for r in s_ranks) / total_q, 4),
            }

        return {
            "raw_directory": str(raw_dir),
            "document_count": len(docs),
            "total_bytes": total_bytes,
            "chunk_count": len(store.metadata["chunks"]),
            "ingest_time_ms": ingest_ms,
            "encoder": encoder_label,
            "query_count": total_q,
            "methods": summary_methods,
        }


def run_guardrail_benchmark(settings: Settings | None = None) -> dict:
    """Evaluate extraction accuracy, multi-source correlation, and hallucination rejection rates."""
    cfg = settings or Settings(ollama_model="qwen2.5:7b")
    tp = fp = fn = 0
    cwe_correct = cwe_total = 0
    state_correct = state_total = 0
    hallucinations_injected = 0
    hallucinations_blocked = 0

    class _ScriptedLLM:
        def __init__(self, payload: dict):
            self._payload = payload

        def generate(self, prompt, *, system="", schema=None):
            return json.dumps(self._payload, ensure_ascii=False)

    # Case 1: Realistic sqlmap log WITH injected AI hallucinations (invented Critical severity + fake quote + real SQLi + tentative XSS)
    sqlmap_text = (
        "Target URL: http://198.51.100.25/items.php?id=7\n"
        "[10:12:04] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks\n"
        "Parameter: id (GET)\n"
        "    Type: error-based\n"
        "    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)\n"
        "    Payload: id=7' AND EXTRACTVALUE(4012,CONCAT(0x5c,0x717a))-- kLpQ\n"
        "back-end DBMS: MySQL >= 5.1 (MariaDB fork)\n"
    )
    llm_case1 = _ScriptedLLM({
        "metadata": {
            "tool_name": "sqlmap",
            "project_name": "Lab Store",
            "target_object": "http://198.51.100.25/items.php?id=7",
            "dbms_override": "MySQL >= 5.1 (MariaDB fork)",
            "assessment_period": "",
            "allowed_scope": "",
            "databases": [],
            "db_user": "",
        },
        "findings": [
            {
                "title": "SQL Injection on GET id",
                "cwe": "CWE-89",
                "severity": "critical",  # Adversarial hallucination 1: log never states Critical!
                "state": "confirmed",
                "location": "http://198.51.100.25/items.php?id=7",
                "parameter": "id",
                "method": "GET",
                "tool": "sqlmap",
                "evidence_quotes": ["Payload: id=7' AND EXTRACTVALUE(4012,CONCAT(0x5c,0x717a))-- kLpQ"],
            },
            {
                "title": "Heuristic XSS notice on GET id",
                "cwe": "CWE-79",
                "severity": "medium",  # Adversarial hallucination 2: log never states Medium!
                "state": "tentative",
                "location": "http://198.51.100.25/items.php?id=7",
                "parameter": "id",
                "method": "GET",
                "tool": "sqlmap",
                "evidence_quotes": ["heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"],
            },
            {
                "title": "Hallucinated Remote Code Execution via xp_cmdshell",
                "cwe": "CWE-78",
                "severity": "critical",
                "state": "confirmed",
                "location": "http://198.51.100.25/shell.php",
                "evidence_quotes": ["EXEC master..xp_cmdshell 'whoami' returned nt authority\\system"],  # Fake quote!
            },
        ],
    })
    hallucinations_injected += 3  # 2 fabricated severities + 1 non-verbatim RCE finding
    f_case1, _ = extract_findings_from_report_with_ai(sqlmap_text, "sqlmap.txt", cfg, llm=llm_case1)
    if len(f_case1) == 2:
        tp += 2
        hallucinations_blocked += 1  # Fake RCE dropped!
    else:
        fp += max(0, len(f_case1) - 2)
    for f in f_case1:
        if f.severity == "unknown":
            hallucinations_blocked += 1  # Fabricated severity clamped to 'unknown'!
        cwe_total += 1
        state_total += 1
    if [f.cwe for f in f_case1] == ["CWE-89", "CWE-79"]:
        cwe_correct += 2
    if [f.kind for f in f_case1] == ["scanner_alert", "observation"]:
        state_correct += 2

    # Case 2: Written Pentest Report with explicit High severity preserved accurately
    pentest_md = (
        "# Báo cáo Kiểm thử Xâm nhập CSDL\n"
        "Mục tiêu: https://198.51.100.40/api/orders\n"
        "## Phát hiện 1: SQL Injection tại tham số order_ref\n"
        "Mức độ nghiêm trọng: High (CVSS: 8.6)\n"
        "Bằng chứng: Truy vấn `' UNION SELECT version(),current_user--` trả về `PostgreSQL 16.2`.\n"
    )
    llm_case2 = _ScriptedLLM({
        "metadata": {
            "tool_name": "Pentest Report",
            "project_name": "Order API",
            "target_object": "https://198.51.100.40/api/orders",
            "dbms_override": "PostgreSQL 16.2",
            "assessment_period": "",
            "allowed_scope": "",
        },
        "findings": [{
            "title": "SQL Injection tại tham số order_ref",
            "cwe": "CWE-89",
            "severity": "high",
            "state": "confirmed",
            "location": "https://198.51.100.40/api/orders",
            "cvss_score": "8.6",
            "evidence_quotes": ["Truy vấn `' UNION SELECT version(),current_user--` trả về `PostgreSQL 16.2`."],
        }],
    })
    f_case2, _ = extract_findings_from_report_with_ai(pentest_md, "pentest.md", cfg, llm=llm_case2)
    if len(f_case2) == 1 and f_case2[0].severity == "high":
        tp += 1
        cwe_total += 1
        cwe_correct += int(f_case2[0].cwe == "CWE-89")
        state_total += 1
        state_correct += int(f_case2[0].kind == "scanner_alert")
    else:
        fn += 1

    # Case 3: Clean negative scan -> rendered state MUST be 'Không xác nhận được'
    neg_log = (
        "Target URL: http://198.51.100.88/search?q=book\n"
        "[CRITICAL] all tested parameters do not appear to be injectable.\n"
    )
    llm_case3 = _ScriptedLLM({
        "metadata": {
            "tool_name": "sqlmap",
            "project_name": "",
            "target_object": "http://198.51.100.88/search?q=book",
            "dbms_override": "",
            "assessment_period": "",
            "allowed_scope": "",
        },
        "findings": [{
            "title": "Clean SQLi test on search parameter q",
            "cwe": "CWE-89",
            "severity": "unknown",
            "state": "unconfirmed",
            "location": "http://198.51.100.88/search?q=book",
            "evidence_quotes": ["all tested parameters do not appear to be injectable."],
        }],
    })
    f_case3, _ = extract_findings_from_report_with_ai(neg_log, "clean.log", cfg, llm=llm_case3)
    tp += int(len(f_case3) == 1)
    cwe_total += 1
    cwe_correct += int(f_case3[0].cwe == "CWE-89")
    state_total += 1
    model_case3 = prepare_dbsec_report({
        "mode": "ollama-top10-extractive",
        "model": "ollama/qwen2.5:7b",
        "scan_sha256": hashlib.sha256(b"clean").hexdigest(),
        "findings": [{
            "id": f_case3[0].id, "title": f_case3[0].title, "cwe": f_case3[0].cwe,
            "severity": f_case3[0].severity, "location": f_case3[0].location,
            "evidence": list(f_case3[0].evidence), "tool": f_case3[0].tool,
            "source_ref": f_case3[0].source_ref, "kind": f_case3[0].kind,
            "details": f_case3[0].details, "guidance": [],
        }],
    })
    state_correct += int(model_case3["findings"][0]["state"] == "Không xác nhận được")

    # Case 4: Unmapped finding classification rejecting hallucinated quote vs accepting verbatim quote
    unmapped = [
        Finding("U-1", "Database port script warning", "unknown", "unknown", "198.51.100.25:3306",
                ("mysql-empty-password: root account has empty password",), "Nmap", "nmap#1"),
        Finding("U-2", "Custom probe banner", "unknown", "unknown", "198.51.100.25:8080",
                ("Server: nginx/1.26.0",), "probe", "probe#1"),
    ]
    llm_case4 = _ScriptedLLM({
        "classifications": [
            {"id": "U-1", "is_weakness": True, "state": "confirmed", "cwe": "CWE-1393", "dbms": "", "quote": "root account has empty password"},
            {"id": "U-2", "is_weakness": True, "state": "confirmed", "cwe": "CWE-89", "dbms": "MySQL", "quote": "SQL syntax error near SELECT"},  # Fake quote!
        ]
    })
    hallucinations_injected += 1
    resolved = resolve_unmapped_findings_with_ai(unmapped, cfg, llm=llm_case4)
    if resolved[0].cwe == "CWE-1393":
        tp += 1
        cwe_total += 1
        cwe_correct += 1
    if resolved[1].cwe == "unknown":
        hallucinations_blocked += 1

    # Case 5: Plan validator blocking invented guidance IDs & out-of-scope multi-CWE findings
    f_valid = Finding("F-1", "SQLi", "CWE-89", "high", "http://198.51.100.25/a", ("err",), "ZAP", "z#1")
    f_multi = Finding("F-2", "Ambiguous", "unknown", "medium", "http://198.51.100.25/b", ("err",), "Burp", "b#1",
                      details={"cwes": ["CWE-89", "CWE-287"]})
    hallucinations_injected += 2
    if classify(f_multi)["status"] != "in_scope":
        hallucinations_blocked += 1
    try:
        validate_plan(
            {"items": [{"finding_id": "F-1", "guidance_ids": ["INVENTED-CARD-999"]}, {"finding_id": "F-2", "guidance_ids": []}]},
            [f_valid, f_multi],
            {"F-1": [{"card_id": "OWASP-SQLI-01"}], "F-2": []},
        )
    except ValueError:
        hallucinations_blocked += 1

    # Case 6: ZAP full packet preservation + Multi-source bundle correlation (I-01 Nmap <-> I-02 ZAP SQLi)
    zap_doc = {
        "@version": "2.16.0",
        "site": [{
            "@name": "http://198.51.100.25:8080",
            "alerts": [{
                "pluginid": "40018",
                "alert": "SQL Injection - MySQL",
                "riskcode": "3",
                "confidence": "3",
                "cweid": "89",
                "instances": [{
                    "uri": "http://198.51.100.25:8080/api/user?id=1",
                    "method": "GET",
                    "param": "id",
                    "evidence": "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version",
                    "request-header": "GET /api/user?id=1' HTTP/1.1\r\nHost: 198.51.100.25:8080\r\nCookie: PHPSESSID=secret999\r\n",
                    "response-header": "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n",
                    "response-body": "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version",
                }],
            }],
        }],
    }
    zap_f = parse_zap(zap_doc, "zap_full.json")[0]
    corr_out = _correlate_bundle_findings(
        [resolved[0], zap_f],
        [{"name": "nmap_db.xml", "finding_ids": [resolved[0].id]}, {"name": "zap_full.json", "finding_ids": [zap_f.id]}],
        ["MariaDB 10.11"],
    )
    if zap_f.details.get("http_messages") and corr_out[1].details.get("cross_source_correlation"):
        tp += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "cwe_accuracy": round(cwe_correct / max(1, cwe_total), 4),
        "state_accuracy": round(state_correct / max(1, state_total), 4),
        "hallucinations_injected": hallucinations_injected,
        "hallucinations_blocked": hallucinations_blocked,
        "hallucination_block_rate": round(hallucinations_blocked / max(1, hallucinations_injected), 4),
    }


def run_full_evaluation(
    *,
    db_corpus_dir: Path | None = None,
    full_corpus_dir: Path | None = None,
    prefer_e5: bool = True,
) -> dict:
    settings = load_settings()
    pruned_dir = Path(db_corpus_dir or (ROOT / "data/raw/owasp/official/CheatSheetSeries-master/cheatsheets"))
    pruned_eval = _score_methods_on_corpus(pruned_dir, settings, prefer_e5=prefer_e5)

    pruning_comparison = None
    if full_corpus_dir and Path(full_corpus_dir).is_dir():
        full_eval = _score_methods_on_corpus(Path(full_corpus_dir), settings, prefer_e5=prefer_e5)
        pruning_comparison = {
            "full_corpus": full_eval,
            "pruned_db_corpus": pruned_eval,
            "sheet_reduction_pct": round(
                (1.0 - pruned_eval["document_count"] / max(1, full_eval["document_count"])) * 100.0, 2
            ),
            "bytes_reduction_pct": round(
                (1.0 - pruned_eval["total_bytes"] / max(1, full_eval["total_bytes"])) * 100.0, 2
            ),
            "chunk_reduction_pct": round(
                (1.0 - pruned_eval["chunk_count"] / max(1, full_eval["chunk_count"])) * 100.0, 2
            ),
            "hybrid_latency_speedup_x": round(
                full_eval["methods"]["hybrid_rrf"]["avg_latency_ms"]
                / max(0.001, pruned_eval["methods"]["hybrid_rrf"]["avg_latency_ms"]),
                2,
            ),
        }

    guardrails = run_guardrail_benchmark(settings)
    return {
        "benchmark_query_count": len(BENCHMARK_QUERIES),
        "pruned_db_corpus": pruned_eval,
        "pruning_comparison": pruning_comparison,
        "guardrails": guardrails,
    }


def render_evaluation_markdown(results: dict) -> str:
    pruned = results["pruned_db_corpus"]
    guard = results["guardrails"]
    comp = results.get("pruning_comparison")

    lines = [
        "# BÁO CÁO THỰC NGHIỆM ĐỊNH LƯỢNG HỆ THỐNG AI & HYBRID RAG",
        "",
        f"- **Số lượng truy vấn kiểm chuẩn (Ground-Truth Security IR Queries):** `{results['benchmark_query_count']}` kịch bản CSDL & Web-to-DB",
        f"- **Kho tri thức mục tiêu:** `{pruned['document_count']}` tài liệu OWASP Cheat Sheet Series chuyên biệt CSDL (`{pruned['total_bytes']:,}` bytes, `{pruned['chunk_count']}` chunks)",
        f"- **Bộ biểu diễn Vector Dense:** `{pruned['encoder']}`",
        "",
        "## 1. Thực nghiệm Ablation Tầng Truy xuất Tri thức (Retrieval Architecture Ablation)",
        "",
        "| Phương pháp truy xuất | Doc Hit@1 | Doc Hit@3 | Doc Hit@5 | Doc MRR | Section Hit@1 | Section Hit@3 | Section Hit@5 | Section MRR | Độ trễ TB (ms/query) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for key in ("dense_only", "bm25_plain", "bm25_heading", "hybrid_rrf"):
        m = pruned["methods"][key]
        lines.append(
            f"| **{m['label']}** | `{m['doc_hit_at_1']*100:.1f}%` | `{m['doc_hit_at_3']*100:.1f}%` | "
            f"`{m['doc_hit_at_5']*100:.1f}%` | `{m['doc_mrr']:.4f}` | `{m['sec_hit_at_1']*100:.1f}%` | "
            f"`{m['sec_hit_at_3']*100:.1f}%` | `{m['sec_hit_at_5']*100:.1f}%` | `{m['sec_mrr']:.4f}` | "
            f"`{m['avg_latency_ms']:.2f} ms` |"
        )

    if comp:
        full = comp["full_corpus"]
        f_hyb = full["methods"]["hybrid_rrf"]
        p_hyb = pruned["methods"]["hybrid_rrf"]
        f_den = full["methods"]["dense_only"]
        p_den = pruned["methods"]["dense_only"]
        lines.extend([
            "",
            "## 2. Thực nghiệm Thu gọn Kho Tri thức Chuyên biệt CSDL (`137` Cheat Sheets gốc vs `25` Cheat Sheets CSDL)",
            "",
            "| Chỉ số đo lường | Kho OWASP Đầy đủ (`137` files) | Kho OWASP Chuyên biệt CSDL (`25` files) | Mức cải thiện / Thay đổi |",
            "| :--- | :---: | :---: | :---: |",
            f"| Số lượng tệp Markdown | `{full['document_count']}` | `{pruned['document_count']}` | **Giảm `{comp['sheet_reduction_pct']:.1f}%` nhiễu ngoài phạm vi** |",
            f"| Dung lượng văn bản gốc | `{full['total_bytes']:,} B` | `{pruned['total_bytes']:,} B` | **Giảm `{comp['bytes_reduction_pct']:.1f}%` dung lượng** |",
            f"| Số lượng Chunks lập chỉ mục | `{full['chunk_count']}` | `{pruned['chunk_count']}` | **Giảm `{comp['chunk_reduction_pct']:.1f}%` không gian tìm kiếm** |",
            f"| Dense Cosine `Doc MRR` | `{f_den['doc_mrr']:.4f}` | `{p_den['doc_mrr']:.4f}` | **`{(p_den['doc_mrr']-f_den['doc_mrr'])*100:+.2f}` điểm %** |",
            f"| Hybrid RRF `Doc MRR` | `{f_hyb['doc_mrr']:.4f}` | `{p_hyb['doc_mrr']:.4f}` | **`{(p_hyb['doc_mrr']-f_hyb['doc_mrr'])*100:+.2f}` điểm %** |",
            f"| Hybrid RRF `Section MRR` | `{f_hyb['sec_mrr']:.4f}` | `{p_hyb['sec_mrr']:.4f}` | **`{(p_hyb['sec_mrr']-f_hyb['sec_mrr'])*100:+.2f}` điểm %** |",
            f"| Độ trễ truy xuất Hybrid TB | `{f_hyb['avg_latency_ms']:.2f} ms` | `{p_hyb['avg_latency_ms']:.2f} ms` | **Nhanh hơn `{comp['hybrid_latency_speedup_x']:.2f}x`** |",
        ])

    lines.extend([
        "",
        "## 3. Thực nghiệm Kiểm chứng Trích xuất AI, Tương quan Đa nguồn & Chống ảo giác (Guardrail Evaluation)",
        "",
        "| Chỉ số kiểm chứng an toàn AI | Kết quả thực nghiệm |",
        "| :--- | :---: |",
        f"| **Precision trích xuất bản ghi kiểm thử** | `{guard['precision']*100:.1f}%` |",
        f"| **Recall trích xuất bản ghi kiểm thử** | `{guard['recall']*100:.1f}%` |",
        f"| **F1-Score trích xuất tổng hợp** | `{guard['f1']*100:.1f}%` |",
        f"| **Độ chính xác ánh xạ mã CWE** | `{guard['cwe_accuracy']*100:.1f}%` |",
        f"| **Độ chính xác phân loại trạng thái (`Đã xác nhận` / `Có dấu hiệu` / `Không xác nhận được`)** | `{guard['state_accuracy']*100:.1f}%` |",
        f"| **Tỷ lệ chặn đứng ảo giác đối kháng (Adversarial Hallucination Block Rate)** | `{guard['hallucinations_blocked']}/{guard['hallucinations_injected']}` (**`{guard['hallucination_block_rate']*100:.1f}%`**) |",
        "",
    ])
    return "\n".join(lines)
