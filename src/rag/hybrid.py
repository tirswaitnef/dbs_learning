"""Hybrid Retrieval Engine: Heading-Aware Okapi BM25 + Dense Cosine + Reciprocal Rank Fusion (RRF).

Enhances OWASP Cheat Sheet retrieval for Database & Web-to-DB security without adding external runtime
dependencies beyond standard library + NumPy:
  1. Hierarchical Markdown heading path extraction (`heading_path_at_offset`) so every character chunk
     is indexed together with its enclosing `H1 / H2 / H3` section context (BM25F heading boost).
  2. Code- & security-aware tokenizer (`tokenize_security_text`) preserving CWE IDs (`cwe-89`), SQL/API
     identifiers (`PDO::prepare`, `PreparedStatement`, `SqlCommand`, `mysql_secure_installation`,
     `bind-address`, `SQLSTATE`), camelCase/snake_case sub-tokens, and folded Unicode terms.
  3. Okapi BM25 (`BM25Index`) + Weighted Reciprocal Rank Fusion (`hybrid_search_store`) combining semantic
     similarity (`intfloat/multilingual-e5-small`) with exact lexical matching to rescue code/config blocks
     whose natural-language cosine score falls slightly below prose thresholds.
  4. Automatic multi-aspect query decomposition (`expand_retrieval_queries`) across OWASP Top 10:2025 CWEs.
"""
from __future__ import annotations

from collections import Counter
import math
import re
import threading
import unicodedata

import numpy as np

from .top10 import finding_cwes

_COMPOUND_TOKEN_RE = re.compile(r"[^\W_]+(?:(?:::|[-_./])[^\W_]+)+|[^\W_]{2,}")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "for", "from", "has", "have",
    "how", "if", "in", "into", "is", "it", "its", "may", "not", "of", "on", "or", "should", "such",
    "that", "the", "their", "then", "there", "these", "this", "to", "use", "used", "using", "via",
    "was", "we", "when", "where", "which", "with", "you", "your",
    "va", "cua", "cho", "trong", "voi", "cac", "mot", "nhung", "duoc", "khi", "theo", "tren", "tai",
})

_CWE_ASPECT_QUERIES: dict[str, tuple[str, ...]] = {
    "CWE-89": (
        "Query Parameterization prepared statement parameterized query bind variables safe code example",
        "SQL injection prevention additional defenses least privilege allow-list input validation",
        "error handling generic error message server side log SQL exception",
    ),
    "CWE-564": (
        "Query Parameterization ORM Hibernate HQL prepared statement bind parameters",
        "SQL injection prevention least privilege input validation",
    ),
    "CWE-943": (
        "NoSQL security parameterized query operator injection input validation MongoDB",
        "Database security least privilege authentication configuration",
    ),
    "CWE-78": (
        "OS command injection prevention avoid shell execution parameterized API input allow-list",
    ),
    "CWE-77": (
        "Injection prevention safe API parameterization escaping input validation",
    ),
    "CWE-79": (
        "Cross Site Scripting Prevention output encoding HTML entity JavaScript attribute context",
        "Content Security Policy CSP HttpOnly cookie framework auto-escaping DOM XSS",
    ),
    "CWE-80": (
        "Cross Site Scripting Prevention HTML entity encoding untrusted output",
    ),
    "CWE-306": (
        "Database Security configuring secure authentication localhost bind-address network isolation",
        "Authentication strong credentials disable anonymous access",
    ),
    "CWE-1393": (
        "Database Security default credentials remove anonymous test accounts mysql_secure_installation strong password",
        "Authentication password policy credential rotation",
    ),
    "CWE-521": (
        "Authentication strong password policy minimum length complexity brute force protection",
        "Database Security configuring secure authentication account lockout",
    ),
    "CWE-287": (
        "Authentication multi-factor authentication session verification secure credential handling",
        "Database Security configuring secure authentication",
    ),
    "CWE-798": (
        "Secrets Management environment variables vault rotate database credentials remove hardcoded password",
        "Database Security protecting credentials configuration",
    ),
    "CWE-250": (
        "Database Security least privilege dedicated application account avoid DBA root superuser",
        "Authorization principle of least privilege separation of duties",
    ),
    "CWE-269": (
        "Database Security creating secure permissions revoke administrative privileges",
        "Authorization role based access control privilege escalation prevention",
    ),
    "CWE-284": (
        "Authorization server side access control deny by default object permissions",
        "Database Security protecting backend database network and user permissions",
    ),
    "CWE-285": (
        "Authorization enforce permissions every request server side access control",
        "Database Security granular table view permissions",
    ),
    "CWE-862": (
        "Authorization verify access controls every endpoint deny by default",
    ),
    "CWE-863": (
        "Authorization horizontal vertical access control ownership check",
    ),
    "CWE-639": (
        "Insecure Direct Object Reference Prevention object level authorization indirect reference",
    ),
    "CWE-352": (
        "Cross-Site Request Forgery Prevention anti-CSRF token SameSite cookie",
    ),
    "CWE-319": (
        "Database Security implementing transport layer protection TLS encrypted connection",
        "Transport Layer Security TLS 1.3 strong cipher certificate verification HSTS",
    ),
    "CWE-311": (
        "Cryptographic Storage encryption at rest TLS transport protection key management",
    ),
    "CWE-326": (
        "Transport Layer Security strong key lengths AES-256 TLS 1.2 TLS 1.3",
    ),
    "CWE-327": (
        "Transport Layer Security disable weak ciphers SSLv3 TLS 1.0 RC4 MD5 SHA1",
    ),
    "CWE-328": (
        "Password Storage Argon2id bcrypt PBKDF2 salted password hashing",
    ),
    "CWE-295": (
        "Transport Layer Security certificate validation hostname verification trusted CA",
        "Database Security TLS certificate verification server client",
    ),
    "CWE-200": (
        "Error Handling disable detailed stack traces generic user message protect sensitive metadata",
    ),
    "CWE-209": (
        "Error Handling suppress SQL database error details generic HTTP error response server logging",
    ),
    "CWE-918": (
        "Server Side Request Forgery Prevention allow-list destination network egress isolation",
    ),
    "CWE-502": (
        "Deserialization avoid untrusted serialization strict type allow-list JSON data format",
    ),
    "CWE-778": (
        "Logging structured security audit events authentication authorization failures",
    ),
    "CWE-117": (
        "Logging encode sanitize log entries prevent log injection protect secrets",
    ),
}

_BM25_CACHE_LOCK = threading.Lock()
_BM25_CACHE: dict[tuple, "BM25Index"] = {}


def _strip_diacritics(text: str) -> str:
    folded = text.replace("đ", "d").replace("Đ", "D")
    nfkd = unicodedata.normalize("NFKD", folded)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def tokenize_security_text(text: str) -> list[str]:
    """Tokenize prose + security identifiers (`CWE-89`, `PDO::prepare`, `PreparedStatement`, Vietnamese)."""
    if not text:
        return []
    tokens: list[str] = []
    for raw_match in _COMPOUND_TOKEN_RE.finditer(text):
        raw = raw_match.group(0)
        low = raw.lower()
        folded = _strip_diacritics(low)
        has_sep = any(sep in low for sep in ("::", "-", "_", ".", "/"))
        if has_sep:
            tokens.append(folded)
            parts = re.split(r"(?:::|[-_./])+", raw)
        else:
            parts = [raw]
        for part in parts:
            if not part:
                continue
            subparts = _CAMEL_BOUNDARY_RE.split(part)
            if len(subparts) > 1:
                whole_p = _strip_diacritics(part.lower())
                if len(whole_p) >= 2 and whole_p not in _STOPWORDS:
                    tokens.append(whole_p)
            for sp in subparts:
                clean = _strip_diacritics(sp.lower())
                if len(clean) >= 2 and clean not in _STOPWORDS:
                    tokens.append(clean)
    return tokens


def heading_path_at_offset(markdown_text: str, offset: int) -> str:
    """Return hierarchical `H1 / H2 / H3` trail active at character `offset` (ignoring code fences)."""
    headings: list[str] = []
    fence: str | None = None
    pos = 0
    for line in markdown_text.splitlines(keepends=True):
        if pos > offset and headings:
            break
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            ch = marker.group(1)[0]
            if fence is None:
                fence = ch
            elif fence == ch:
                fence = None
        elif fence is None:
            m = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line.rstrip("\r\n"))
            if m and pos <= offset:
                level = len(m.group(1))
                headings = headings[: level - 1]
                headings.append(m.group(2).strip())
        pos += len(line)
    return " / ".join(headings)


class BM25Index:
    """Pure-Python / NumPy Okapi BM25 index with Markdown section-heading field boost."""

    def __init__(self, chunks: list[dict], documents=None, *, k1: float = 1.5, b: float = 0.75, heading_boost: int = 2):
        self.k1 = float(k1)
        self.b = float(b)
        self.n_docs = len(chunks)
        by_source = {d.source: d.text for d in (documents or [])}

        self.section_paths: list[str] = []
        self.doc_tfs: list[Counter[str]] = []
        doc_lens = np.zeros(self.n_docs, dtype=np.float32)
        df_counts: Counter[str] = Counter()

        for idx, ch in enumerate(chunks):
            src = str(ch.get("source") or "")
            full_md = by_source.get(src, "")
            sec_path = (
                str(ch.get("section") or "")
                or (heading_path_at_offset(full_md, int(ch.get("start", 0))) if full_md else "")
            )
            self.section_paths.append(sec_path)
            body_tokens = tokenize_security_text(str(ch.get("text") or ""))
            head_tokens = tokenize_security_text(sec_path) * max(0, int(heading_boost))
            src_tokens = tokenize_security_text(src.removesuffix(".md").replace("_", " "))
            combined = head_tokens + src_tokens + body_tokens
            tf = Counter(combined)
            self.doc_tfs.append(tf)
            doc_lens[idx] = float(len(combined))
            for term in tf:
                df_counts[term] += 1

        self.doc_lens = doc_lens
        self.avgdl = float(doc_lens.mean()) if self.n_docs > 0 and float(doc_lens.sum()) > 0 else 1.0
        self.idf: dict[str, float] = {
            term: math.log(1.0 + (self.n_docs - df + 0.5) / (df + 0.5))
            for term, df in df_counts.items()
        }
        # Inverted postings list for fast sub-millisecond scoring: term -> list[(doc_idx, tf)]
        self.postings: dict[str, list[tuple[int, int]]] = {}
        for doc_idx, tf in enumerate(self.doc_tfs):
            for term, freq in tf.items():
                self.postings.setdefault(term, []).append((doc_idx, freq))

    def score_all(self, query: str) -> np.ndarray:
        scores = np.zeros(self.n_docs, dtype=np.float32)
        if self.n_docs == 0:
            return scores
        q_terms = Counter(tokenize_security_text(query))
        if not q_terms:
            return scores
        k1 = self.k1
        b = self.b
        avgdl = self.avgdl
        dl = self.doc_lens
        for term, q_weight in q_terms.items():
            postings = self.postings.get(term)
            if not postings:
                continue
            idf = self.idf[term] * (1.0 + 0.25 * math.log1p(q_weight - 1))
            for doc_idx, tf in postings:
                denom = tf + k1 * (1.0 - b + b * (float(dl[doc_idx]) / avgdl))
                scores[doc_idx] += float(idf * (tf * (k1 + 1.0)) / denom)
        return scores


def get_or_build_bm25(store, documents=None) -> BM25Index:
    """Cache `BM25Index` per loaded `DocumentVectorStore` + corpus SHA-256."""
    key = (
        id(store),
        str(store.metadata.get("chunks_sha256") or ""),
        len(documents or []),
    )
    with _BM25_CACHE_LOCK:
        cached = _BM25_CACHE.get(key)
        if cached is not None:
            return cached
        idx = BM25Index(store.metadata["chunks"], documents)
        if len(_BM25_CACHE) > 8:
            _BM25_CACHE.clear()
        _BM25_CACHE[key] = idx
        return idx


def expand_retrieval_queries(finding, base_query: str) -> list[str]:
    """Decompose a security finding into complementary OWASP prevention & stack-specific sub-queries."""
    queries = [base_query]
    if finding is None:
        return queries
    cwes = finding_cwes(finding)
    for cwe in cwes:
        for aspect in _CWE_ASPECT_QUERIES.get(cwe, ()):
            if aspect not in queries:
                queries.append(aspect)

    details = finding.details if isinstance(finding.details, dict) else {}
    blob = " ".join([
        str(finding.title or ""),
        str(finding.location or ""),
        " ".join(str(x) for x in (finding.evidence or [])[:2]),
        str(details.get("dbms") or ""),
        str((details.get("scan_telemetry") or {}).get("web_tech") or ""),
    ]).lower()

    if "CWE-89" in cwes:
        if any(k in blob for k in ("php", "dvwa", "pdo", "mysqli", "wordpress", "laravel")):
            queries.append("Query Parameterization PHP Data Objects PDO prepare bindValue bindParam")
        elif any(k in blob for k in ("java", "spring", "jdbc", "tomcat", "jsp", "hibernate")):
            queries.append("Query Parameterization Java PreparedStatement setString Hibernate parameter")
        elif any(k in blob for k in ("asp.net", ".net", "csharp", "sql server", "mssql", "iis")):
            queries.append("Query Parameterization .NET SqlCommand Parameters AddWithValue")
        elif any(k in blob for k in ("oracle", "pl/sql", "ora-")):
            queries.append("Query Parameterization Oracle PL/SQL bind variables")

    if any(k in blob for k in ("mysql", "mariadb")):
        queries.append("Database Security hardening MySQL MariaDB authentication permissions")
    elif any(k in blob for k in ("mssql", "sql server")):
        queries.append("Database Security hardening Microsoft SQL Server permissions authentication")
    elif any(k in blob for k in ("postgres", "pg_")):
        queries.append("Database Security PostgreSQL authentication permissions TLS")
    elif any(k in blob for k in ("mongodb", "nosql")):
        queries.append("Database Security MongoDB authentication configuration NoSQL")

    return list(dict.fromkeys(queries))


def hybrid_search_store(
    store,
    documents,
    query_vector: np.ndarray,
    query_text: str,
    *,
    top_k: int = 24,
    min_score: float | None = 0.75,
    rrf_k: int = 6,
    w_dense: float = 0.50,
    w_bm25: float = 1.50,
) -> list[dict]:
    """Fuse Dense Cosine similarity + Heading-Boosted Okapi BM25 via Weighted Reciprocal Rank Fusion."""
    q = np.asarray(query_vector, dtype=np.float32)
    norm = float(np.linalg.norm(q))
    if q.ndim != 1 or q.shape[0] != store.vectors.shape[1] or not math.isfinite(norm) or norm == 0.0:
        raise ValueError("Invalid query vector for hybrid search")
    q = q / norm

    dense_scores = np.asarray(store.vectors @ q, dtype=np.float32)
    bm25_index = get_or_build_bm25(store, documents)
    bm25_scores = bm25_index.score_all(query_text)

    n = len(dense_scores)
    dense_order = np.argsort(-dense_scores, kind="stable")
    bm25_order = np.argsort(-bm25_scores, kind="stable")

    dense_ranks = np.empty(n, dtype=np.float32)
    dense_ranks[dense_order] = np.arange(1, n + 1, dtype=np.float32)

    bm25_ranks = np.empty(n, dtype=np.float32)
    bm25_ranks[bm25_order] = np.arange(1, n + 1, dtype=np.float32)

    # Rescue floor lets strong lexical hits on code/config blocks survive slightly lower prose cosine scores
    # without admitting anti-correlated / completely unrelated chunks.
    rescue_floor = -1.0 if min_score is None else max(0.0, float(min_score) - 0.15)
    passes_dense = np.ones(n, dtype=bool) if min_score is None else (dense_scores >= float(min_score))
    has_bm25 = bm25_scores > 0.0
    eligible_mask = passes_dense | (has_bm25 & (dense_scores >= rescue_floor))
    valid_indices = np.flatnonzero(eligible_mask)
    if valid_indices.size == 0:
        return []

    max_possible_rrf = (w_dense + w_bm25) / float(rrf_k + 1)
    rrf_raw = (
        w_dense / (float(rrf_k) + dense_ranks[valid_indices])
        + np.where(has_bm25[valid_indices], w_bm25 / (float(rrf_k) + bm25_ranks[valid_indices]), 0.0)
    )
    norm_scores = np.minimum(1.0, rrf_raw / max_possible_rrf) if max_possible_rrf > 0 else dense_scores[valid_indices]
    order = np.lexsort((
        valid_indices,
        -bm25_scores[valid_indices],
        -dense_scores[valid_indices],
        -norm_scores,
    ))[:top_k]

    chunks = store.metadata["chunks"]
    out: list[dict] = []
    for pos in order:
        idx = int(valid_indices[pos])
        out.append({
            **chunks[idx],
            "score": round(float(norm_scores[pos]), 6),
            "dense_score": round(float(dense_scores[idx]), 6),
            "bm25_score": round(float(bm25_scores[idx]), 6),
            "section": bm25_index.section_paths[idx],
            "retrieval_method": "hybrid-e5-bm25-rrf",
        })
    return out


def hybrid_search_multi_query(
    store,
    documents,
    embed_fn,
    sub_queries: list[str],
    *,
    top_k: int = 24,
    min_score: float | None = 0.75,
    aux_weight: float = 0.35,
    consensus_bonus: float = 0.08,
) -> list[dict]:
    """Execute primary + auxiliary aspect queries without letting generic sub-queries displace #1 specificity.

    Primary query (`sub_queries[0]`) carries weight `1.0`; complementary defense-in-depth sub-queries carry
    `aux_weight` (`0.45`), while multi-query agreement adds `consensus_bonus * sum(weighted_scores)`.
    """
    best_weighted: dict[tuple[str, int, int], float] = {}
    sum_weighted: dict[tuple[str, int, int], float] = {}
    exemplar: dict[tuple[str, int, int], dict] = {}
    q_weights = [1.0 if q_idx == 0 else aux_weight for q_idx in range(len(sub_queries))]
    norm_denom = max(1e-6, 1.0 + consensus_bonus * sum(q_weights))

    for q_idx, sq in enumerate(sub_queries):
        q_weight = q_weights[q_idx]
        q_vec = embed_fn(sq)
        for hit in hybrid_search_store(
            store,
            documents,
            q_vec,
            sq,
            top_k=top_k,
            min_score=min_score,
        ):
            key = (hit["source"], hit["start"], hit["end"])
            w_s = q_weight * float(hit["score"])
            sum_weighted[key] = sum_weighted.get(key, 0.0) + w_s
            if key not in best_weighted or w_s > best_weighted[key]:
                best_weighted[key] = w_s
                exemplar[key] = hit

    combined_out: list[dict] = []
    for key, base_hit in exemplar.items():
        agg = (best_weighted[key] + consensus_bonus * sum_weighted[key]) / norm_denom
        combined_out.append({**base_hit, "score": round(agg, 6)})
    combined_out.sort(key=lambda item: (-item["score"], -item["bm25_score"], -item["dense_score"]))
    return combined_out[: max(top_k, 32)]
