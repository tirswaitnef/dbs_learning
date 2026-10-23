"""Conversational Pentest & OWASP Database Security Assistant Engine.

Powers genuine multi-turn chatbot interactions (`/api/chat`) grounded simultaneously on:
1. The active session's analyzed report (`report.json` formatted via `prepare_compact_pentest`), if any.
2. Live Hybrid BM25 + E5 RRF retrieval over the bundled 25 OWASP Database Security Cheat Sheets & Top 10:2025.
3. Local Ollama LLM (`OllamaLLM`) when running in live mode, with deterministic grounded Markdown synthesis in demo/offline fallback so every message receives an immediate, helpful, cited answer.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .compact_pentest_template import prepare_compact_pentest
from .config import Settings

RAW_SCAN_PATTERNS = (
    re.compile(r'<\?xml[^>]*>.*<(?:nmaprun|OWASPZAPReport|issues|NessusClientData_v2)\b', re.S | re.I),
    re.compile(r'Parameter:\s*\S+\s*\((?:GET|POST|PUT|COOKIE|HEADER|URI)', re.I),
    re.compile(r'back-end DBMS:\s*\S+', re.I),
    re.compile(r'Nmap scan report for\s+\S+', re.I),
    re.compile(r'PORT\s+STATE\s+SERVICE', re.I),
    re.compile(r'"@version"\s*:\s*"[^"]+".*"site"\s*:\s*\[', re.S),
    re.compile(r'"template-id"\s*:\s*"[^"]+".*"info"\s*:\s*\{', re.S),
    re.compile(r'HTTP request \[#\d+\]:', re.I),
)

CWE_KEYWORDS = {
    'CWE-89': ('sql', 'sqli', 'pdo', 'prepared', 'bindparam', 'parameterized', 'union', 'injection', 'tiêm nhiễm', 'truy vấn'),
    'CWE-79': ('xss', 'cross-site scripting', 'output encoding', 'phản xạ', 'htmlspecialchars'),
    'CWE-287': ('authentication', 'xác thực', 'password', 'mật khẩu', 'mfa', 'brute'),
    'CWE-319': ('tls', 'ssl', 'cleartext', 'mã hóa đường truyền', 'encrypt'),
    'CWE-732': ('privilege', 'grant', 'dba', 'root', 'quyền tối thiểu', 'least privilege'),
    'CWE-209': ('error message', 'stack trace', 'thông báo lỗi', 'xpath syntax'),
}


def looks_like_raw_scan_paste(text: str) -> bool:
    """Detect when a user pastes raw scanner output directly into the chat composer."""
    s = (text or '').strip()
    if len(s) < 90:
        return False
    return any(p.search(s) for p in RAW_SCAN_PATTERNS)


def _infer_query_cwe_and_stack(message: str, compact_model: dict | None) -> tuple[str, str]:
    low = (message or '').lower()
    for cwe, words in CWE_KEYWORDS.items():
        if any(w in low for w in words):
            return cwe, str((compact_model or {}).get('dbms_summary') or '')
    if compact_model and compact_model.get('findings'):
        f0 = compact_model['findings'][0]
        m = re.search(r'CWE-\d+', str(f0.get('owasp_cwe_short') or ''))
        if m:
            return m.group(0), str(compact_model.get('dbms_summary') or '')
    return '', str((compact_model or {}).get('dbms_summary') or '')


def retrieve_owasp_for_chat(query: str, cwe: str = '', stack_hint: str = '', top_k: int = 3) -> list[dict]:
    """Run fast lexical/hybrid search across bundled OWASP DB Cheat Sheets without forcing heavy model loads."""
    try:
        from .eval_benchmark import debug_hybrid_search_playground
        res = debug_hybrid_search_playground(
            query=query[:280],
            cwe=cwe,
            stack_hint=stack_hint[:80],
            top_k=max(1, min(top_k, 5)),
            prefer_e5=False,
        )
        hits = []
        for item in (res.get('results') or [])[:top_k]:
            hits.append({
                'title': str(item.get('title') or item.get('doc_id') or 'OWASP Cheat Sheet').strip(),
                'section': str(item.get('section') or '').strip(),
                'url': str(item.get('url') or 'https://cheatsheetseries.owasp.org/').strip(),
                'excerpt': str(item.get('snippet') or item.get('text') or '').strip(),
            })
        return hits
    except Exception:
        return []


def build_suggested_prompts(compact_model: dict | None) -> list[str]:
    """Return contextual 1-click follow-up prompts tailored to the current conversation state."""
    if compact_model and compact_model.get('findings'):
        f0 = compact_model['findings'][0]
        fid = f0['id']
        return [
            f"Giải thích chi tiết lỗ hổng {fid} và viết code vá an toàn",
            f"Hướng dẫn từng bước kiểm thử lại (Retest) cho {fid} không dùng --dump",
            "Phân tích ý nghĩa các dịch vụ ở Mục 3 và kết quả âm tính ở Mục 4",
            "Tóm tắt 3 việc ưu tiên nhất cho đội phát triển sửa ngay hôm nay",
        ]
    return [
        "Cách phòng chống SQL Injection bằng Prepared Statements (PHP PDO & Python)?",
        "Khi nào gán CWE ở Mục 2 và khi nào đưa vào Quan sát ở Mục 3?",
        "Quy trình Retest xác nhận lỗ hổng SQLi an toàn không dùng --dump?",
        "Cách cấu hình tài khoản CSDL theo nguyên tắc đặc quyền tối thiểu (Least Privilege)?",
    ]


def _synthesize_grounded_reply(
    user_msg: str,
    compact_model: dict | None,
    owasp_hits: list[dict],
) -> str:
    """Deterministic, high-signal Vietnamese Markdown response when running in Demo mode or offline fallback."""
    low = user_msg.lower()
    parts: list[str] = []

    if compact_model:
        findings = compact_model.get('findings') or []
        obs = compact_model.get('observations') or []
        negs = compact_model.get('negative_results') or []
        lims = compact_model.get('limitations_and_verify') or []

        # Specific question about Section 3 / Section 4 / passive banners / negative tests
        if any(k in low for k in ('mục 3', 'mục 4', 'quan sát', 'âm tính', 'submit', 'banner', 'port')):
            parts.append(f"### Phân tích Mục 3 (Quan sát) & Mục 4 (Kết quả âm tính) — `{compact_model['doc_title']}`")
            if obs:
                parts.append('**1. Các quan sát thụ động tại Mục 3 (không gán CWE do chưa có bằng chứng khai thác trực tiếp):**')
                for ob in obs:
                    parts.append(f"- **`{ob['service']}` ({ob['location']}):** `{ob['observation']}` — {ob['note']}")
            if negs:
                parts.append('\n**2. Kết quả kiểm thử âm tính tại Mục 4:**')
                for n in negs:
                    parts.append(f"- {n}")
            return '\n'.join(parts)

        # Specific question about Retest
        if any(k in low for k in ('retest', 'kiểm thử lại', 'kiểm tra lại', 'xác nhận sau vá')):
            parts.append(f"### Quy trình Kiểm thử lại (Retest) an toàn cho `{compact_model['doc_title']}`")
            for f in findings:
                parts.append(
                    f"1. **Đối với `{f['id']}` ({f['title']} — {f['component']}):**\n"
                    f"   - Triển khai bản vá tham số hóa truy vấn / mã hóa đầu ra trên môi trường staging hoặc lab.\n"
                    f"   - Gửi lại đúng request kiểm chứng trong bằng chứng của `{f['id']}` (giữ nguyên giới hạn an toàn `NO --dump`).\n"
                    f"   - **Tiêu chí Đạt:** Phản hồi HTTP không còn trả về lỗi cú pháp CSDL (`XPATH syntax error` / `SQLSTATE`), không rò rỉ thông tin schema và không còn chênh lệch boolean/time-based."
                )
            if lims:
                parts.append('\n**Lưu ý từ Mục 5 (Giới hạn & việc cần xác minh):**')
                for l in lims[:3]:
                    parts.append(f"- {l}")
            return '\n'.join(parts)

        # General / remediation / finding explanation grounded on active report
        if findings:
            f0 = findings[0]
            # Pick targeted finding if user named F-02, F-03...
            for cand in findings:
                if cand['id'].lower() in low:
                    f0 = cand
                    break
            parts.append(f"### Phân tích & Hướng dẫn Khắc phục — `{f0['id']}: {f0['title']}`")
            parts.append(
                f"- **Thành phần ảnh hưởng:** {f0['component']}\n"
                f"- **Phân loại OWASP / CWE:** `{f0['owasp_cwe_full']}`\n"
                f"- **Mức độ / CVSS:** `{f0['sev_cvss_display']}` · **Trạng thái:** **{f0['state']}**"
            )
            parts.append(f"\n**Bản chất & Tác động thực tế:**\n{f0['description']}\n\n{f0['impact']}")
            parts.append(f"\n**Biện pháp khắc phục chính (chuẩn OWASP):**\n{f0['remediation']}")
            if f0.get('code_example'):
                lang = 'php' if '$' in f0['code_example'] else 'sql'
                parts.append(f"```{lang}\n{f0['code_example']}\n```")
            parts.append(f"**Nguồn tham chiếu chính:** [{f0['remediation_source_title']}]({f0['remediation_source_url']})")
            return '\n'.join(parts)

    # Standalone security / OWASP question (no active report yet)
    parts.append('### Hướng dẫn Bảo mật CSDL & Khắc phục theo chuẩn OWASP')
    if owasp_hits:
        top = owasp_hits[0]
        parts.append(
            f"Dựa trên tài liệu chính thức **{top['title']}**"
            + (f" (*{top['section']}*)" if top['section'] else '')
            + ':'
        )
        for h in owasp_hits[:2]:
            snippet = re.sub(r'\s+', ' ', h['excerpt']).strip()
            parts.append(f"- **{h['title']}:** {snippet[:280]}")
    if any(w in low for w in ('sql', 'pdo', 'prepared', 'injection', 'tiêm nhiễm')):
        parts.append(
            "\n**Mẫu mã nguồn tham số hóa an toàn (PHP PDO — tắt `ATTR_EMULATE_PREPARES`):**\n"
            "```php\n"
            "$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);\n"
            "$stmt = $pdo->prepare('SELECT user_id, first_name FROM users WHERE user_id = :id');\n"
            "$stmt->bindValue(':id', $id, PDO::PARAM_INT);\n"
            "$stmt->execute();\n"
            "```"
        )
    parts.append(
        "\nBạn có thể **đính kèm tệp quét (`📎`)** hoặc **dán trực tiếp nội dung log `sqlmap` / `Nmap` / `ZAP` ngay vào ô chat** để mình tự động phân tích và xuất **Báo cáo Kiểm thử Bảo mật Gọn (6 mục · PDF & Markdown)**."
    )
    return '\n'.join(parts)


def answer_assistant_message(
    user_message: str,
    *,
    history: list[dict] | None = None,
    report_path: Path | None = None,
    demo: bool = False,
) -> dict[str, Any]:
    """Generate an accurate, grounded assistant response with OWASP citations and follow-up suggestions."""
    compact_model: dict | None = None
    if report_path and report_path.is_file():
        try:
            raw_rep = json.loads(report_path.read_text(encoding='utf-8'))
            compact_model = prepare_compact_pentest(raw_rep)
        except Exception:
            compact_model = None

    cwe_hint, stack_hint = _infer_query_cwe_and_stack(user_message, compact_model)
    owasp_hits = retrieve_owasp_for_chat(user_message, cwe=cwe_hint, stack_hint=stack_hint, top_k=3)

    citations: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    if compact_model:
        for f in compact_model.get('findings') or []:
            u = f.get('remediation_source_url') or ''
            if u and u not in seen_urls:
                seen_urls.add(u)
                citations.append({'title': f.get('remediation_source_title') or 'OWASP Reference', 'url': u})
    for h in owasp_hits:
        u = h.get('url') or ''
        if u and u not in seen_urls:
            seen_urls.add(u)
            citations.append({'title': h.get('title') or 'OWASP Cheat Sheet', 'url': u})

    if not demo:
        try:
            from .llm import OllamaLLM
            settings = Settings()
            llm = OllamaLLM(
                model=settings.ollama_model,
                base_url=settings.ollama_url,
                timeout=min(settings.llm_timeout, 90),
            )
            ctx_chunks: list[str] = []
            if compact_model:
                ctx_chunks.append('=== BÁO CÁO PHIÊN HIỆN TẠI (MỤC 1–6) ===')
                ctx_chunks.append(f"Tiêu đề: {compact_model['doc_title']}")
                ctx_chunks.append(f"Tóm tắt: {compact_model['summary_text']}")
                for f in (compact_model.get('findings') or [])[:6]:
                    ctx_chunks.append(
                        f"- {f['id']}: {f['title']} | Thành phần: {f['component']} | "
                        f"OWASP/CWE: {f['owasp_cwe_full']} | Mức độ/CVSS: {f['sev_cvss_display']} | Trạng thái: {f['state']}\n"
                        f"  Mô tả: {f['description']}\n  Tác động: {f['impact']}\n  Khắc phục: {f['remediation']}"
                    )
                for ob in (compact_model.get('observations') or [])[:4]:
                    ctx_chunks.append(f"- Quan sát Mục 3: {ob['service']} @ {ob['location']} -> {ob['observation']} ({ob['note']})")
                for neg in (compact_model.get('negative_results') or [])[:3]:
                    ctx_chunks.append(f"- Kết quả âm tính Mục 4: {neg}")

            if owasp_hits:
                ctx_chunks.append('=== TRÍCH ĐOẠN OWASP CHEAT SHEET LIÊN QUAN ===')
                for i, h in enumerate(owasp_hits, 1):
                    ctx_chunks.append(f"[OWASP-{i}] {h['title']} ({h['section']}): {h['excerpt'][:420]}")

            recent_turns = []
            for turn in (history or [])[-6:]:
                r_lbl = 'Người dùng' if turn.get('role') == 'user' else 'Trợ lý'
                txt = str(turn.get('text') or '').strip()
                if txt:
                    recent_turns.append(f"{r_lbl}: {txt[:500]}")

            full_prompt = (
                ('\n'.join(ctx_chunks) + '\n\n' if ctx_chunks else '')
                + ('=== HỘI THOẠI GẦN ĐÂY ===\n' + '\n'.join(recent_turns) + '\n\n' if recent_turns else '')
                + f"=== CÂU HỎI HIỆN TẠI CỦA NGƯỜI DÙNG ===\n{user_message.strip()}\n\n"
                "Hãy trả lời trực tiếp, súc tích, rõ ràng bằng tiếng Việt chuẩn kỹ thuật bảo mật (dùng Markdown gọn gàng và ví dụ code an toàn nếu phù hợp). "
                "Tuyệt đối không tự bịa điểm CVSS hay bằng chứng không có trong hồ sơ."
            )
            sys_prompt = (
                "Bạn là Trợ lý Chuyên gia Kiểm thử Bảo mật Ứng dụng & Cơ sở Dữ liệu chuẩn OWASP. "
                "Trả lời tự nhiên như một trợ lý đối thoại thực thụ, bám sát dữ liệu thực tế của phiên báo cáo (nếu có) và OWASP Cheat Sheet Series."
            )
            raw_reply = str(llm.generate(full_prompt[:11500], system=sys_prompt) or '').strip()
            # Strip optional `<think>...</think>` blocks emitted by reasoning models like qwen3
            clean_reply = re.sub(r'<think>.*?</think>', '', raw_reply, flags=re.S).strip()
            if clean_reply:
                return {
                    'reply': clean_reply,
                    'citations': citations[:3],
                    'suggestions': build_suggested_prompts(compact_model),
                    'mode': 'ollama',
                }
        except Exception:
            pass

    return {
        'reply': _synthesize_grounded_reply(user_message, compact_model, owasp_hits),
        'citations': citations[:3],
        'suggestions': build_suggested_prompts(compact_model),
        'mode': 'grounded-rag',
    }
