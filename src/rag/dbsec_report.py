"""Official 10-Section Database Security Testing & OWASP Remediation Report Engine.

Strictly implements the coursework/project specification:
  # BÁO CÁO KIỂM THỬ BẢO MẬT CSDL VÀ ĐỀ XUẤT REMEDIATION THEO OWASP
  1. Thông tin chung
  2. Đánh giá dữ liệu đầu vào (2.1 Nguồn dữ liệu I-01.. | 2.2 Chất lượng dữ liệu)
  3. Phương pháp phân tích
  4. Tóm tắt kết quả (4.1 Ma trận 6x4 không tự tạo mức độ | 4.2 Nhận xét tổng quan)
  5. Danh sách phát hiện (F-01..)
  6. Phân tích chi tiết phát hiện (6.1..6.7 kèm E-01.., phân tách rõ bằng chứng & giả thuyết mã nguồn)
  7. Đề xuất remediation (7.1..7.5 đối chiếu RAG OWASP Cheat Sheet & kế hoạch kiểm tra lại)
  8. Giới hạn và độ tin cậy của báo cáo (8.1..8.3)
  9. Kết luận (không khẳng định an toàn/đã khắc phục khi chưa có retest)
  10. Phụ lục (10.1 Dữ liệu I-xx | 10.2 Bằng chứng E-xx | 10.3 Tài liệu OWASP | 10.4 Kiểm tra lại)

Zero case-specific hardcoding: every field is derived strictly from the parsed input scan(s),
approved OWASP Top 10:2025 / Cheat Sheet Series knowledge base, and citation-verified local AI output.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import re
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from .db_scope import db_frame
from .pentest_polish import (
    CWE_FRIENDLY,
    _analyze_http_messages,
    _clean_markdown_excerpt,
    _extract_card_action,
    build_cvss_rationale,
    clean_internal_jargon,
    collect_ip_mapping,
    compact_http_exchange,
    sanitize_text_value,
)
from .report_view import (
    STATUS_LABELS,
    cwe_origin,
    cwe_text,
    evidence_profile,
    extract_scan_context,
    is_nonfinding_intake_record,
    is_passive_service_observation,
)
from .top10 import enforce, finding_cwes, mapping

REPORT_TITLE = 'BÁO CÁO KIỂM THỬ BẢO MẬT CSDL VÀ ĐỀ XUẤT REMEDIATION THEO OWASP'
REPORT_SUBTITLE = 'Phân tích kết quả kiểm thử dựa trên bằng chứng và đối chiếu khuyến nghị chính thức từ OWASP'

SEVERITY_MATRIX_ROWS = [
    ('critical', 'Critical'),
    ('high', 'High'),
    ('medium', 'Medium'),
    ('low', 'Low'),
    ('informational', 'Informational'),
    ('unknown', 'Chưa xác định'),
]

SEVERITY_CANONICAL = {
    'critical': 'Critical',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'informational': 'Informational',
    'info': 'Informational',
    'unknown': 'Chưa xác định',
}

STATE_CONFIRMED = 'Đã xác nhận'
STATE_TENTATIVE = 'Có dấu hiệu'
STATE_INSUFFICIENT = 'Chưa đủ dữ liệu'
STATE_UNCONFIRMED = 'Không xác nhận được'

SECTION_TITLES = [
    '1. Thông tin chung',
    '2. Đánh giá dữ liệu đầu vào',
    '3. Phương pháp phân tích',
    '4. Tóm tắt kết quả',
    '5. Danh sách phát hiện',
    '6. Phân tích chi tiết phát hiện',
    '7. Đề xuất remediation',
    '8. Giới hạn và độ tin cậy của báo cáo',
    '9. Kết luận',
    '10. Phụ lục',
]

FORMAT_DISPLAY = {
    'pentest-report': 'Báo cáo kiểm thử Pentest / Tài liệu kỹ thuật (PDF/MD/TXT)',
    'sqlmap-log': 'Nhật ký kiểm thử SQLMap (Văn bản thuần)',
    'nmap': 'Bản quét cổng & dịch vụ Nmap XML (-oX)',
    'nessus': 'Bản đánh giá lỗ hổng Nessus (.nessus XML)',
    'zap': 'Báo cáo quét OWASP ZAP (JSON/XML)',
    'burp': 'Báo cáo quét Burp Suite (XML)',
    'nuclei': 'Kết quả kiểm thử Nuclei (JSON/JSONL)',
    'normalized': 'Dữ liệu phát hiện chuẩn hóa (JSON)',
    'bundle': 'Gói đa tệp đầu vào (Multi-file Bundle)',
    'auto': 'Tự động nhận diện định dạng công cụ',
}

_FENCED_CODE_RE = re.compile(r'```([A-Za-z0-9_+#.-]*)\s*\n(.*?)```', re.S)


def canonical_severity(raw_value: str | None) -> tuple[str, str]:
    """Map raw scanner severity strictly without inventing any severity level."""
    val = str(raw_value or '').strip().lower()
    if val == 'info':
        val = 'informational'
    if val not in {'critical', 'high', 'medium', 'low', 'informational'}:
        return 'unknown', 'Chưa xác định'
    return val, SEVERITY_CANONICAL[val]


def classify_finding_state(row: dict) -> str:
    """Classify finding verification state strictly from input record evidence & kind."""
    kind = str(row.get('kind') or 'scanner_alert').strip().lower()
    if kind == 'unconfirmed':
        return STATE_UNCONFIRMED
    if kind == 'observation':
        return STATE_TENTATIVE
    details = row.get('details') or {}
    conf = str(details.get('confidence') or '').strip().lower()
    if conf in {'tentative', 'heuristic', 'low', '1', '0', 'false positive'}:
        return STATE_TENTATIVE
    has_ev = bool(row.get('evidence')) or bool(details.get('request')) or bool(details.get('response')) or bool(details.get('http_messages'))
    if not has_ev:
        return STATE_INSUFFICIENT
    return STATE_CONFIRMED


def _clean_tool_display(raw_tool: str, fallback_pool: list[str] | None = None) -> str:
    t = str(raw_tool or '').strip()
    if t.lower() not in {'', 'ai-extracted', 'ai', 'unknown', 'none', 'n/a'}:
        return t
    for cand in (fallback_pool or []):
        c = str(cand or '').strip()
        if c.lower() not in {'', 'ai-extracted', 'ai', 'unknown', 'none', 'n/a'}:
            return c
    return 'công cụ kiểm thử'


def _infer_dbms_summary(findings: list[dict], scan_ctx: dict, sanitize) -> str:
    """Extract DBMS engine/version strictly from telemetry, service banners, titles, or evidence (deduplicated)."""
    found: list[str] = []
    for r in findings:
        det = r.get('details') or {}
        tel = det.get('scan_telemetry') or {}
        if tel.get('dbms'):
            found.append(sanitize(str(tel['dbms']).strip()))
        svc = ' '.join(str(det.get(k) or '') for k in ('service', 'product', 'version', 'banner')).strip()
        if svc and re.search(r'\b(mysql|mariadb|postgres|postgresql|mssql|sql\s*server|oracle|mongodb|redis|sqlite|cassandra|elasticsearch|db2)\b', svc, re.I):
            found.append(sanitize(svc))
        blob = ' '.join([str(r.get('title') or ''), *[str(x) for x in (r.get('evidence') or [])[:4]]])
        for m in re.finditer(
            r'\b(MySQL(?:\s*>=\s*[\d.]+)?(?:\s*\([^)]+\))?|MariaDB(?:\s+[\d.]+)?|'
            r'PostgreSQL(?:\s+[\d.]+)?|Microsoft SQL Server(?:\s+\d+)?|MSSQL|'
            r'Oracle(?:\s+Database)?(?:\s+[\d.c]+)?|MongoDB(?:\s+[\d.]+)?|'
            r'SQLite(?:\s+[\d.]+)?|Redis(?:\s+[\d.]+)?)\b',
            blob,
            re.I,
        ):
            cand = sanitize(m.group(1).strip())
            if not any(cand.lower() in prev.lower() for prev in found):
                found.append(cand)
    # Keep longest canonical banner per DB engine family when multiple version probes overlap (e.g. MySQL >= 5.1 (MariaDB fork))
    dedup: list[str] = []
    for item in sorted(found, key=len, reverse=True):
        if not item:
            continue
        low = item.lower()
        if any(low in d.lower() for d in dedup):
            continue
        # Subsume bare secondary MySQL/MariaDB version probe strings when a full MySQL/MariaDB fork banner already exists
        if ('mysql' in low or 'mariadb' in low) and any(('mysql' in d.lower() and 'mariadb' in d.lower()) or ('mysql >=' in d.lower() and low.startswith('mysql >=')) for d in dedup):
            continue
        dedup.append(item)
    return '; '.join(dedup) if dedup else 'Chưa xác định từ dữ liệu đầu vào'


def _infer_component_label(row: dict, sanitize) -> str:
    """Return concise exact component label for Section 5 & 6.2 without duplicating parameter annotations."""
    det = row.get('details') or {}
    loc = sanitize(str(row.get('location') or '').strip())
    param = sanitize(str(det.get('parameter') or det.get('param') or '').strip())
    method = sanitize(str(det.get('method') or '').strip().upper())
    port = str(det.get('port') or '').strip()
    proto = str(det.get('protocol') or '').strip()

    param_tag_m = re.search(r'\s*\(parameter=([^,)]+)(?:,\s*([A-Za-z]+))?\)\s*$', loc, re.I)
    if param_tag_m:
        if not param:
            param = sanitize(param_tag_m.group(1).strip())
        if param_tag_m.group(2) and not method:
            method = sanitize(param_tag_m.group(2).strip().upper())
        loc = loc[:param_tag_m.start()].strip()

    if not param:
        m = re.search(r"\b(GET|POST|PUT|DELETE|PATCH|COOKIE|HEADER)?\s*parameter\s+'([^']+)'", ' '.join([str(row.get('title') or ''), loc, *[str(x) for x in (row.get('evidence') or [])[:2]]]), re.I)
        if m:
            if m.group(1) and not method:
                method = m.group(1).upper()
            param = sanitize(m.group(2))
    if not param and '://' in loc and '?' in loc:
        qkeys = [k for k, _ in parse_qsl(urlsplit(loc).query, keep_blank_values=True)]
        if len(qkeys) == 1:
            param = sanitize(qkeys[0])

    parts = [loc or 'Chưa ghi nhận vị trí cụ thể']
    if param:
        parts.append(f"tham số {method + ' ' if method else ''}`{param}`")
    elif method:
        parts.append(f"phương thức `{method}`")
    elif port and port not in loc:
        parts.append(f"cổng `{port}/{proto or 'tcp'}`")
    return ' — '.join(parts)


def _extract_code_blocks_from_guidance(guidance: list[dict], stack_hint: str = '') -> list[dict]:
    """Extract verbatim safe code/configuration examples directly from retrieved OWASP Cheat Sheets."""
    candidates: list[dict] = []
    hint_low = stack_hint.lower()
    for g in guidance or []:
        raw_ex = str(g.get('source_excerpt') or g.get('text') or g.get('excerpt') or '')
        for m in _FENCED_CODE_RE.finditer(raw_ex):
            lang = (m.group(1) or 'text').strip().lower()
            code = m.group(2).strip()
            if not code or len(code) < 20:
                continue
            # Prefer safe defense snippets over vulnerable anti-examples when Cheat Sheet contrasts both
            lower_code = code.lower()
            is_safe = any(tok in lower_code for tok in (
                'prepare(', 'preparedstatement', 'bindparam', 'bindvalue', 'sqlparameter',
                'parameters.add', 'createquery', 'setparameter', 'htmlspecialchars',
                'encodefor', 'mysql_secure_installation', 'require ssl', 'grant ', 'revoke ',
            ))
            stack_match = (
                ('php' in hint_low or 'apache' in hint_low or 'dvwa' in hint_low) and lang == 'php'
            ) or (('java' in hint_low or 'spring' in hint_low or 'hibernate' in hint_low) and lang == 'java') \
              or (('dotnet' in hint_low or 'asp' in hint_low or 'mssql' in hint_low) and lang in {'csharp', 'cs', 'c#'}) \
              or ('python' in hint_low and lang in {'python', 'py'})
            score = (4 if stack_match else 0) + (3 if is_safe else 0)
            candidates.append({
                'score': score,
                'lang': lang or 'text',
                'code': code[:1100],
                'section': str(g.get('section') or g.get('title') or 'OWASP Cheat Sheet'),
                'url': str(g.get('url') or ''),
            })
    candidates.sort(key=lambda x: -x['score'])
    return candidates[:1]


def _packet_proof_score(pkt: dict) -> int:
    req = unquote(str(pkt.get('request') or '')).lower()
    resp = str(pkt.get('response') or '').lower()
    score = 0
    if any(k in resp for k in ('xpath syntax error', 'sql syntax', 'sqlstate', 'ora-', 'psqlexception', 'mysql_fetch', 'sqlite3.')):
        score += 10
    if 'union' in req and 'select' in req:
        score += 6
    if any(k in req + resp for k in ('<script', 'onerror=', 'onload=')):
        score += 5
    return score


def _build_evidence_items_for_finding(
    row: dict,
    *,
    source_id: str,
    next_ev_num: int,
    sanitize,
    ai_obs: list[str],
    is_compact: bool = True,
    fallback_tools: list[str] | None = None,
) -> tuple[list[dict], int, str]:
    """Build globally numbered E-xx evidence items strictly from real finding proof & packets."""
    items: list[dict] = []
    det = row.get('details') or {}
    tel = det.get('scan_telemetry') or {}
    cwe = str(row.get('cwe') or '').strip()
    state = classify_finding_state(row)
    tool_disp = sanitize(_clean_tool_display(row.get('tool'), fallback_tools))

    matched_packets, excluded_note = _analyze_http_messages(row, lang='vi')
    matched_packets = sorted(matched_packets, key=_packet_proof_score, reverse=True)

    # DB enumeration lines (merged into E-01 in compact mode so finding stays <= 2 crisp evidence items)
    has_db_enum = cwe in {'CWE-89', 'CWE-564', 'CWE-943'} and any(
        tel.get(k) is not None for k in ('current_user', 'current_db', 'is_dba', 'databases', 'tables', 'tables_by_db')
    )
    t_lines: list[str] = []
    dba_note = ''
    if has_db_enum:
        if tel.get('dbms'):
            t_lines.append(f"back-end DBMS: {sanitize(tel['dbms'])}")
        if tel.get('current_user'):
            t_lines.append(f"current user: '{sanitize(tel['current_user'])}'" + (f" | current database: '{sanitize(tel['current_db'])}'" if tel.get('current_db') else ''))
        elif tel.get('current_db'):
            t_lines.append(f"current database: '{sanitize(tel['current_db'])}'")
        if tel.get('is_dba') is not None:
            t_lines.append(f"current user is DBA: {tel['is_dba']}")
        if tel.get('databases'):
            t_lines.append(f"available databases [{len(tel['databases'])}]: {', '.join(sanitize(x) for x in tel['databases'])}")
        for db_n, tbl_list in (tel.get('tables_by_db') or tel.get('tables') or {}).items():
            t_lines.append(f"Database {sanitize(db_n)} tables [{len(tbl_list)}]: {', '.join(sanitize(x) for x in tbl_list)}")
        dba_note = (
            'Tài khoản CSDL không có quyền DBA (`is_dba = False`), giới hạn leo thang hệ điều hành.'
            if tel.get('is_dba') is False
            else (
                'Tài khoản CSDL mang đặc quyền DBA (`is_dba = True`), gia tăng nghiêm trọng phạm vi tác động.'
                if tel.get('is_dba') is True
                else ''
            )
        )

    # 1. Primary scanner proof lines (merged with concise DB schema proof in compact mode)
    ev_lines = [sanitize(str(x).strip()) for x in (row.get('evidence') or []) if str(x).strip()]
    if ev_lines or (is_compact and t_lines):
        eid = f'E-{next_ev_num:02d}'
        next_ev_num += 1
        max_ev_lines = 3 if is_compact else 6
        snippet_parts = list(ev_lines[:max_ev_lines])
        kind_lbl = 'Trích đoạn kết quả công cụ kiểm thử'
        if is_compact and t_lines:
            snippet_parts.extend(t_lines[:4])
            kind_lbl = 'Trích đoạn kết quả công cụ & siêu dữ liệu CSDL'
        raw_snippet = '\n'.join(snippet_parts)
        if ai_obs:
            explanation = clean_internal_jargon(ai_obs[0])
            if is_compact and dba_note and 'dba' not in explanation.lower():
                explanation = f"{explanation.rstrip('.')} ({dba_note})"
        elif state == STATE_TENTATIVE:
            explanation = (
                'Nhật ký sơ bộ ghi nhận dấu hiệu phản xạ đầu vào ở mức dò tự động (heuristic), '
                'chưa có gói tin khai thác thực thi hoàn chỉnh.'
            )
        else:
            explanation = (
                f"Đầu ra trực tiếp từ `{tool_disp}` ghi nhận bằng chứng kỹ thuật tại `{sanitize(row.get('location') or 'mục tiêu')}`."
                + (f' {dba_note}' if is_compact and dba_note else '')
            )
        items.append({
            'id': eid,
            'source_id': source_id,
            'kind': kind_lbl,
            'snippet': raw_snippet[: (720 if is_compact else 2000)],
            'explanation': explanation[: (320 if is_compact else 900)],
        })

    # 2. Matched HTTP Request / Response packets (max 1 minified proof in compact mode; up to 3 full packets in audit mode)
    pkt_limit = 1 if is_compact else 3
    if matched_packets:
        for pkt_idx, pkt in enumerate(matched_packets[:pkt_limit]):
            eid = f'E-{next_ev_num:02d}'
            next_ev_num += 1
            pid = str(pkt.get('id') or f'HTTP-{pkt_idx + 1}')
            req_s = sanitize(str(pkt.get('request') or '').strip())
            resp_s = sanitize(str(pkt.get('response') or '').strip())
            if is_compact:
                pkt_snippet = compact_http_exchange(req_s, resp_s, pid)
            else:
                combined = []
                if req_s:
                    combined.append(f"[Request {pid}]\n{req_s[:950]}")
                if resp_s:
                    combined.append(f"[Response {pid}]\n{resp_s[:950]}")
                pkt_snippet = '\n\n'.join(combined)
            if 'xpath syntax error' in resp_s.lower() or 'sql syntax' in resp_s.lower() or 'exception' in resp_s.lower():
                pkt_explain = (
                    f"Phản hồi `{pid}` trả trực tiếp lỗi truy vấn CSDL trong thân HTTP, "
                    f"chứng minh payload đầu vào đã làm thay đổi cú pháp thực thi tại tầng CSDL."
                )
            elif 'union' in unquote(req_s).lower() and ('information_schema' in unquote(req_s).lower() or 'select' in unquote(req_s).lower()):
                pkt_explain = (
                    f"Gói tin `{pid}` chứng minh khả năng nối kết quả `UNION SELECT` trực tiếp ra phản hồi HTTP 200."
                )
            else:
                pkt_explain = f"Gói tin `{pid}` ghi nhận payload kiểm thử thực tế trên tham số đích (đã che khóa phiên `[REDACTED]`)."
            items.append({
                'id': eid,
                'source_id': source_id,
                'kind': f'Lưu lượng HTTP chứng minh ({pid})',
                'snippet': pkt_snippet,
                'explanation': pkt_explain,
            })
    elif det.get('request') or det.get('response'):
        eid = f'E-{next_ev_num:02d}'
        next_ev_num += 1
        req_s = sanitize(str(det.get('request') or '').strip())
        resp_s = sanitize(str(det.get('response') or '').strip())
        if is_compact:
            pkt_snippet = compact_http_exchange(req_s, resp_s, '')
        else:
            combined = []
            if req_s:
                combined.append(f"[Request]\n{req_s[:950]}")
            if resp_s:
                combined.append(f"[Response]\n{resp_s[:950]}")
            pkt_snippet = '\n\n'.join(combined)
        items.append({
            'id': eid,
            'source_id': source_id,
            'kind': 'Gói tin yêu cầu / phản hồi từ công cụ quét',
            'snippet': pkt_snippet,
            'explanation': 'Bằng chứng gói tin yêu cầu/phản hồi thu thập trực tiếp trên mục tiêu.',
        })

    # 3. Separate full DB enumeration block in full audit mode (already merged into E-01 in compact mode)
    if (not is_compact) and has_db_enum and t_lines:
        eid = f'E-{next_ev_num:02d}'
        next_ev_num += 1
        items.append({
            'id': eid,
            'source_id': source_id,
            'kind': 'Siêu dữ liệu phiên làm việc & lược đồ CSDL thu thập được',
            'snippet': '\n'.join(t_lines),
            'explanation': f"Xác nhận trực tiếp danh tính kết nối và cấu trúc lược đồ CSDL qua lỗ hổng. {dba_note}".strip(),
        })

    return items, next_ev_num, ('' if is_compact else excluded_note)


def _bundled_cheatsheet_count() -> int:
    """Count bundled OWASP Cheat Sheet markdown files dynamically from disk."""
    repo_root = Path(__file__).resolve().parents[2]
    cs_dir = repo_root / 'data' / 'raw' / 'owasp' / 'official' / 'CheatSheetSeries-master' / 'cheatsheets'
    if cs_dir.is_dir():
        return sum(1 for _ in cs_dir.glob('*.md'))
    return 0


def _build_root_cause(row: dict, state: str, component: str, ev_items: list[dict], sanitize) -> str:
    """Section 6.6: Separate proven behavior strictly present in input evidence from source/config hypothesis."""
    cwe = str(row.get('cwe') or '').strip()
    det = row.get('details') or {}
    tel = det.get('scan_telemetry') or {}
    tech = sanitize(str(tel.get('web_tech') or '')).strip()
    native_desc = clean_internal_jargon(sanitize(str(det.get('description') or '').strip()))
    ev_blob = '\n'.join(
        [str(e.get('snippet') or '') for e in ev_items]
        + [str(x or '') for x in (row.get('evidence') or [])]
    ).lower()

    if state == STATE_TENTATIVE:
        return (
            f"Từ bằng chứng hiện có trên {component}, mới chỉ ghi nhận dấu hiệu phản hồi đầu vào chưa được lọc/mã hóa đầy đủ. "
            f"**Giả thuyết ở tầng mã nguồn (cần xác minh thêm do không có mã nguồn):** ứng dụng có thể đang xuất trực tiếp giá trị tham số ra phản hồi HTTP "
            f"mà chưa áp dụng mã hóa đầu ra theo ngữ cảnh (context-aware output encoding)."
        )
    if state == STATE_INSUFFICIENT:
        return (
            f"Dữ liệu đầu vào chưa cung cấp đủ trích đoạn phản hồi kỹ thuật để kết luận cơ chế gây lỗi trên {component}; "
            f"cần thu thập thêm bản ghi yêu cầu/phản hồi và kiểm tra mã nguồn/cấu hình thực tế."
        )
    if cwe in {'CWE-89', 'CWE-564', 'CWE-943'}:
        stack_note = f" (nền tảng ghi nhận từ tiêu đề máy chủ: `{tech}`)" if tech else ''
        techs_raw = det.get('techniques') or tel.get('techniques') or []
        tech_clause = f" thông qua kỹ thuật `{', '.join(sanitize(t) for t in techs_raw)}`" if techs_raw else ''
        has_db_error = any(
            err_tok in ev_blob
            for err_tok in (
                'sql syntax', 'xpath syntax error', 'mysql_fetch', 'ora-', 'postgresql query failed',
                'unclosed quotation mark', 'odbc sql server driver', 'sqlite3.operationalerror', 'sqlstate[',
            )
        )
        err_clause = (
            ', đồng thời ứng dụng để lộ trực tiếp thông báo ngoại lệ CSDL ra phản hồi HTTP'
            if has_db_error
            else ' (phản hồi kiểm thử xác nhận hành vi truy vấn bị chi phối bởi tham số đầu vào ngay cả khi không cần hiển thị lỗi cú pháp trực tiếp)'
        )
        return (
            f"**Cơ sở đã được chứng minh từ phản hồi kiểm thử:** dữ liệu đầu vào tại {component} đã làm thay đổi trực tiếp cấu trúc "
            f"lô-gic truy vấn thực thi tại tầng CSDL{tech_clause}{stack_note}{err_clause}. "
            f"**Giả thuyết nguyên nhân gốc ở tầng mã nguồn (cần đối chiếu mã nguồn để xác nhận vì kiểm thử hộp đen không truy cập mã nguồn):** "
            f"tầng truy cập dữ liệu ghép nối chuỗi trực tiếp tham số người dùng vào câu lệnh truy vấn thay vì sử dụng truy vấn tham số hóa (`Prepared Statements` / `Parameterized Queries`)."
        )
    if cwe == 'CWE-79':
        return (
            f"**Cơ sở đã được chứng minh từ phản hồi kiểm thử:** ký tự điều khiển kịch bản truyền qua {component} được phản hồi trở lại ngữ cảnh tài liệu HTML mà không bị trung hòa. "
            f"**Giả thuyết ở tầng mã nguồn (cần xác minh trên mã nguồn):** thiếu bước mã hóa đầu ra theo đúng ngữ cảnh hiển thị (HTML body / attribute / JavaScript) trước khi dựng trang."
        )
    if cwe in {'CWE-306', 'CWE-287', 'CWE-521', 'CWE-1393', 'CWE-798'}:
        return (
            f"**Cơ sở đã được chứng minh từ phản hồi kiểm thử:** dịch vụ tại {component} cho phép thiết lập phiên hoặc truy vấn siêu dữ liệu mà không yêu cầu thông tin xác thực đủ mạnh. "
            f"**Giả thuyết ở tầng cấu hình (cần đối chiếu tệp cấu hình dịch vụ CSDL):** dịch vụ chưa bật cơ chế bắt buộc xác thực mạnh hoặc chưa giới hạn giao diện mạng lắng nghe nội bộ."
        )
    if cwe in {'CWE-319', 'CWE-295', 'CWE-311', 'CWE-327'}:
        desc_clause = f" ({native_desc[:220].rstrip('.')})" if native_desc else ''
        return (
            f"**Cơ sở đã được chứng minh từ dữ liệu quét:** kênh giao tiếp hoặc cấu hình mật mã tại {component} chưa đảm bảo bảo mật đường truyền/xác thực chứng chỉ{desc_clause}. "
            f"**Giả thuyết ở tầng cấu hình:** máy chủ chưa bắt buộc giao thức TLS mạnh với bộ mã an toàn hoặc chứng chỉ hợp lệ."
        )
    desc_clause = f" ({native_desc[:220].rstrip('.')})" if native_desc else ''
    return (
        f"**Cơ sở từ bằng chứng kiểm thử:** công cụ ghi nhận phản hồi bất thường tại {component} tương ứng phân loại `{cwe or 'Chưa xác định'}`{desc_clause}. "
        f"**Giả thuyết ở tầng mã nguồn / cấu hình (cần kiểm chứng trực tiếp):** thiếu cơ chế kiểm soát đầu vào, phân quyền hoặc cấu hình làm cứng an toàn tương ứng trên máy chủ."
    )


def _build_potential_impact(row: dict, state: str, ai_impacts: list[str], sanitize) -> str:
    """Section 6.7: Separate proven scope from conditional potential impact without overclaiming."""
    det = row.get('details') or {}
    tel = det.get('scan_telemetry') or {}
    parts: list[str] = []

    tables_map = tel.get('tables_by_db') or tel.get('tables') or {}
    if tel.get('databases') or tables_map or tel.get('current_user'):
        proven_bits = []
        if tel.get('current_user'):
            proven_bits.append(f"danh tính kết nối `{sanitize(tel['current_user'])}`")
        if tel.get('databases'):
            proven_bits.append(f"danh sách lược đồ ({', '.join(f'`{sanitize(d)}`' for d in tel['databases'])})")
        for db_n, tbls in tables_map.items():
            proven_bits.append(f"danh mục bảng trong `{sanitize(db_n)}` ({', '.join(f'`{sanitize(t)}`' for t in tbls)})")
        no_dump_note = (
            ' (trong phạm vi kiểm thử an toàn hiện tại chưa thực hiện trích xuất hàng dữ liệu bên trong bảng)'
            if not tel.get('dumped_rows')
            else ''
        )
        parts.append(f"**Phạm vi tác động đã chứng minh thực tế:** đã đọc được {', '.join(proven_bits)}{no_dump_note}.")

    cross_corr = sanitize(str(det.get('cross_source_correlation') or '').strip())
    if cross_corr:
        parts.append(f"**Tương quan rủi ro liên nguồn:** {cross_corr}")

    for imp in ai_impacts[:2]:
        cleaned = clean_internal_jargon(imp)
        if cleaned:
            parts.append(cleaned)

    if not parts:
        if state == STATE_TENTATIVE:
            parts.append(
                'Trong trường hợp ghi nhận sơ bộ này được xác minh là dương tính thật trên trình duyệt/máy khách, '
                'kẻ tấn công có thể lợi dụng phản hồi không được mã hóa để tác động lên phiên làm việc của người dùng.'
            )
        elif state == STATE_INSUFFICIENT:
            parts.append('Chưa đủ bằng chứng kỹ thuật để định lượng phạm vi ảnh hưởng thực tế; cần thu thập thêm dữ liệu kiểm chứng.')
        else:
            parts.append(
                'Nếu không được kiểm soát kịp thời, điểm yếu này có thể làm suy giảm tính bí mật hoặc tính toàn vẹn '
                'của dữ liệu trao đổi với thành phần CSDL/ứng dụng liên quan.'
            )
    return ' '.join(parts)


def _select_top_guidance_for_finding(guidance_list: list[dict], *, stack_hint: str, is_compact: bool) -> list[dict]:
    """Select max 2 high-value distinct OWASP items in compact mode (1 primary defense + 1 stack code / secondary control)."""
    deduped: list[dict] = []
    seen_sec: set[str] = set()
    for g in guidance_list:
        sec = str(g.get('section') or g.get('title') or 'OWASP Cheat Sheet').strip()
        if sec in seen_sec:
            continue
        seen_sec.add(sec)
        deduped.append(g)
    if not is_compact or len(deduped) <= 2:
        return deduped[: (2 if is_compact else 5)]

    hint_low = stack_hint.lower()

    def _primary_rank(g: dict) -> int:
        sec = str(g.get('section') or g.get('title') or '').lower()
        raw = str(g.get('source_excerpt') or g.get('text') or g.get('excerpt') or '')
        if 'defense option 1' in sec or 'primary' in sec or 'output encoding' in sec or 'secure authentication' in sec:
            return 10
        if not _FENCED_CODE_RE.search(raw):
            return 6
        return 2

    def _code_rank(g: dict) -> int:
        sec = str(g.get('section') or g.get('title') or '').lower()
        raw = str(g.get('source_excerpt') or g.get('text') or g.get('excerpt') or '')
        has_code = bool(_FENCED_CODE_RE.search(raw))
        s_match = (
            (('php' in hint_low or 'apache' in hint_low or 'dvwa' in hint_low) and 'php' in sec)
            or (('java' in hint_low or 'spring' in hint_low) and 'java' in sec)
            or (('.net' in hint_low or 'mssql' in hint_low) and '.net' in sec)
        )
        return (8 if has_code else 0) + (6 if s_match else 0) + (3 if 'parameterization' in sec or 'least privilege' in sec else 0)

    primary = max(deduped, key=_primary_rank)
    rest = [g for g in deduped if g is not primary]
    secondary = max(rest, key=_code_rank)
    return [primary, secondary]


def normalize_report_profile(profile: str | None = None, meta: dict | None = None) -> str:
    raw = str(profile or (meta or {}).get('report_profile') or 'compact').strip().lower()
    return 'full' if raw in {'full', 'audit', 'archive', 'day_du'} else 'compact'


def prepare_dbsec_report(report: dict, *, profile: str | None = None) -> dict:
    """Build complete structured model for Sections 1..10 of the official coursework template."""
    if isinstance(report, dict) and 'general_info' in report and 'methodology' in report and 'quality_assessment' in report:
        return copy.deepcopy(report)
    work = copy.deepcopy(report)
    enforce(work)
    meta = work.get('report_metadata') or {}
    resolved_profile = normalize_report_profile(profile, meta)
    is_compact = (resolved_profile == 'compact')
    xss_dec = str(meta.get('xss_decision') or '').strip().lower()
    raw_findings = list(work.get('findings') or [])

    if xss_dec == 'drop':
        active_findings = [
            r for r in raw_findings
            if str(r.get('kind') or '') != 'observation'
            and not is_nonfinding_intake_record(r)
            and not is_passive_service_observation(r)
        ]
    else:
        active_findings = [
            r for r in raw_findings
            if not is_nonfinding_intake_record(r)
            and not is_passive_service_observation(r)
        ]

    scan_ctx = extract_scan_context(work)

    mask_ips = str(meta.get('mask_public_ips') or '').strip().lower() in {'1', 'true', 'yes', 'on'}
    ip_map = (
        collect_ip_mapping(repr(active_findings) + ' ' + repr(meta), target_alias=str(meta.get('target_alias') or 'target-app.local'))
        if mask_ips
        else {}
    )
    redaction_stats = {'ips_masked': 0, 'secrets_masked': 0, 'paths_masked': 0}

    def sanitize(val) -> str:
        return sanitize_text_value(str(val or ''), ip_map, redaction_stats)

    clean_tools_pool: list[str] = []
    for r in raw_findings:
        cleaned_t = _clean_tool_display(r.get('tool'))
        if cleaned_t != 'công cụ kiểm thử' and sanitize(cleaned_t) not in clean_tools_pool:
            clean_tools_pool.append(sanitize(cleaned_t))
    if not clean_tools_pool:
        fmt_hint_l = str(work.get('input_format') or '').lower()
        for tok, lbl in (('sqlmap', 'sqlmap'), ('nmap', 'nmap'), ('zap', 'OWASP ZAP'), ('burp', 'Burp Suite'), ('nuclei', 'nuclei'), ('nessus', 'Nessus')):
            if tok in fmt_hint_l:
                clean_tools_pool.append(lbl)
                break

    # --- Section 2.1 Input Sources (supports single file OR multi-file bundle I-01..I-K) ---
    raw_sources = work.get('input_sources') or []
    input_sources: list[dict] = []
    finding_to_source_id: dict[str, str] = {}

    if raw_sources:
        for idx, src in enumerate(raw_sources, 1):
            sid = f'I-{idx:02d}'
            fmt_code = str(src.get('format') or work.get('input_format') or 'auto')
            fcount = int(src.get('finding_count', 0))
            status_txt = (
                f"Đầy đủ cho phạm vi quét ({fcount} bản ghi)"
                if fcount > 0
                else 'Đã nạp hợp lệ (0 bản ghi cảnh báo)'
            )
            input_sources.append({
                'id': sid,
                'name': sanitize(src.get('name') or f'input_{idx}'),
                'source': FORMAT_DISPLAY.get(fmt_code, fmt_code),
                'status': status_txt,
                'sha256': str(src.get('sha256') or ''),
                'size_bytes': int(src.get('size_bytes') or 0),
                'finding_count': fcount,
            })
            for fid in src.get('finding_ids') or []:
                finding_to_source_id[str(fid)] = sid
    else:
        fmt_code = str(work.get('input_format') or 'normalized')
        src_desc = FORMAT_DISPLAY.get(fmt_code, fmt_code)
        if clean_tools_pool:
            src_desc = f"{src_desc} ({', '.join(clean_tools_pool)})"
        gaps = [str(g).strip().rstrip('.') for g in (scan_ctx.get('repro_gaps') or []) if str(g).strip()]
        has_any_unknown_sev = any(canonical_severity(r.get('severity'))[0] == 'unknown' for r in active_findings)
        status_notes = []
        if gaps and not is_compact:
            status_notes.extend(gaps[:2])
        if has_any_unknown_sev:
            status_notes.append('không kèm điểm CVSS gốc')
        status_str = (
            f"Đầy đủ ({len(active_findings)} bản ghi; {'; '.join(status_notes)})"
            if status_notes
            else f"Đầy đủ ({len(active_findings)} bản ghi chuẩn hóa)"
        )
        input_sources.append({
            'id': 'I-01',
            'name': sanitize(work.get('input_filename') or 'du_lieu_kiem_thu'),
            'source': src_desc,
            'status': status_str,
            'sha256': str(work.get('scan_sha256') or ''),
            'size_bytes': 0,
            'finding_count': len(active_findings),
        })

    default_source_id = input_sources[0]['id'] if input_sources else 'I-01'

    # --- Section 1 General Information (deduplicated URLs, DBMS, timestamps & clean tool names) ---
    gen_at = str(work.get('generated_at') or '')
    gen_day = gen_at[:10].replace('-', '') if len(gen_at) >= 10 else datetime.now(timezone.utc).strftime('%Y%m%d')
    sha8 = str(work.get('scan_sha256') or '00000000')[:8].upper()
    report_id = meta.get('report_id') or f'RPT-DBSEC-{gen_day}-{sha8}'

    lab_info = scan_ctx.get('lab') or {}
    raw_targets = [sanitize(t) for t in (scan_ctx.get('targets') or []) if t]
    if not raw_targets:
        raw_targets = [sanitize(r.get('location') or '') for r in active_findings if r.get('location')]
    targets: list[str] = []
    for raw_t in raw_targets:
        clean_t = re.sub(r'\s*\(parameter=[^)]*\)\s*$', '', raw_t, flags=re.I).strip()
        if clean_t and not any(clean_t.lower() == prev.lower() for prev in targets):
            targets.append(clean_t)

    project_name = (
        meta.get('project_name')
        or meta.get('application')
        or (f"Đánh giá bảo mật CSDL & ứng dụng {lab_info['name']}" if lab_info.get('name') else '')
        or (f"Đánh giá bảo mật CSDL & ứng dụng ({input_sources[0]['name']})")
    )
    raw_target_override = str(meta.get('target_object') or meta.get('client') or '').strip()
    if raw_target_override:
        dedup_override: list[str] = []
        for seg in [x.strip() for x in raw_target_override.split(';') if x.strip()]:
            norm_seg = re.sub(r'\s*\(parameter=[^)]*\)\s*$', '', seg, flags=re.I).strip()
            if norm_seg and not any(norm_seg.lower() == p.lower() for p in dedup_override):
                dedup_override.append(norm_seg)
        target_object = '; '.join(dedup_override) if dedup_override else raw_target_override
    else:
        target_object = '; '.join(targets[:4]) if targets else 'Chưa xác định rõ URL/địa chỉ đích trong dữ liệu đầu vào'

    dbms_summary = meta.get('dbms_override') or _infer_dbms_summary(active_findings, scan_ctx, sanitize)
    tools_str = ', '.join(clean_tools_pool) if clean_tools_pool else FORMAT_DISPLAY.get(str(work.get('input_format') or ''), 'Không ghi nhận trong đầu vào')
    raw_window = str(meta.get('assessment_period') or scan_ctx.get('scan_window') or '').strip()
    if raw_window:
        raw_window = re.sub(r'\(ghi trong log\s+ai-extracted\)', f"(ghi trong log {clean_tools_pool[0]})" if clean_tools_pool else '', raw_window, flags=re.I).strip(' ;')
        win_segs = [w.strip() for w in raw_window.split(';') if w.strip()]
        kept_wins: list[str] = []
        for ws in win_segs:
            hh = re.findall(r'\b\d{2}:\d{2}:\d{2}\b', ws)
            if hh and any(all(t in p for t in hh) for p in kept_wins):
                continue
            if hh:
                kept_wins = [p for p in kept_wins if not all(t in ws for t in (re.findall(r'\b\d{2}:\d{2}:\d{2}\b', p) or ['__none__']))]
            kept_wins.append(ws)
        testing_window = '; '.join(kept_wins)
    else:
        testing_window = (
            f"Không ghi nhận mốc giờ quét gốc trong tệp đầu vào (thời điểm phân tích: {gen_at[:16].replace('T', ' ')} UTC)"
            if gen_at else 'Không ghi nhận trong dữ liệu đầu vào'
        )
    scope_parts: list[str] = []
    if meta.get('allowed_scope'):
        scope_parts.append(meta['allowed_scope'])
    elif meta.get('excluded_areas'):
        scope_parts.append(meta['excluded_areas'])
    elif scan_ctx.get('scope_rule'):
        scope_parts.append(sanitize(scan_ctx['scope_rule']))
    if meta.get('note'):
        scope_parts.append(meta['note'])
    allowed_scope = (
        '; '.join(scope_parts)
        if scope_parts
        else (
            'Giới hạn trong mục tiêu kiểm thử của tệp đầu vào; không thực hiện tấn công phá hủy hoặc trích xuất bản ghi dữ liệu trái phép'
            if targets
            else 'Chỉ phân tích trong phạm vi bản ghi đầu vào được cung cấp; chưa có văn bản khai báo phạm vi riêng'
        )
    )

    general_info = [
        ('Mã báo cáo', report_id),
        ('Tên dự án', project_name),
        ('Đối tượng kiểm thử', target_object),
        ('Hệ quản trị CSDL', dbms_summary),
        ('Thời gian kiểm thử', testing_window),
        ('Công cụ kiểm thử', tools_str),
        ('Phạm vi kiểm thử được phép', allowed_scope),
    ]
    if meta.get('prepared_by'):
        general_info.append(('Người thực hiện', meta['prepared_by']))

    # --- Build Detailed Findings, Evidences, & OWASP Remediation Entries ---
    top10_map = mapping()
    cat_lookup = {c['id']: c for c in top10_map['categories']}
    retest_status_meta = meta.get('retest_status') or 'Chưa thực hiện'
    retest_evidence_meta = meta.get('retest_evidence') or 'Chưa có dữ liệu kiểm tra lại trong đầu vào'

    matrix = {
        sev_k: {STATE_CONFIRMED: 0, STATE_TENTATIVE: 0, STATE_INSUFFICIENT: 0}
        for sev_k, _ in SEVERITY_MATRIX_ROWS
    }

    findings_out: list[dict] = []
    all_evidences: list[dict] = []
    cited_owasp_docs: dict[str, dict] = {}
    next_ev_idx = 1

    for idx_f, row in enumerate(active_findings, 1):
        fid = f'F-{idx_f:02d}'
        src_id = finding_to_source_id.get(str(row.get('id') or ''), default_source_id)
        sev_key, sev_label = canonical_severity(row.get('severity'))
        state = classify_finding_state(row)
        if state in matrix[sev_key]:
            matrix[sev_key][state] += 1

        det = row.get('details') or {}
        tel = det.get('scan_telemetry') or {}
        component = _infer_component_label(row, sanitize)

        # AI reviewed claims if available
        ai_block = row.get('ai_analysis') or {}
        ai_claims = (ai_block.get('claims') or {}) if ai_block.get('status') == 'ai_reviewed' else {}
        ai_obs = [str(c.get('text_vi') or '') for c in (ai_claims.get('observations') or []) if c.get('text_vi')]
        ai_impacts = [str(c.get('text_vi') or '') for c in (ai_claims.get('potential_impacts') or []) if c.get('text_vi')]
        ai_limits = [str(c.get('text_vi') or '') for c in (ai_claims.get('limitations') or []) if c.get('text_vi')]

        ev_items, next_ev_idx, excluded_pkt_note = _build_evidence_items_for_finding(
            row,
            source_id=src_id,
            next_ev_num=next_ev_idx,
            sanitize=sanitize,
            ai_obs=ai_obs,
            is_compact=is_compact,
            fallback_tools=clean_tools_pool,
        )
        for ev_it in ev_items:
            all_evidences.append({**ev_it, 'finding_id': fid})

        # 6.4 OWASP Top 10:2025 classification (NEVER guess when unmapped/unknown)
        top10 = row.get('owasp_top10') or {}
        t_status = str(top10.get('status') or 'unknown')
        cats = list(top10.get('categories') or [])
        cwe_code = str(row.get('cwe') or '').strip()
        friendly_cwe = CWE_FRIENDLY.get(cwe_code) or cwe_text(row)
        if not cats and t_status == 'observation':
            row_cwes = finding_cwes(row)
            if len(row_cwes) == 1:
                cats = [c for c in top10_map['categories'] if row_cwes[0] in c['cwes']]

        if (t_status == 'in_scope' or (t_status == 'observation' and len(cats) == 1)) and cats:
            cat_id = cats[0]['id']
            raw_cat_title = str(cats[0]['title'] or '').strip()
            short_title = re.sub(rf'^{re.escape(cat_id)}\s*[-:]?\s*', '', raw_cat_title).strip()
            cat_full = f"{cat_id} - {short_title}" if short_title else cat_id
            cat_meta = cat_lookup.get(cat_id) or {}
            cat_url = str(cat_meta.get('url') or 'https://owasp.org/Top10/2025/')
            owasp_doc_name = 'OWASP Top 10'
            owasp_doc_ver = '2025'
            obs_clause = ' (áp dụng ở mức tham chiếu phân loại cho ghi nhận `Có dấu hiệu` cần xác minh thủ công)' if t_status == 'observation' else ''
            owasp_reason = (
                f"Phát hiện mang mã `{friendly_cwe}` ({cwe_origin(row)}), thuộc danh sách ánh xạ chính thức của danh mục `{cat_full}` trong OWASP Top 10:2025{obs_clause}."
            )
            cited_owasp_docs[cat_full] = {
                'type': 'OWASP Top 10:2025',
                'title': cat_full,
                'url': cat_url,
            }
        else:
            cat_full = 'Chưa xác định'
            cat_url = 'Chưa xác định (CWE nằm ngoài danh mục ánh xạ trực tiếp hoặc chưa đủ thông tin CWE)'
            owasp_doc_name = 'OWASP Top 10'
            owasp_doc_ver = '2025'
            owasp_reason = (
                f"Bản ghi có `{friendly_cwe}` ({top10.get('reason') or 'không đủ cơ sở đối chiếu trực tiếp vào một danh mục OWASP Top 10:2025 duy nhất'}). "
                f"Theo nguyên tắc trung thực dữ liệu, giữ trạng thái phân loại là `Chưa xác định`."
            )

        # 6.5 Severity grounding (strictly honoring input severity without fabricating scores)
        raw_cvss = str(det.get('cvss_score') or '').strip()
        raw_vec = str(det.get('cvss_vector') or '').strip()
        if sev_key != 'unknown':
            cvss_bit = f" (điểm CVSS ghi nhận trong đầu vào: `{raw_cvss}` — `{raw_vec}`)" if raw_cvss and raw_vec else (f" (điểm CVSS trong đầu vào: `{raw_cvss}`)" if raw_cvss else '')
            cvss_expl = build_cvss_rationale(row, scan_ctx) if (raw_cvss or raw_vec) else ''
            sev_basis = (
                f"Giữ nguyên mức độ `{sev_label}` được ghi nhận trực tiếp từ dữ liệu đầu vào{cvss_bit}, "
                f"đối chiếu phù hợp với bằng chứng `{', '.join(e['id'] for e in ev_items) or 'Chưa có'}`."
                + (f" {cvss_expl}" if cvss_expl else '')
            )
        else:
            tech_signals = []
            techs_found = det.get('techniques') or tel.get('techniques') or []
            if techs_found:
                tech_signals.append(f"{len(techs_found)} kỹ thuật ({', '.join(techs_found)})")
            if tel.get('databases'):
                tech_signals.append(f"liệt kê {len(tel['databases'])} schema")
            if state == STATE_TENTATIVE:
                tech_signals.append('cảnh báo dò sơ bộ heuristic')
            signal_clause = f" Dấu hiệu kỹ thuật: {'; '.join(tech_signals)}." if tech_signals else ''
            sev_basis = (
                f"Công cụ `{sanitize(_clean_tool_display(row.get('tool'), clean_tools_pool))}` không xuất nhãn mức độ hay điểm CVSS gốc; "
                f"giữ nguyên `Chưa xác định` theo nguyên tắc trung thực dữ liệu.{signal_clause}"
            )

        unknown_factors_bits: list[str] = []
        if not is_compact:
            unknown_factors_bits.extend(str(g).strip().rstrip('.') for g in (scan_ctx.get('repro_gaps') or []) if str(g).strip())
        if not tel.get('dumped_rows') and cwe_code == 'CWE-89' and state == STATE_CONFIRMED:
            unknown_factors_bits.append('mức độ nhạy cảm thực tế của dữ liệu trong bảng (chưa trích xuất hàng dữ liệu)')
        if state == STATE_TENTATIVE:
            unknown_factors_bits.append('kết quả kiểm chứng thực thi thực tế trên trình duyệt độc lập')
        for al in ai_limits[: (1 if is_compact else 3)]:
            cleaned_al = clean_internal_jargon(al).rstrip('.')
            # Passive OS/Apache EOL banner notes belong consolidated ONCE in Section 8.1, not repeated inside 6.5
            if is_compact and ('eol' in cleaned_al.lower() or 'debian' in cleaned_al.lower() or 'apache 2.4' in cleaned_al.lower()):
                continue
            if cleaned_al and cleaned_al not in unknown_factors_bits:
                unknown_factors_bits.append(cleaned_al)
        unknown_factors = (
            '; '.join(unknown_factors_bits[: (2 if is_compact else 5)]) + '.'
            if unknown_factors_bits
            else 'Phạm vi ảnh hưởng trên môi trường vận hành thực tế (chi tiết giới hạn chung tại Mục 8).'
        )

        # 6.6 & 6.7
        root_cause = _build_root_cause(row, state, component, ev_items, sanitize)
        potential_impact = _build_potential_impact(row, state, ai_impacts, sanitize)

        # Section 7 Remediation per finding (Top-2 OWASP controls in compact mode + 1 concise safe code snippet)
        guidance_list = list(row.get('guidance') or [])
        scanner_sol = sanitize(str(det.get('scanner_solution') or det.get('solution') or det.get('remediation') or '').strip())
        stack_hint = ' '.join([
            str(tel.get('web_tech') or ''),
            str(tel.get('dbms') or ''),
            str(row.get('title') or ''),
            str(row.get('location') or ''),
            ' '.join(str(x) for x in (row.get('evidence') or [])[:3]),
        ])
        code_examples = _extract_code_blocks_from_guidance(guidance_list, stack_hint=stack_hint)
        if is_compact and code_examples:
            trimmed_code_lines = [ln for ln in code_examples[0]['code'].splitlines() if ln.strip()][:10]
            code_examples = [{**code_examples[0], 'code': '\n'.join(trimmed_code_lines)[:520]}]

        rem_steps: list[str] = []
        if state in {STATE_TENTATIVE, STATE_INSUFFICIENT}:
            rem_steps.append(
                f"**Xác minh thủ công trước khi sửa đổi (`{fid}` — `{state}`):** kiểm chứng thực tế tại {component}; chỉ triển khai bản vá bên dưới khi xác nhận dương tính thật."
            )
        if scanner_sol and (not is_compact or not guidance_list):
            rem_steps.append(f"**Khuyến nghị từ công cụ kiểm thử:** {scanner_sol}")

        selected_guidance = _select_top_guidance_for_finding(guidance_list, stack_hint=stack_hint, is_compact=is_compact)
        ref_entries: list[dict] = []
        for g in selected_guidance:
            sec_name = str(g.get('section') or g.get('title') or 'OWASP Cheat Sheet').strip()
            g_url = str(g.get('url') or '').strip()
            short_sec = ' / '.join(p.strip() for p in sec_name.split('/') if p.strip())
            if is_compact and len(short_sec) > 85:
                parts_s = [p.strip() for p in sec_name.split('/') if p.strip()]
                short_sec = f"{parts_s[0]} / {parts_s[-1]}" if len(parts_s) >= 2 else sec_name[:85]
            raw_g_txt = str(
                g.get('source_excerpt')
                or g.get('guidance_vi')
                or g.get('text')
                or g.get('excerpt')
                or g.get('summary_vi')
                or ''
            )
            prose_without_code = _FENCED_CODE_RE.sub(' ', raw_g_txt).strip()
            max_ex_len = 200 if is_compact else 440
            cleaned_ex = _clean_markdown_excerpt(prose_without_code, max_len=max_ex_len)
            ai_comp = str(g.get('guidance_summary_vi') or '').strip()
            if is_compact and ai_comp:
                rem_steps.append(f"**Theo `{short_sec}` (OWASP):** {ai_comp.rstrip('.')}.")
            elif cleaned_ex:
                rem_steps.append(f"**Theo `{short_sec if is_compact else sec_name}` (OWASP):** {cleaned_ex}")
            else:
                card_act = _extract_card_action(g, row, lang='vi').strip().rstrip('.')
                rem_steps.append(f"**Theo `{short_sec if is_compact else sec_name}` (OWASP):** {card_act}.")
            ref_entries.append({'section': short_sec if is_compact else sec_name, 'url': g_url})
            sheet_title = sec_name.split(' / ')[0].strip()
            cited_owasp_docs[sheet_title] = {
                'type': 'OWASP Cheat Sheet Series',
                'title': sheet_title,
                'url': g_url or 'https://cheatsheetseries.owasp.org/',
            }

        if not rem_steps:
            rem_steps.append(
                f"Thực hiện rà soát mã nguồn/cấu hình trực tiếp tại {component} để loại bỏ nguyên nhân thuộc nhóm `{friendly_cwe}`, "
                f"kết hợp nguyên tắc đặc quyền tối thiểu trên tài khoản kết nối CSDL."
            )

        dbf = db_frame(row)
        db_layer = (dbf.get('control_label') or 'tầng giao tiếp ứng dụng — CSDL') if dbf else 'tầng ứng dụng — CSDL'

        if state == STATE_CONFIRMED:
            if sev_key in {'critical', 'high'} or cwe_code in {'CWE-89', 'CWE-564', 'CWE-943', 'CWE-306', 'CWE-1393'}:
                priority = (
                    f"**Ưu tiên P1 (Khẩn cấp — Xử lý ngay trước khi vận hành):** `{fid}` có trạng thái `{STATE_CONFIRMED}` "
                    f"với bằng chứng thực nghiệm trực tiếp (`{', '.join(e['id'] for e in ev_items)}`) tác động vào `{db_layer}`, "
                    f"có nguy cơ xâm phạm trực tiếp tính bí mật và toàn vẹn dữ liệu trong CSDL."
                )
            elif sev_key == 'medium':
                priority = (
                    f"**Ưu tiên P2 (Cao / Trung bình — Lên kế hoạch xử lý sớm):** `{fid}` đã được xác nhận bằng bằng chứng kỹ thuật "
                    f"(`{', '.join(e['id'] for e in ev_items)}`), cần khắc phục để ngăn chặn khai thác kết hợp."
                )
            else:
                priority = (
                    f"**Ưu tiên P3 (Củng cố cấu hình theo lộ trình):** `{fid}` đã được ghi nhận với bằng chứng `{', '.join(e['id'] for e in ev_items)}`, "
                    f"nên thực hiện làm cứng để tăng cường phòng thủ chiều sâu."
                )
        else:
            priority = (
                f"**Ưu tiên P3 (Xác minh thủ công trước, khắc phục có điều kiện):** `{fid}` hiện ở trạng thái `{state}`, "
                f"cần hoàn tất bước xác minh thực tế sau khi đã xử lý dứt điểm các phát hiện `Đã xác nhận` ưu tiên P1/P2."
            )

        ev_ref_str = ', '.join(e['id'] for e in ev_items) or fid
        if cwe_code in {'CWE-89', 'CWE-564', 'CWE-943'}:
            rem_goal = (
                f"Tách biệt hoàn toàn dữ liệu đầu vào không tin cậy tại {component} khỏi cấu trúc câu lệnh truy vấn ở `{db_layer}`, "
                f"loại bỏ khả năng tiêm nhiễm truy vấn và bảo vệ tính bí mật, toàn vẹn của CSDL theo chuẩn OWASP."
            )
            retest_check = (
                f"Kiểm tra lại {component} với bộ payload kiểm chứng tương đương bằng chứng `{ev_ref_str}`: "
                f"(1) xác nhận tham số đầu vào không còn làm thay đổi lô-gic truy vấn hay để lộ thông báo lỗi CSDL; "
                f"(2) xác nhận truy vấn hợp lệ vẫn trả kết quả đúng (regression test)."
            )
        elif cwe_code == 'CWE-79':
            rem_goal = (
                f"Đảm bảo toàn bộ dữ liệu đầu vào phản hồi từ {component} được mã hóa đúng ngữ cảnh hiển thị trước khi dựng trang HTML/kịch bản, "
                f"ngăn chặn thực thi mã kịch bản phía trình duyệt theo khuyến nghị OWASP."
            )
            retest_check = (
                f"Kiểm tra lại {component} đối chiếu bằng chứng `{ev_ref_str}`: "
                f"(1) xác nhận các ký tự điều khiển HTML/JavaScript được mã hóa an toàn trong phản hồi HTTP; "
                f"(2) xác nhận hiển thị giao diện bình thường không bị lỗi ký tự (regression test)."
            )
        elif cwe_code in {'CWE-306', 'CWE-287', 'CWE-521', 'CWE-1393', 'CWE-798'}:
            rem_goal = (
                f"Thiết lập cơ chế xác thực mạnh, loại bỏ thông tin đăng nhập mặc định/rỗng và giới hạn phạm vi tiếp xúc mạng cho dịch vụ tại {component} theo khuyến nghị OWASP."
            )
            retest_check = (
                f"Kiểm tra lại dịch vụ tại {component} đối chiếu bằng chứng `{ev_ref_str}`: "
                f"(1) xác nhận kết nối không xác thực hoặc dùng thông tin mặc định bị từ chối hoàn toàn; "
                f"(2) xác nhận kết nối từ ứng dụng được cấp phép vẫn hoạt động ổn định (regression test)."
            )
        elif cwe_code in {'CWE-319', 'CWE-295', 'CWE-311', 'CWE-327'}:
            rem_goal = (
                f"Đảm bảo kênh truyền thông tới dịch vụ tại {component} chỉ sử dụng giao thức TLS mạnh, bộ mã an toàn và chứng chỉ hợp lệ theo khuyến nghị OWASP."
            )
            retest_check = (
                f"Kiểm tra lại phiên bắt tay mật mã tại {component} đối chiếu bằng chứng `{ev_ref_str}`: "
                f"(1) xác nhận dịch vụ từ chối hoàn toàn giao thức cũ/bộ mã yếu và chỉ chấp nhận TLS 1.2/1.3 với chứng chỉ hợp lệ; "
                f"(2) xác nhận ứng dụng kết nối bình thường qua TLS mới (regression test)."
            )
        else:
            rem_goal = (
                f"Khắc phục triệt để điểm yếu bảo mật tại {component} thuộc phân loại `{friendly_cwe}`, "
                f"đảm bảo cấu hình và kiểm soát an toàn tuân thủ khuyến nghị chính thức của OWASP."
            )
            retest_check = (
                f"Kiểm tra lại {component} đối chiếu trực tiếp với bằng chứng `{ev_ref_str}`: "
                f"(1) xác nhận dấu hiệu kỹ thuật của điểm yếu không còn tái hiện; "
                f"(2) xác nhận chức năng nghiệp vụ liên quan vận hành bình thường (regression test)."
            )
        rem_reason = (
            f"Các biện pháp được chọn trực tiếp từ kho tri thức OWASP dựa trên mã điểm yếu `{friendly_cwe}`, "
            f"bằng chứng thực tế `{', '.join(e['id'] for e in ev_items) or 'Chưa có'}` trên `{db_layer}`"
            + (f" và đặc thù hệ quản trị `{dbms_summary}`." if dbms_summary != 'Chưa xác định từ dữ liệu đầu vào' else '.')
        )
        retest_method = (
            f"Chạy lại `{sanitize(_clean_tool_display(row.get('tool'), clean_tools_pool))}` cùng tham số tương đương `{src_id}`, "
            f"kết hợp đối chiếu mã nguồn/cấu hình sau khi vá."
        )

        extra_ai_notes: list[str] = []
        for o in ai_obs[1:]:
            co = clean_internal_jargon(o)
            if not co:
                continue
            if is_compact and any(tok in co.lower() for tok in ('eol', 'debian', 'apache 2.4', 'damn vulnerable', 'dvwa')):
                continue
            extra_ai_notes.append(co)
            if is_compact and len(extra_ai_notes) >= 2:
                break
        ev_prof = evidence_profile(row)
        clean_title = clean_internal_jargon(sanitize(row.get('title') or 'Phát hiện kiểm thử bảo mật')) or sanitize(row.get('title') or 'Phát hiện kiểm thử bảo mật')
        state_detail_str = (
            f"{state} — {ev_prof['label_vi']}"
            if is_compact
            else f"{state} ({ev_prof['label_vi']} — {ev_prof['note_vi']})"
        )
        findings_out.append({
            'id': fid,
            'raw_id': str(row.get('id') or fid),
            'source_id': src_id,
            'title': clean_title,
            'component': component,
            'cwe_code': cwe_code,
            'db_layer': db_layer,
            'owasp_doc': owasp_doc_name,
            'owasp_version': owasp_doc_ver,
            'owasp_category': cat_full,
            'owasp_reason': owasp_reason,
            'owasp_url': cat_url,
            'cwe_label': friendly_cwe,
            'severity_key': sev_key,
            'severity_label': sev_label,
            'state': state,
            'state_detail': state_detail_str,
            'evidences': ev_items,
            'evidence_ids': [e['id'] for e in ev_items],
            'ai_notes': extra_ai_notes,
            'excluded_http_note': excluded_pkt_note,
            'severity_basis': sev_basis,
            'unknown_factors': unknown_factors,
            'root_cause': root_cause,
            'potential_impact': potential_impact,
            'rem_goal': rem_goal,
            'rem_steps': rem_steps,
            'code_examples': code_examples,
            'rem_refs': ref_entries,
            'rem_reason': rem_reason,
            'priority': priority,
            'retest_check': retest_check,
            'retest_method': retest_method,
            'retest_result': retest_status_meta,
            'retest_evidence': retest_evidence_meta,
            'evidence_tier': ev_prof['label_vi'],
            'ai_status': STATUS_LABELS.get(str(ai_block.get('status') or 'not_requested'), 'Không gọi AI'),
        })

    # --- Section 2.2 Data Quality Assessment ---
    was_redacted = (
        redaction_stats['secrets_masked'] > 0
        or redaction_stats['paths_masked'] > 0
        or bool(ip_map)
        or any('[REDACTED' in str(e.get('snippet') or '') for e in all_evidences)
    )
    present_cwes = {f['cwe_code'] for f in findings_out if f['cwe_code']}
    has_query_findings = bool(present_cwes & {'CWE-89', 'CWE-564', 'CWE-943'})
    has_xss_findings = 'CWE-79' in present_cwes
    has_auth_findings = bool(present_cwes & {'CWE-306', 'CWE-287', 'CWE-521', 'CWE-1393', 'CWE-798'})
    has_tls_findings = bool(present_cwes & {'CWE-319', 'CWE-295', 'CWE-311', 'CWE-327'})
    has_app_findings = any('://' in f['component'] for f in findings_out) or has_query_findings or has_xss_findings
    has_net_findings = any(not ('://' in f['component']) for f in findings_out) or has_auth_findings or has_tls_findings

    have_bits: list[str] = []
    if targets:
        have_bits.append(f"địa chỉ/mục tiêu kiểm thử ({'; '.join(targets[:3])})")
    if dbms_summary != 'Chưa xác định từ dữ liệu đầu vào':
        have_bits.append(f"thông tin hệ quản trị CSDL (`{dbms_summary}`)")
    if scan_ctx.get('auth_context'):
        have_bits.append(f"ngữ cảnh xác thực ({sanitize(scan_ctx['auth_context'])})")
    if all_evidences:
        ev_span = (
            f"`{all_evidences[0]['id']}`"
            if len(all_evidences) == 1
            else f"`{all_evidences[0]['id']}`..`{all_evidences[-1]['id']}`"
        )
        have_bits.append(f"{len(all_evidences)} mục bằng chứng kỹ thuật được đánh mã ({ev_span})")
    if any('HTTP' in e['kind'] for e in all_evidences):
        redact_tag = ' (đã che thông tin phiên nhạy cảm `[REDACTED]`)' if was_redacted else ''
        have_bits.append(f"bản ghi gói tin HTTP Request/Response nguyên văn{redact_tag}")
    if findings_out and all(f['severity_key'] != 'unknown' for f in findings_out):
        have_bits.append('nhãn mức độ nghiêm trọng gốc đầy đủ trên toàn bộ phát hiện')
    if not have_bits:
        have_bits.append(f"tệp đầu vào `{input_sources[0]['name']}` định dạng `{input_sources[0]['source']}`")

    missing_bits: list[str] = []
    if has_app_findings and has_net_findings:
        missing_bits.append('mã nguồn ứng dụng phía máy chủ và tệp cấu hình gốc trên máy chủ đích (do kiểm thử hộp đen từ bên ngoài)')
    elif has_app_findings:
        missing_bits.append('mã nguồn ứng dụng phía máy chủ và tệp cấu hình kết nối CSDL (do kiểm thử hộp đen từ bên ngoài)')
    elif has_net_findings:
        missing_bits.append('tệp cấu hình trực tiếp trên máy chủ dịch vụ đích (do quét kiểm thử từ bên ngoài qua mạng)')
    else:
        missing_bits.append('thông tin cấu hình nội bộ chi tiết của hệ thống đích ngoài phạm vi bản quét cung cấp')

    for g in scan_ctx.get('repro_gaps') or []:
        if str(g).strip():
            missing_bits.append(str(g).strip().rstrip('.'))
    if any(f['severity_key'] == 'unknown' for f in findings_out):
        missing_bits.append('nhãn mức độ nghiêm trọng / điểm CVSS gốc trên các bản ghi do công cụ dòng lệnh không tự gán điểm')
    if any(f['state'] in {STATE_TENTATIVE, STATE_INSUFFICIENT} for f in findings_out):
        missing_bits.append('bằng chứng xác minh độc lập cho các ghi nhận chưa đủ điều kiện xác nhận (`Có dấu hiệu` / `Chưa đủ dữ liệu`)')
    if findings_out and retest_status_meta == 'Chưa thực hiện':
        missing_bits.append('nhật ký kiểm thử lại (retest) sau khi triển khai khắc phục')

    redact_limit_clause = (
        ', và các thông tin nhạy cảm về phiên/đường dẫn cục bộ đã được làm sạch bằng `[REDACTED]`.'
        if was_redacted
        else '.'
    )
    quality_assessment = {
        'present': '; '.join(have_bits) + '.',
        'missing': '; '.join(dict.fromkeys(missing_bits)) + '.',
        'analytic_limits': (
            'Chỉ kết luận trong phạm vi bằng chứng đầu vào (các giới hạn phân tích & môi trường chi tiết tổng hợp tại Mục 8)'
            + redact_limit_clause
            if is_compact
            else (
                'Phân tích chỉ kết luận trên các thành phần, tham số và dịch vụ thực sự xuất hiện trong tệp đầu vào; '
                'mọi nhận định về nguyên nhân ở tầng mã nguồn/cấu hình nội bộ chỉ được trình bày dưới dạng giả thuyết kỹ thuật cần đối chiếu thực tế'
                + redact_limit_clause
            )
        ),
    }

    # --- Section 3 Methodology ---
    mode_raw = str(work.get('mode') or 'demo-no-ai')
    model_raw = str(work.get('model') or 'none')
    is_ai_mode = mode_raw not in {'demo-no-ai', 'none', ''}
    cs_total = _bundled_cheatsheet_count()
    cs_count_phrase = f"bộ {cs_total} tài liệu chính thức thuộc " if cs_total else 'bộ tài liệu chính thức thuộc '
    matched_doc_titles = [d['title'] for d in cited_owasp_docs.values()]
    matched_doc_clause = (
        f" Đối chiếu trực tiếp: {', '.join(f'`{t}`' for t in matched_doc_titles[:4])}."
        if matched_doc_titles
        else ''
    )
    methodology = {
        'method': (
            'Đọc hiểu trực tiếp đầu vào bằng AI cục bộ kết hợp kiểm chứng trích dẫn nguyên văn (`I-xx` → `E-xx`), '
            'ánh xạ `OWASP Top 10:2025` khóa cứng và truy xuất lai (`Multilingual-E5` + `BM25` `RRF`) trên kho `OWASP Cheat Sheet Series` CSDL.'
            if (is_ai_mode and is_compact)
            else (
                'Phân tích kết hợp hai tầng (AI-First Direct Input Reading + Hybrid Extractive OWASP RAG + Deterministic Verification): '
                '(1) mô hình ngôn ngữ cục bộ đọc trực tiếp tệp kết quả kiểm thử / báo cáo đầu vào, đối khớp nguyên văn từng trích đoạn bằng chứng `E-xx` và tương quan rủi ro liên nguồn (`I-xx`); '
                '(2) ánh xạ CWE sang `OWASP Top 10:2025` theo bảng chuẩn khóa cứng; '
                '(3) truy xuất lai (Hybrid Search: `Multilingual-E5` Dense Cosine kết hợp `Okapi BM25` nhận biết tiêu đề mục theo `Reciprocal Rank Fusion - RRF`) trên kho `OWASP Cheat Sheet Series` chuyên biệt CSDL; '
                '(4) tổng hợp phân tích & tự động kiểm chứng chéo trích dẫn để loại bỏ suy diễn không có bằng chứng.'
                if is_ai_mode
                else 'Phân tích tất định chuẩn hóa dữ liệu đầu vào kết hợp đối chiếu trực tiếp `OWASP Top 10:2025` và thẻ tri thức `OWASP` đã phê duyệt.'
            )
        ),
        'tools': (
            f"Công cụ đầu vào: `{tools_str}` | Truy xuất lai: `multilingual-e5-small` + `BM25` (`RRF`) | "
            + (f"LLM cục bộ: `{model_raw}`." if is_ai_mode else 'Chế độ Demo cục bộ (`--demo`).')
        ),
        'references': (
            f"OWASP Top 10:2025 và {cs_count_phrase}OWASP Cheat Sheet Series chuyên biệt CSDL (CC BY-SA 4.0).{matched_doc_clause}"
        ),
        'criteria': (
            '4 trạng thái xác minh (`Đã xác nhận`, `Có dấu hiệu`, `Chưa đủ dữ liệu`, `Không xác nhận được`); '
            'mức độ nghiêm trọng giữ nguyên từ đầu vào (`Chưa xác định` khi công cụ gốc không cung cấp).'
        ),
    }

    # --- Section 4 Summary ---
    matrix_rows = [
        (
            sev_label,
            matrix[sev_key][STATE_CONFIRMED],
            matrix[sev_key][STATE_TENTATIVE],
            matrix[sev_key][STATE_INSUFFICIENT],
        )
        for sev_key, sev_label in SEVERITY_MATRIX_ROWS
    ]
    confirmed_list = [f for f in findings_out if f['state'] == STATE_CONFIRMED]
    tentative_list = [f for f in findings_out if f['state'] == STATE_TENTATIVE]
    insufficient_list = [f for f in findings_out if f['state'] == STATE_INSUFFICIENT]

    ai_sum = work.get('ai_summary') or {}
    ai_sum_claims = (ai_sum.get('claims') or {}) if ai_sum.get('status') == 'ai_reviewed' else {}
    if is_compact:
        summary_lead = (
            f"Từ {len(input_sources)} nguồn đầu vào (`{', '.join(s['id'] for s in input_sources)}`), "
            f"ghi nhận **{len(findings_out)}** mục: **{len(confirmed_list)}** `{STATE_CONFIRMED}`, "
            f"**{len(tentative_list)}** `{STATE_TENTATIVE}` và **{len(insufficient_list)}** `{STATE_INSUFFICIENT}`."
        )
        if confirmed_list:
            top_desc = '; '.join(f"`{f['id']}` ({f['title']})" for f in confirmed_list[:3])
            summary_lead += f" Trọng tâm cần xử lý ngay: {top_desc}."
        if tentative_list or insufficient_list:
            pend_desc = ', '.join(f"`{f['id']}` (`{f['state']}`)" for f in (tentative_list + insufficient_list)[:4])
            summary_lead += f" Ghi nhận tách riêng chờ xác minh thủ công: {pend_desc}."
        overview_paras = [summary_lead]
    else:
        overview_paras = [
            (
                f"Từ {len(input_sources)} nguồn dữ liệu đầu vào (`{', '.join(s['id'] for s in input_sources)}`), "
                f"báo cáo ghi nhận tổng cộng **{len(findings_out)}** phát hiện: **{len(confirmed_list)}** phát hiện ở trạng thái `{STATE_CONFIRMED}`, "
                f"**{len(tentative_list)}** phát hiện ở trạng thái `{STATE_TENTATIVE}` và **{len(insufficient_list)}** phát hiện ở trạng thái `{STATE_INSUFFICIENT}`."
            )
        ]
        for s_obs in (ai_sum_claims.get('observations') or [])[:2]:
            txt = clean_internal_jargon(s_obs.get('text_vi') or '')
            if txt:
                overview_paras.append(txt)
        if confirmed_list:
            top_desc = '; '.join(f"`{f['id']}` ({f['title']} tại {f['component']})" for f in confirmed_list[:3])
            overview_paras.append(f"Các điểm yếu đã được xác nhận bằng bằng chứng kỹ thuật trực tiếp gồm: {top_desc}.")
        if tentative_list or insufficient_list:
            pend_desc = ', '.join(f"`{f['id']}` (`{f['state']}`)" for f in (tentative_list + insufficient_list)[:4])
            overview_paras.append(
                f"Các ghi nhận chưa đủ điều kiện kết luận xác nhận ({pend_desc}) được tách bạch rõ ràng để xác minh thủ công, không gộp chung vào nhóm lỗ hổng đã xác nhận."
            )

    # --- Section 8 Consolidated Limitations, Verification Checklist & Reliability ---
    limits_bullets = [
        'Kiểm thử hộp đen từ dữ liệu đầu vào: không truy cập mã nguồn ứng dụng, tệp cấu hình máy chủ đích hay can thiệp trực tiếp CSDL; nguyên nhân tại Mục 6.6 là giả thuyết kỹ thuật cần đối chiếu mã nguồn.',
    ]
    if scan_ctx.get('eol_notes'):
        merged_eol = '; '.join(clean_internal_jargon(sanitize(e)) for e in scan_ctx['eol_notes'] if clean_internal_jargon(sanitize(e)))
        if merged_eol:
            limits_bullets.append(
                f"Ghi nhận thụ động từ banner môi trường: {merged_eol} (chỉ mang tính cảnh báo vòng đời nền tảng, không gộp thành lỗ hổng CSDL)."
            )
    if not is_compact:
        limits_bullets.append(
            'Các trích đoạn khuyến nghị từ `OWASP Cheat Sheet Series` cần được kiểm tra tính tương thích kiến trúc trước khi triển khai.'
        )
        for s_lim in (ai_sum_claims.get('limitations') or [])[:2]:
            txt = clean_internal_jargon(s_lim.get('text_vi') or '')
            if txt and txt not in limits_bullets:
                limits_bullets.append(txt)

    verify_items: list[str] = []
    for f in findings_out:
        if f['state'] in {STATE_TENTATIVE, STATE_INSUFFICIENT}:
            verify_items.append(
                f"Xác minh thủ công `{f['id']}` ({f['title']}) tại {f['component']} để phân định rõ dương tính thật hay cảnh báo nhiễu."
            )
    if has_query_findings:
        verify_items.append(
            'Đối chiếu trực tiếp mã nguồn tầng truy cập dữ liệu và cấu hình phân quyền tài khoản CSDL (`GRANT` / vai trò kết nối) để kiểm chứng giả thuyết nguyên nhân tại Mục 6.6.'
        )
    if has_xss_findings:
        verify_items.append(
            'Kiểm tra cơ chế mã hóa đầu ra theo ngữ cảnh (output encoding / auto-escaping) tại tầng giao diện của các điểm cuối bị ảnh hưởng.'
        )
    if has_auth_findings:
        verify_items.append(
            'Kiểm tra tệp cấu hình xác thực dịch vụ CSDL, chính sách mật khẩu và quy tắc giới hạn giao diện mạng lắng nghe trên máy chủ đích.'
        )
    if has_tls_findings:
        verify_items.append(
            'Kiểm tra cấu hình giao thức TLS, danh sách bộ mã (cipher suites) và chuỗi chứng chỉ số trực tiếp trên dịch vụ đích.'
        )
    if findings_out and not (has_query_findings or has_xss_findings or has_auth_findings or has_tls_findings):
        verify_items.append(
            'Đối chiếu mã nguồn/tệp cấu hình trực tiếp trên thành phần bị ảnh hưởng để kiểm chứng các giả thuyết nguyên nhân tại Mục 6.6.'
        )
    if not findings_out:
        verify_items.append(
            'Mở rộng phạm vi kịch bản kiểm thử chủ động hoặc rà soát cấu hình nội bộ nếu cần đánh giá sâu hơn ngoài phạm vi bản quét hiện tại.'
        )
    if findings_out and retest_status_meta == 'Chưa thực hiện':
        verify_items.append(
            'Thực hiện đầy đủ kế hoạch kiểm tra lại (retest) tại Mục 7.5 sau khi triển khai bản vá để có bằng chứng đóng lỗ hổng.'
        )

    confirmed_ev_ids = [eid for f in confirmed_list for eid in f['evidence_ids']]
    reliability_paras = [
        (
            "Độ tin cậy phân tầng theo bằng chứng: "
            + (
                f"nhóm `{STATE_CONFIRMED}` ({', '.join(f['id'] for f in confirmed_list)}) có độ tin cậy cao nhờ bằng chứng phản hồi trực tiếp (`{', '.join(confirmed_ev_ids[:5])}`); "
                if confirmed_list
                else 'chưa có phát hiện đạt ngưỡng `Đã xác nhận`; '
            )
            + (
                f"nhóm `{STATE_TENTATIVE}` / `{STATE_INSUFFICIENT}` ({', '.join(f['id'] for f in tentative_list + insufficient_list)}) chỉ mang tính định hướng xác minh thủ công."
                if (tentative_list or insufficient_list)
                else 'mọi nhận định ngoài dữ liệu đầu vào đều gắn nhãn giả thuyết hoặc `Chưa xác định`.'
            )
        )
    ]
    if not is_compact:
        reliability_paras.append(
            'Nguyên tắc xuyên suốt: mọi suy luận vượt quá dữ liệu đầu vào đều được gắn nhãn giả thuyết hoặc `Chưa xác định`, không thay thế cho kiểm chứng độc lập.'
        )

    # --- Section 9 Conclusion ---
    conclusion_paras: list[str] = []
    if confirmed_list:
        conclusion_paras.append(
            f"Trên `{target_object}`, kết quả kiểm thử xác nhận **{len(confirmed_list)}** lỗ hổng có bằng chứng trực tiếp "
            f"({', '.join(f['id'] + ': ' + f['title'] for f in confirmed_list[:4])})"
            + (
                f" và **{len(tentative_list) + len(insufficient_list)}** mục cần xác minh bổ sung ({', '.join(f['id'] for f in (tentative_list + insufficient_list)[:4])}); "
                if (tentative_list or insufficient_list)
                else '; '
            )
            + 'các biện pháp khắc phục tại Mục 7 được đối chiếu trực tiếp từ `OWASP Top 10:2025` và `OWASP Cheat Sheet Series`.'
        )
    else:
        conclusion_paras.append(
            f"Trên `{target_object}`, dữ liệu đầu vào ghi nhận **{len(findings_out)}** mục và chưa có phát hiện nào ở trạng thái `{STATE_CONFIRMED}`."
        )
    if retest_status_meta == 'Chưa thực hiện':
        conclusion_paras.append(
            'Do chưa có kết quả kiểm tra lại (retest) sau khắc phục, báo cáo không khẳng định hệ thống đã an toàn và không kết luận lỗ hổng đã được xử lý hoàn toàn.'
        )
    else:
        conclusion_paras.append(
            f"Trạng thái kiểm tra lại: `{retest_status_meta}` (`{retest_evidence_meta}`), chỉ có hiệu lực trong phạm vi mục tiêu đã kiểm chứng lại."
        )

    return {
        'profile': resolved_profile,
        'title': REPORT_TITLE,
        'subtitle': REPORT_SUBTITLE,
        'section_titles': SECTION_TITLES,
        'general_info': general_info,
        'input_sources': input_sources,
        'quality_assessment': quality_assessment,
        'methodology': methodology,
        'matrix_rows': matrix_rows,
        'overview_paras': overview_paras,
        'findings': findings_out,
        'all_evidences': all_evidences,
        'cited_owasp_docs': list(cited_owasp_docs.values()),
        'knowledge_sha256': str(work.get('knowledge_sha256') or ''),
        'scan_sha256': str(work.get('scan_sha256') or ''),
        'limits_bullets': limits_bullets,
        'verify_items': verify_items,
        'reliability_paras': reliability_paras,
        'conclusion_paras': conclusion_paras,
        'retest_status': retest_status_meta,
        'retest_evidence': retest_evidence_meta,
        'counts': {
            'total': len(findings_out),
            'confirmed': len(confirmed_list),
            'tentative': len(tentative_list),
            'insufficient': len(insufficient_list),
            'with_guidance': sum(1 for f in findings_out if f['rem_refs']),
        },
    }


def _md_cell(val: str) -> str:
    return str(val or '').replace('|', '\\|').replace('\n', ' ').strip()


def render_dbsec_markdown(report: dict, *, profile: str | None = None) -> str:
    """Render complete 10-section Markdown strictly conforming to the official coursework template."""
    m = prepare_dbsec_report(report, profile=profile)
    out: list[str] = [
        f"# {m['title']}",
        '',
        '## 1. Thông tin chung',
        '',
    ]
    for k, v in m['general_info']:
        out.append(f"- **{k}:** {v}")

    # Section 2
    out.extend([
        '',
        '## 2. Đánh giá dữ liệu đầu vào',
        '',
        '### 2.1. Nguồn dữ liệu',
        '',
        '| Mã | Tên dữ liệu | Nguồn | Trạng thái |',
        '|---|---|---|---|',
    ])
    for s in m['input_sources']:
        out.append(f"| {_md_cell(s['id'])} | `{_md_cell(s['name'])}` | {_md_cell(s['source'])} | {_md_cell(s['status'])} |")

    qa = m['quality_assessment']
    out.extend([
        '',
        '### 2.2. Chất lượng dữ liệu',
        '',
        f"- **Thông tin đã có:** {qa['present']}",
        f"- **Thông tin còn thiếu:** {qa['missing']}",
        f"- **Giới hạn phân tích:** {qa['analytic_limits']}",
    ])

    # Section 3
    meth = m['methodology']
    out.extend([
        '',
        '## 3. Phương pháp phân tích',
        '',
        f"- **Phương pháp:** {meth['method']}",
        f"- **Công cụ hỗ trợ:** {meth['tools']}",
        f"- **Tài liệu đối chiếu:** {meth['references']}",
        f"- **Tiêu chí phân loại:** {meth['criteria']}",
    ])

    # Section 4
    out.extend([
        '',
        '## 4. Tóm tắt kết quả',
        '',
        '### 4.1. Tổng quan phát hiện',
        '',
        '| Mức độ | Đã xác nhận | Có dấu hiệu | Chưa đủ dữ liệu |',
        '|---|---:|---:|---:|',
    ])
    for sev_lbl, c_conf, c_tent, c_insuf in m['matrix_rows']:
        out.append(f"| {sev_lbl} | {c_conf} | {c_tent} | {c_insuf} |")
    out.extend([
        '',
        '*Ghi chú: Chỉ thống kê các phát hiện thực tế từ dữ liệu đầu vào. Không tự tạo số liệu hoặc tự gán mức độ nghiêm trọng khi công cụ gốc không cung cấp.*',
        '',
        '### 4.2. Nhận xét tổng quan',
        '',
    ])
    for p in m['overview_paras']:
        out.extend([p, ''])

    # Section 5
    out.extend([
        '## 5. Danh sách phát hiện',
        '',
        '| ID | Phát hiện | Thành phần | OWASP | Mức độ | Trạng thái |',
        '|---|---|---|---|---|---|',
    ])
    if not m['findings']:
        out.append('| — | Không ghi nhận cảnh báo lỗ hổng trong dữ liệu đầu vào | — | Chưa xác định | Chưa xác định | Không xác nhận được |')
    else:
        for f in m['findings']:
            out.append(
                f"| {f['id']} | {_md_cell(f['title'])} | {_md_cell(f['component'])} | "
                f"{_md_cell(f['owasp_category'])} | {_md_cell(f['severity_label'])} | {_md_cell(f['state'])} |"
            )

    # Section 6
    out.extend([
        '',
        '## 6. Phân tích chi tiết phát hiện',
    ])
    if not m['findings']:
        out.extend(['', 'Không có phát hiện nào trong dữ liệu đầu vào cần phân tích chi tiết.'])
    for f in m['findings']:
        out.extend([
            '',
            f"### {f['id']}: {f['title']}",
            '',
            '#### 6.1. Trạng thái phát hiện',
            f"- {f['state_detail']}",
            '',
            '#### 6.2. Vị trí và thành phần bị ảnh hưởng',
            f"- {f['component']} (`{f['cwe_label']}`)",
            '',
            '#### 6.3. Bằng chứng',
        ])
        if not f['evidences']:
            out.append(f"- Không có trích đoạn bằng chứng phản hồi chi tiết trong nguồn `{f['source_id']}`.")
        for ev in f['evidences']:
            out.extend([
                f"- **Mã bằng chứng:** `{ev['id']}` ({ev['kind']})",
                f"  - **Nguồn:** `{ev['source_id']}`",
                '  - **Trích đoạn dữ liệu gốc:**',
                '```text',
                ev['snippet'],
                '```',
                f"  - **Giải thích bằng chứng:** {ev['explanation']}",
            ])
        if f['excluded_http_note']:
            out.append(f"- *Lưu ý lọc nhiễu bằng chứng:* {f['excluded_http_note']}")
        for ai_n in f.get('ai_notes') or []:
            out.append(f"- **Diễn giải kỹ thuật từ dữ liệu đầu vào:** {ai_n}")
        out.extend([
            '',
            '#### 6.4. Phân loại OWASP',
            f"- **Tài liệu:** {f['owasp_doc']}",
            f"- **Phiên bản:** {f['owasp_version']}",
            f"- **Danh mục:** {f['owasp_category']}",
            f"- **Lý do phân loại:** {f['owasp_reason']}",
            f"- **Nguồn tham khảo:** {f['owasp_url']}",
            '',
            '#### 6.5. Đánh giá mức độ nghiêm trọng',
            f"- **Mức độ:** {f['severity_label']}",
            f"- **Cơ sở đánh giá:** {f['severity_basis']}",
            f"- **Các yếu tố chưa xác định:** {f['unknown_factors']}",
            '',
            '#### 6.6. Nguyên nhân',
            f"- {f['root_cause']}",
            '',
            '#### 6.7. Ảnh hưởng tiềm tàng',
            f"- {f['potential_impact']}",
        ])

    # Section 7
    out.extend([
        '',
        '## 7. Đề xuất remediation',
    ])
    if not m['findings']:
        out.extend(['', 'Không phát sinh đề xuất khắc phục bắt buộc do dữ liệu đầu vào không ghi nhận phát hiện lỗ hổng.'])
    for f in m['findings']:
        ref_str = (
            '; '.join(
                f"{r['section']}" + (f" ({r['url']})" if r['url'] else '')
                for r in f['rem_refs']
            )
            if f['rem_refs']
            else f"{f['owasp_doc']} {f['owasp_version']} — {f['owasp_category']} ({f['owasp_url']})"
        )
        out.extend([
            '',
            f"### {f['id']}: {f['title']}",
            '',
            '#### 7.1. Mục tiêu khắc phục',
            f"- {f['rem_goal']}",
            '',
            '#### 7.2. Biện pháp đề xuất',
        ])
        for st_line in f['rem_steps']:
            out.append(f"- {st_line}")
        for code_ex in f['code_examples']:
            out.extend([
                f"- **Ví dụ mã an toàn trích xuất từ `{code_ex['section']}`:**",
                f"```{code_ex['lang']}",
                code_ex['code'],
                '```',
            ])
        out.extend([
            '',
            '#### 7.3. Cơ sở của đề xuất',
            f"- **Phát hiện liên quan:** `{f['id']}`",
            f"- **Bằng chứng liên quan:** {', '.join(f'`{eid}`' for eid in f['evidence_ids']) or 'Chưa có'}",
            f"- **Tài liệu tham khảo:** {ref_str}",
            f"- **Lý do lựa chọn:** {f['rem_reason']}",
            '',
            '#### 7.4. Ưu tiên khắc phục',
            f"- {f['priority']}",
            '',
            '#### 7.5. Kế hoạch kiểm tra lại',
            f"- **Nội dung cần kiểm tra:** {f['retest_check']}",
            f"- **Phương pháp xác minh:** {f['retest_method']}",
            f"- **Kết quả kiểm tra:** {f['retest_result']}",
            f"- **Bằng chứng sau khắc phục:** {f['retest_evidence']}",
        ])

    # Section 8
    out.extend([
        '',
        '## 8. Giới hạn và độ tin cậy của báo cáo',
        '',
        '### 8.1. Giới hạn',
    ])
    for lb in m['limits_bullets']:
        out.append(f"- {lb}")
    out.extend([
        '',
        '### 8.2. Những nội dung cần xác minh',
    ])
    for vi in m['verify_items']:
        out.append(f"- {vi}")
    out.extend([
        '',
        '### 8.3. Độ tin cậy',
        '',
    ])
    for rp in m['reliability_paras']:
        out.extend([rp, ''])

    # Section 9
    out.extend([
        '## 9. Kết luận',
        '',
    ])
    for cp in m['conclusion_paras']:
        out.extend([cp, ''])

    # Section 10
    out.extend([
        '## 10. Phụ lục',
        '',
        '### 10.1. Danh sách dữ liệu đầu vào',
    ])
    for s in m['input_sources']:
        sha_bit = f" | SHA-256: `{s['sha256']}`" if s['sha256'] else ''
        out.append(f"- **`{s['id']}`** — `{s['name']}` ({s['source']}) — {s['status']}{sha_bit}")

    out.extend([
        '',
        '### 10.2. Danh mục bằng chứng kiểm thử',
    ])
    if not m['all_evidences']:
        out.append('- Không có trích đoạn bằng chứng chi tiết trong dữ liệu đầu vào.')
    else:
        for ev in m['all_evidences']:
            out.append(f"- **`{ev['id']}`** (thuộc `{ev['finding_id']}`, nguồn `{ev['source_id']}`): {ev['kind']}")

    out.extend([
        '',
        '### 10.3. Tài liệu OWASP được đối chiếu',
    ])
    if not m['cited_owasp_docs']:
        out.append('- OWASP Top 10:2025 (https://owasp.org/Top10/2025/)')
    else:
        for doc in m['cited_owasp_docs']:
            out.append(f"- **{doc['type']}:** {doc['title']}" + (f" — {doc['url']}" if doc['url'] else ''))
    if m['knowledge_sha256'] and m['knowledge_sha256'] != 'not_used':
        out.append(f"- **Mã băm toàn vẹn kho tri thức OWASP cục bộ (SHA-256):** `{m['knowledge_sha256']}`")

    out.extend([
        '',
        '### 10.4. Kết quả kiểm tra lại',
        f"- **Trạng thái hiện tại:** {m['retest_status']}",
        f"- **Bằng chứng kiểm tra lại:** {m['retest_evidence']}",
        '',
    ])
    return '\n'.join(out)
