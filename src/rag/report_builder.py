import html
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .db_scope import attach_db_scope
from .schemas import card_digest
from .top10 import classify, enforce, finding_cwes
from .validators import validate_plan


def build_report(findings, candidates, cards, plan, *, mode, scan_sha256, model=""):
    validate_plan(plan, findings, candidates)
    selections = {item["finding_id"]: item["guidance_ids"] for item in plan["items"]}
    card_map = {c.id: c for c in cards}
    rows = []
    for finding in findings:
        ids = selections[finding.id]
        # Defense in depth if this function is used outside the standard pipeline.
        for id_ in ids:
            card = card_map[id_]
            if not card.approved or card.cwe not in finding_cwes(finding):
                raise ValueError("Guidance not approved or CWE mismatch")
        status = ("missing_evidence" if not finding.evidence else
                  "guidance_available" if ids else "no_supported_guidance")
        rows.append({**asdict(finding), "owasp_top10": classify(finding), "status": status,
                     "evidence_assessment": "Presence only; not independently verified",
                     "retrieval": candidates[finding.id],
                     "guidance": [asdict(card_map[id_]) for id_ in ids]})
    for row in rows:
        row["guidance_reason"] = "" if row["guidance"] else guidance_reason(row)
    return attach_db_scope(enforce({"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode, "model": model, "scan_sha256": scan_sha256,
            "knowledge_sha256": card_digest(cards), "findings": rows,
            "limitations": [
                "Kết quả do công cụ/đầu vào cung cấp; chưa xác minh độc lập lỗ hổng.",
                "Kiểm tra bằng chứng hiện chỉ xét có/không, chưa xác định true/false positive.",
                "Gợi ý là hướng dẫn có điều kiện, không phải bản vá đã kiểm chứng.",
                "Không truy cập source code/database, không chạy quét hoặc retest."]}))



def sample_notice(report):
    # Explicit labels in input, not a guess based on URLs or model mode.
    rows = report.get("findings", [])
    labels = [any(marker in str(f.get("tool", "")).lower()
                  for marker in ("synthetic", "demo only")) for f in rows]
    if labels and all(labels):
        return "BÁO CÁO TỪ KIỂM THỬ GIẢ LẬP - theo nhãn nguồn đầu vào."
    if any(labels):
        return "BÁO CÁO CÓ CHỨA KIỂM THỬ GIẢ LẬP - theo nhãn nguồn đầu vào."
    return ""


def guidance_reason(finding):
    scope = classify(finding)
    if scope["status"] != "in_scope":
        return scope["reason"]
    if finding.get("kind") == "observation":
        return "Đây là quan sát dịch vụ; chưa được xác định là lỗ hổng để gắn hướng dẫn khắc phục."
    if not finding.get("evidence"):
        return "Thiếu bằng chứng kiểm thử đính kèm; chưa chọn hướng dẫn khắc phục."
    if not finding_cwes(finding):
        return "Chưa xác định được CWE duy nhất từ kiểm thử; chưa chọn hướng dẫn khắc phục."
    if finding.get("generation_status") == "api_error":
        return "Không chọn được hướng dẫn do lỗi gọi model; dữ liệu kiểm thử vẫn được giữ."
    if finding.get("generation_status") == "rejected_output":
        return "Kết quả AI bị từ chối vì không vượt qua kiểm tra ID nguồn/cấu trúc; chưa hiển thị hướng dẫn."
    if not finding.get("retrieval"):
        return "Chưa truy xuất được hướng dẫn phù hợp trong kho hiện có và các bộ lọc hiện tại. Không có nghĩa OWASP không có hướng dẫn."
    return "Có hướng dẫn được truy xuất nhưng chưa được chọn trong kế hoạch báo cáo; cần kiểm tra tính phù hợp."

def md_text(value):
    value = html.escape(str(value), quote=False).replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value)


def render_markdown(report):
    from .report_view import (
        MISSING, SEVERITIES, category_rows, cwe_text, defense_layer_label,
        evidence_profile, extract_scan_context, fallback_description,
        overview, severity_counts, technical_fields,
    )
    from .analysis import narrative_lines
    enforce(report)
    scan_ctx=report.get('scan_context') or extract_scan_context(report)
    lines=['# Báo cáo phân tích kiểm thử bảo mật','',md_text(sample_notice(report)),
           'Chế độ: '+md_text(report['mode']), 'Thời điểm UTC: '+md_text(report['generated_at'])]
    def add(text):lines.extend(['',md_text(text)])
    for key,value in report.get('report_metadata',{}).items():add(key+': '+value)
    if scan_ctx.get('application_hint') and not (report.get('report_metadata') or {}).get('application'):
        add('Ứng dụng / môi trường nhận diện: '+scan_ctx['application_hint'])
    if scan_ctx.get('scan_window') and not (report.get('report_metadata') or {}).get('assessment_period'):
        add('Thời gian kiểm thử (từ log): '+scan_ctx['scan_window'])
    lines+=['','## 1. Tổng quan điều hành']
    for line in overview(report):add(line)
    if scan_ctx.get('lab'):add('Ngữ cảnh mục tiêu: '+scan_ctx['lab']['note_vi'])
    if report.get('ai_summary'):
        lines+=['','### Tổng quan AI']
        for line in narrative_lines(report['ai_summary']):add(line)
    lines+=['','## 2. Phạm vi và phương pháp']
    add('Phân tích kiểm thử được cung cấp; không quét lại hoặc xác minh độc lập. Ánh xạ CWE với OWASP Top 10:2025.')
    for t_line in scan_ctx.get('telemetry_lines',[]):add('Thông số phiên quét: '+t_line)
    for eol in scan_ctx.get('eol_notes',[]):add('Cảnh báo vòng đời nền tảng: '+eol)
    for gap in scan_ctx.get('repro_gaps',[]):add('Giới hạn tái hiện: '+gap)
    from .db_scope import scope_lines
    db_scope=report.get('db_scope') or {}
    for line in (db_scope.get('lines') or scope_lines(report['findings'])):add(line)
    for row in report['findings']:add(row['tool']+' — '+row['location'])
    probe=report.get('prose_check') or {}
    if probe:
        from .report_variety import prose_line
        add(prose_line(probe))
    lines+=['','## 3. Tổng hợp phát hiện theo OWASP']
    for row in category_rows(report):add(' | '.join(row))
    lines+=['','## 4. Chi tiết phát hiện']
    for f in report['findings']:
        lines+=['','### '+md_text(f['id']+' — '+f['title'])]
        for key in ['severity','cwe','location','tool','kind','source_ref']:add(key+': '+(cwe_text(f) if key=='cwe' else str(f.get(key,MISSING))))
        prof=evidence_profile(f)
        add('Đánh giá chứng cứ: '+prof['label_vi']+' — '+prof['note_vi'])
        if f.get('db_frame'):
            from .db_scope import frame_line
            add('Phạm vi CSDL: '+frame_line(f['db_frame']))
        t=technical_fields(f)
        for key in ['method','parameter','cvss','cvss_vector']:add(key+': '+str(t[key]))
        add(f['owasp_top10']['reason']);add(t['description'] or fallback_description(f))
        if f.get('ai_analysis'):
            lines+=['','#### Diễn giải AI']
            for line in narrative_lines(f['ai_analysis']):add(line)
        lines+=['','#### Bằng chứng đầu vào']
        for i,e in enumerate(f.get('evidence',[]),1):add(f'E{i}: '+e)
        for req in t['requests']:add('HTTP request: '+req)
        add('Khắc phục: xem mục 6.' if f['guidance'] else guidance_reason(f))
    lines+=['','## 5. Xếp hạng rủi ro']
    counts=severity_counts(report)
    for key,label in SEVERITIES:add(label+': '+str(counts[key]))
    add('Giữ mức độ từ đầu vào; không tự tính CVSS hoặc xác nhận khả năng khai thác.')
    lines+=['','## 6. Hướng dẫn khắc phục']
    for f in report['findings']:
        if not f['guidance']:continue
        lines+=['','### '+md_text(f['id']+' — '+f['title'])]
        for card in f['guidance']:
            add(defense_layer_label(card) if card.get('origin')=='official-corpus-extractive' else 'Thẻ cũ / demo; không coi là trích nguyên văn OWASP')
            for key in ['guidance_vi','applicability_vi','title','section','source_excerpt']:add(str(card.get(key,MISSING)))
            from urllib.parse import urlsplit
            url=card.get('url','')
            if urlsplit(url).scheme=='https' and urlsplit(url).hostname=='cheatsheetseries.owasp.org' and not any(c in url for c in '<>\n\r'):
                lines+=['','<'+url+'>']
            else:add(url)
    for eol in scan_ctx.get('eol_notes',[]):
        add('Lưu ý hạ tầng EOL: '+eol)
    lines+=['','## 7. Phụ lục và dấu vết xử lý']
    for line in report.get('limitations',[]):add(line)
    for key in ['input_filename','scan_sha256','knowledge_sha256','model']:add(key+': '+str(report.get(key) or MISSING))
    return '\n'.join(lines)+'\n'


def write_report(report, output):
    from .llm import format_ai_trace_text
    from .pentest_polish import prepare_pentest_view, render_pentest_markdown
    enforce(report)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    view = prepare_pentest_view(report)
    sanitized_report = view['work']
    sanitized_report['privacy_audit'] = view['privacy_audit']
    trace_obj = sanitized_report.get('ai_trace')
    if trace_obj is None:
        trace_obj = {
            'mode': sanitized_report.get('mode', 'demo'),
            'model': sanitized_report.get('model') or 'none',
            'from_cache': False,
            'call_count': 0,
            'entries': [],
        }
        sanitized_report['ai_trace'] = trace_obj
    (output / "ai_trace.json").write_text(json.dumps(trace_obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "ai_trace.txt").write_text(format_ai_trace_text(trace_obj), encoding="utf-8")
    from .pdf_report import render_pdf
    pdf_path = output / "report.pdf"
    render_pdf(sanitized_report, pdf_path)
    json_path, md_path = output / "report.json", output / "report.md"
    pentest_md_path = output / "pentest_report.md"
    json_path.write_text(json.dumps(sanitized_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(sanitized_report), encoding="utf-8")
    pentest_md_path.write_text(render_pentest_markdown(sanitized_report), encoding="utf-8")
    return md_path, json_path, pdf_path
