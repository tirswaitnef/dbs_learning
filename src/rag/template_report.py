"""Render an existing report.json into the 7-section pentest report template.

No AI calls and no invented values. Every field is tagged with where it came from:
  [Đầu vào]        copied from the scanner file
  [Quy tắc]        fixed rule/template text produced by code
  [AI đã rà soát]  Gemini prose that passed citation + review checks
  [OWASP]          verbatim OWASP Cheat Sheet excerpt (AI only chose which one)
Fields the input does not contain are printed as "Không có trong đầu vào".
"""
import html
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

IN, RULE, AI, OWASP = '[Đầu vào]', '[Quy tắc]', '[AI đã rà soát]', '[OWASP]'
MISSING = 'Không có trong đầu vào'
ORDER = ['critical', 'high', 'medium', 'low', 'informational', 'info', 'unknown']
CHECKS = [
    'Phạm vi OWASP Top 10:2025 do code tra bảng CWE chính xác, không do AI quyết định.',
    'Không có bằng chứng đầu vào thì không gắn hướng dẫn khắc phục.',
    'Mức độ giữ nguyên như scanner cung cấp; không tự nâng/hạ, không tự tính CVSS.',
    'AI chỉ chọn ID đoạn OWASP; văn bản khắc phục là trích nguyên văn, không do AI viết.',
    'Diễn giải AI phải có trích dẫn nguyên văn từ đầu vào; sai nguồn/cấu trúc thì bị loại.',
    'Một lượt AI khác rà soát: có căn cứ, không có khuyến nghị, không khẳng định quá mức.',
    'Mọi kiểm tra trên không bảo đảm đúng ngữ nghĩa; báo cáo cần người có chuyên môn xác minh.',
]


VI_CHARS = set('àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ')
VI_LOWER = ''.join(sorted(VI_CHARS))
VI_CHARS |= {c.upper() for c in VI_CHARS}
VI_UPPER = ''.join(sorted(c for c in VI_CHARS if c.isupper()))
UPPER_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ' + VI_UPPER)


def readable_vi(text):
    """Cheap render-time guard against garbled/unaccented AI prose. It cannot catch
    wrong-but-valid words, so it never proves the text is correct."""
    import unicodedata
    for ch in text:
        if ch.isascii() or ch in VI_CHARS:
            continue
        if unicodedata.category(ch)[0] in 'PSNZ':
            continue
        return False
    words = re.findall(r'[^\W\d_]+', text)
    if any(any(c in VI_CHARS for c in w) and any(c in UPPER_CHARS for c in w[1:]) for w in words):
        return False
    if len(words) >= 8 and sum(any(c in VI_CHARS for c in w) for w in words) / len(words) < 0.15:
        return False
    return True


def severity_rank(value):
    value = str(value).lower()
    return ORDER.index(value) if value in ORDER else len(ORDER)


def render_template_pdf(report, path, *, client='[Chưa cung cấp]', tester='[Chưa cung cấp]',
                        application='[Chưa cung cấp]', classification='CONFIDENTIAL'):
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, CondPageBreak
    from .analysis import redact
    from .report_builder import guidance_reason, sample_notice
    from .top10 import cwe_label, enforce

    enforce(report)
    fonts = Path(__file__).parent / 'fonts'
    for name, filename in [('RagText', 'DejaVuSans.ttf'), ('RagBold', 'DejaVuSans-Bold.ttf')]:
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(fonts / filename)))
    pdfmetrics.registerFontFamily('RagText', normal='RagText', bold='RagBold', italic='RagText', boldItalic='RagBold')
    ink, muted, line = colors.HexColor('#1f2d3d'), colors.HexColor('#67768b'), colors.HexColor('#dce3ec')
    body = ParagraphStyle('b', fontName='RagText', fontSize=9, leading=14, spaceAfter=5, textColor=ink, splitLongWords=True)
    h1 = ParagraphStyle('h1', parent=body, fontName='RagBold', fontSize=15, leading=21, spaceBefore=14, spaceAfter=8, keepWithNext=True)
    h2 = ParagraphStyle('h2', parent=body, fontName='RagBold', fontSize=11.5, leading=17, spaceBefore=12, spaceAfter=6, keepWithNext=True)
    h3 = ParagraphStyle('h3', parent=body, fontName='RagBold', fontSize=9.5, spaceBefore=6, spaceAfter=3, keepWithNext=True)
    cover = ParagraphStyle('c', parent=body, fontName='RagBold', fontSize=26, leading=34, spaceAfter=10)
    small = ParagraphStyle('s', parent=body, fontSize=7.5, leading=11, textColor=muted)
    code = ParagraphStyle('code', parent=body, fontSize=7.5, leading=10.5, backColor=colors.HexColor('#f3f6fa'), borderPadding=5, spaceAfter=8)
    notice = ParagraphStyle('n', parent=body, fontName='RagBold', backColor=colors.HexColor('#fff2dc'), borderPadding=8, spaceAfter=14)

    def safe(value):
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value))
        return html.escape(text, quote=True).replace('\n', '<br/>').replace('\r', '')

    def tag(label):
        return f' <font size="7" color="#67768b">{label}</font>'

    def ai_claims(narrative, *sections):
        """Reviewed AI claims that also pass readable_vi -> (texts, number_hidden)."""
        texts, hidden = [], 0
        if (narrative or {}).get('status') == 'ai_reviewed':
            for section in sections:
                for claim in narrative['claims'].get(section, []):
                    if readable_vi(claim['text_vi']):
                        texts.append(claim['text_vi'])
                    else:
                        hidden += 1
        return texts, hidden

    def hidden_note(count):
        if count:
            P(f'Đã ẩn {count} ý AI do lỗi ký tự/chính tả tiếng Việt.' + tag(RULE), small)

    story = []
    P = lambda text, style=body: story.append(Paragraph(text, style))
    rows = report['findings']
    notice_text = sample_notice(report)

    def table(data, widths, header=True, raw=False):
        # raw=True: cells are already-escaped markup built with safe()/tag().
        cells = [[Paragraph(str(c) if raw else safe(c), body) for c in r] for r in data]
        t = Table(cells, colWidths=widths, repeatRows=1 if header else 0)
        style = [('GRID', (0, 0), (-1, -1), 0.4, line), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                 ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6)]
        if header:
            style.append(('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#eef2f7')))
        t.setStyle(TableStyle(style))
        story.extend([t, Spacer(1, 8)])

    # ---- Cover and contents
    P('Báo cáo kiểm thử bảo mật ứng dụng web', cover)
    P('Đánh giá bảo mật ứng dụng web theo OWASP', h2)
    if notice_text:
        P(safe(notice_text), notice)
    generated = str(report.get('generated_at', ''))[:10] or MISSING
    for label, value in [('Khách hàng', client), ('Người thực hiện', tester), ('Ngày lập báo cáo', generated),
                         ('Phân loại', classification)]:
        P(f'<b>{safe(label)}:</b> {safe(value)}')
    P('Mục lục', h2)
    for item in ['1. Tóm tắt điều hành', '2. Phạm vi và phương pháp', '3. Tổng hợp theo nhóm OWASP',
                 '4. Chi tiết phát hiện', '5. Phân loại mức độ', '6. Khuyến nghị khắc phục', '7. Phụ lục']:
        P(safe(item))
    story.append(PageBreak())

    # ---- 1. Executive summary
    by_sev = Counter(str(r['severity']).lower() for r in rows)
    vulns = [r for r in rows if r.get('kind') != 'observation']
    top = min((r['severity'] for r in vulns), key=severity_rank, default=None)
    cats = {c['id'] for r in rows for c in r['owasp_top10']['categories']}
    P('1. Tóm tắt điều hành', h1)
    P(safe(f"Đầu vào gồm {len(rows)} bản ghi ({len(vulns)} cảnh báo, {len(rows) - len(vulns)} quan sát) "
           f"thuộc {len(cats)} nhóm OWASP Top 10:2025 có ánh xạ CWE trực tiếp.") + tag(RULE))
    P(safe('Mức độ cao nhất theo đầu vào: ' + (str(top) if top else 'không có cảnh báo') +
           '. Đây không phải đánh giá tổng thể độ an toàn của ứng dụng.') + tag(RULE))
    P(safe('Phân bố mức độ do công cụ cung cấp: ' + ', '.join(f'{k}: {v}' for k, v in sorted(by_sev.items(), key=lambda i: severity_rank(i[0])))) + tag(IN))
    summary = report.get('ai_summary') or {}
    texts, hidden = ai_claims(summary, 'observations', 'limitations')
    for text in texts:
        P(safe(text) + tag(AI))
    hidden_note(hidden)
    if not texts and not hidden:
        P(safe('Không có tổng quan AI: ' + str(summary.get('reason', 'chưa được yêu cầu.'))) + tag(RULE))

    # ---- 2. Scope and methodology
    hosts = sorted({f"{u.scheme}://{u.netloc}" for u in (urlsplit(str(r['location'])) for r in rows) if u.scheme and u.netloc})
    tools = sorted({str(r.get('tool', '')) for r in rows if r.get('tool')})
    P('2. Phạm vi và phương pháp', h1)
    for label, value, source in [('URL mục tiêu (suy ra từ vị trí các phát hiện)', ', '.join(hosts) or MISSING, IN),
                                 ('Vai trò đã kiểm thử', MISSING, RULE), ('Vùng loại trừ', MISSING, RULE),
                                 ('Công cụ tạo đầu vào', ', '.join(tools) or MISSING, IN),
                                 ('Ứng dụng', application, RULE)]:
        P(f'<b>{safe(label)}:</b> {safe(value)}' + tag(source))
    P('Logic kiểm soát áp dụng khi tạo báo cáo', h3)
    for item in CHECKS:
        P('- ' + safe(item))

    # ---- 3. Summary by category
    P('3. Tổng hợp theo nhóm OWASP', h1)
    groups = {}
    for r in rows:
        keys = [c['id'] + ' - ' + c['title'] for c in r['owasp_top10']['categories']]
        if r.get('kind') == 'observation':
            keys = ['Quan sát dịch vụ (không phải lỗ hổng)']
        elif not keys:
            keys = ['Chưa phân loại / ngoài ánh xạ Top 10:2025']
        for key in keys:
            groups.setdefault(key, []).append(r)
    data = [['Nhóm OWASP', 'Số phát hiện', 'Mức độ cao nhất (đầu vào)']]
    for key in sorted(groups):
        data.append([key, str(len(groups[key])), min((r['severity'] for r in groups[key]), key=severity_rank)])
    table(data, [250, 80, 185])

    # ---- 4. Detailed findings
    story.append(CondPageBreak(300))
    P('4. Chi tiết phát hiện', h1)
    for index, r in enumerate(rows, 1):
        details = r.get('details') or {}
        story.append(CondPageBreak(260))
        P(f"W-{index:03d} ({safe(r['id'])}): {safe(r['title'])}", h2)
        cwe = cwe_label(r, MISSING)
        cwe_tag = RULE if (details.get('cwe_mapping') and cwe != MISSING) else IN
        categories = ', '.join(c['id'] + ' - ' + c['title'] for c in r['owasp_top10']['categories']) or r['owasp_top10']['reason']
        cvss = details.get('cvss_score')
        data = [['Mức độ', safe(r['severity']) + tag(IN)],
                ['CVSS 3.1', (safe(cvss) + tag(IN)) if cvss else MISSING + ' (dự án không tự tính CVSS)'],
                ['Nhóm OWASP', safe(categories) + tag(RULE)],
                ['CWE', safe(cwe) + tag(cwe_tag)],
                ['URL bị ảnh hưởng', safe(r['location']) + (f" (tham số: {safe(details['parameter'])})" if details.get('parameter') else '') + tag(IN)],
                ['Phương thức HTTP', (safe(details['method']) + tag(IN)) if details.get('method') else MISSING]]
        table(data, [120, 395], header=False, raw=True)
        analysis = r.get('ai_analysis') or {}
        P('Mô tả', h3)
        texts, hidden = ai_claims(analysis, 'observations')
        for text in texts:
            P(safe(text) + tag(AI))
        hidden_note(hidden)
        if not texts:
            P(safe(r.get('analysis_vi', MISSING)) + tag(RULE))
        if details.get('description'):
            P('Mô tả từ công cụ: ' + safe(redact(details['description'])[:1200]) + tag(IN))
        messages = details.get('http_messages') or []
        P('Yêu cầu (Request)', h3)
        if messages:
            for m in messages[:6]:
                P(safe(redact(m.get('request', ''))[:2400]), code)
        else:
            P(MISSING + '.')
        P('Phản hồi (Response)', h3)
        if messages:
            for m in messages[:6]:
                P(safe(redact(m.get('response', ''))[:2400]), code)
        else:
            P(MISSING + '.')
        if r.get('evidence'):
            P('Bằng chứng đầu vào' + tag(IN), h3)
            for item in r['evidence']:
                P(safe(redact(item)[:2400]), code)
        else:
            P('Chưa có bằng chứng đính kèm; chưa đủ căn cứ để xác nhận phát hiện.' + tag(RULE))
        P('Tác động', h3)
        impacts, hidden = ai_claims(analysis, 'potential_impacts')
        for text in impacts:
            P(safe(text) + tag(AI))
        hidden_note(hidden)
        if not impacts:
            P('Không đủ căn cứ trong đầu vào để nêu tác động; không suy đoán.' + tag(RULE))
        P('Khắc phục', h3)
        if not r.get('guidance'):
            P(safe(guidance_reason(r)) + tag(RULE))
        for g in r.get('guidance', []):
            P(safe(g['guidance_vi']) + tag(OWASP))
            P(safe(g['title'] + ' | ' + g['section']) + ' - ' + safe(g['url']), small)

    # ---- 5. Risk ratings (as provided)
    P('5. Phân loại mức độ', h1)
    P('Dự án giữ nguyên mức độ do công cụ cung cấp và không tự chấm lại. Số lượng theo mức độ đầu vào:' + tag(IN))
    table([['Mức độ', 'Số bản ghi']] + [[k, str(v)] for k, v in sorted(by_sev.items(), key=lambda i: severity_rank(i[0]))], [250, 120])

    # ---- 6. Remediation recommendations (only OWASP excerpts actually selected)
    P('6. Khuyến nghị khắc phục', h1)
    seen, n = set(), 0
    for r in rows:
        for g in r.get('guidance', []):
            key = (g.get('source', g['title']), g.get('start', g['id']))
            if key in seen:
                continue
            seen.add(key)
            n += 1
            P(f"{n}. <b>{safe(g['title'])}</b> ({safe(r['id'])}): {safe(g['guidance_vi'][:700])}" + tag(OWASP))
    if not n:
        P('Chưa có hướng dẫn nào được chọn từ nguồn OWASP cho đầu vào này.' + tag(RULE))
    P('Cần người có chuyên môn kiểm tra tính phù hợp với công nghệ thực tế trước khi áp dụng.', small)

    # ---- 7. Appendix
    P('7. Phụ lục', h1)
    for label, value in [('A. SHA-256 tệp đầu vào', report.get('scan_sha256')),
                         ('B. SHA-256 kho hướng dẫn OWASP', report.get('knowledge_sha256')),
                         ('C. Model AI', report.get('model') or 'không dùng'),
                         ('D. Thời điểm UTC', report.get('generated_at')),
                         ('E. Số lượt gọi AI', report.get('generation_calls', 0))]:
        P(f'<b>{safe(label)}:</b> {safe(value)}', small)
    P('Báo cáo chưa được xác minh độc lập. ' + safe(' '.join(report.get('limitations', [])[-1:])), small)

    def footer(canvas, doc):
        canvas.setStrokeColor(line)
        canvas.line(40, 38, 555, 38)
        canvas.setFont('RagText', 8)
        canvas.setFillColor(muted)
        canvas.drawString(40, 25, classification + ' | ' + ('Có dữ liệu giả lập' if notice_text else 'Chưa xác minh độc lập'))
        canvas.drawRightString(555, 25, 'Trang ' + str(doc.page))

    path = Path(path)
    SimpleDocTemplate(str(path), rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=52,
                      title='Báo cáo kiểm thử bảo mật ứng dụng web', author='OWASP Report RAG').build(story, onFirstPage=footer, onLaterPages=footer)
    return path
