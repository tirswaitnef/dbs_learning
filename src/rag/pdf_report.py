"""Client-ready 7-section Penetration Testing PDF Report (OWASP standard layout)."""
from __future__ import annotations

import html
import re
from pathlib import Path


def render_pdf(report, path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        BaseDocTemplate, CondPageBreak, Frame, PageBreak, PageTemplate,
        Paragraph, Spacer, Table, TableStyle,
    )
    from reportlab.platypus.tableofcontents import TableOfContents

    from .pentest_polish import SEVERITY_ORDER, prepare_pentest_view
    from .report_builder import sample_notice
    from .top10 import enforce

    enforce(report)
    view = prepare_pentest_view(report)
    work = view['work']
    scan_ctx = view['scan_ctx']
    entries = view['entries']
    meta = work.get('report_metadata') or {}

    fonts = Path(__file__).parent / 'fonts'
    for name, filename in [('RagText', 'DejaVuSans.ttf'), ('RagBold', 'DejaVuSans-Bold.ttf')]:
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(fonts / filename)))
    pdfmetrics.registerFontFamily('RagText', normal='RagText', bold='RagBold', italic='RagText', boldItalic='RagBold')

    navy = colors.HexColor('#16324f')
    slate = colors.HexColor('#4a6074')
    muted = colors.HexColor('#64748b')
    border_col = colors.HexColor('#d8e2ec')
    code_bg = colors.HexColor('#f4f7fa')
    accent_bg = colors.HexColor('#e8eff6')
    biz_bg = colors.HexColor('#fffaf2')
    biz_border = colors.HexColor('#c26a1b')

    width = A4[0] - 88
    body = ParagraphStyle('body', fontName='RagText', fontSize=9.2, leading=14, spaceAfter=6, textColor=navy, splitLongWords=True)
    bold_body = ParagraphStyle('bold_body', parent=body, fontName='RagBold', spaceAfter=4)
    cover_kicker = ParagraphStyle('cover_kicker', parent=body, fontName='RagBold', fontSize=9, leading=13, textColor=colors.HexColor('#2563eb'), spaceAfter=10)
    cover_title = ParagraphStyle('cover_title', parent=body, fontName='RagBold', fontSize=24, leading=32, spaceAfter=10, textColor=navy)
    cover_sub = ParagraphStyle('cover_sub', parent=body, fontSize=12, leading=17, textColor=slate, spaceAfter=24)
    heading = ParagraphStyle('section', parent=body, fontName='RagBold', fontSize=14.5, leading=20, spaceBefore=14, spaceAfter=8, keepWithNext=True)
    sub = ParagraphStyle('sub', parent=heading, fontSize=11, leading=15.5, spaceBefore=10, spaceAfter=5)
    label_h = ParagraphStyle('label_h', parent=body, fontName='RagBold', fontSize=9.3, leading=13, spaceBefore=6, spaceAfter=3, keepWithNext=True)
    small = ParagraphStyle('small', parent=body, fontSize=7.8, leading=11, spaceAfter=4, textColor=muted)
    code_style = ParagraphStyle('code', fontName='Courier', fontSize=7.6, leading=10.8, spaceAfter=6, textColor=navy, backColor=code_bg, borderPadding=6, splitLongWords=True)

    def safe(v):
        return html.escape(re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(v)), quote=True).replace('\n', '<br/>')

    story = []

    def add(v, style=body):
        story.append(Paragraph(safe(v), style))

    def block(v, mono=False):
        text = str(v or '')
        st = code_style if mono else body
        for start in range(0, len(text), 2200):
            add(text[start:start + 2200], st)

    def callout(header_text, body_text):
        cell = [
            Paragraph(safe(header_text), bold_body),
            Paragraph(safe(body_text), body),
        ]
        t = Table([[cell]], colWidths=[width], hAlign='LEFT')
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), biz_bg),
            ('LINEBEFORE', (0, 0), (0, -1), 3, biz_border),
            ('BOX', (0, 0), (-1, -1), 0.4, colors.HexColor('#f1dfc4')),
            ('LEFTPADDING', (0, 0), (-1, -1), 11),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.extend([t, Spacer(1, 8)])

    def section(n, label):
        story.append(CondPageBreak(120))
        p = Paragraph(safe(f'{n}. {label}'), heading)
        p.toc_label = f'{n}. {label}'
        story.append(p)

    def table(headers, rows, widths):
        data = [[Paragraph(safe(v), small if i == 0 else body) for v in row] for i, row in enumerate([headers] + rows)]
        t = Table(data, colWidths=widths, repeatRows=1, hAlign='LEFT')
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), accent_bg),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LINEBELOW', (0, 0), (-1, 0), 0.8, navy),
            ('LINEBELOW', (0, 1), (-1, -1), 0.35, border_col),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.extend([t, Spacer(1, 8)])

    def kv_table(pairs):
        data = [[Paragraph(safe(k), bold_body), Paragraph(safe(v), body)] for k, v in pairs]
        t = Table(data, colWidths=[width * 0.28, width * 0.72], hAlign='LEFT')
        t.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LINEBELOW', (0, 0), (-1, -1), 0.35, border_col),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5.5),
        ]))
        story.extend([t, Spacer(1, 8)])

    # Resolve clean Cover & Scope labels without internal developer notes
    lab_info = scan_ctx.get('lab') or {}
    app_name = (
        meta.get('application')
        or (f"{lab_info['name']} (Môi trường Kiểm thử)" if lab_info.get('name') else '')
        or 'Ứng dụng Web & Cơ sở dữ liệu Mục tiêu'
    )
    client_name = meta.get('client') or 'Đơn vị Chủ quản Hệ thống'
    prepared_by = meta.get('prepared_by') or 'Nhóm Kiểm thử Bảo mật'
    classification = meta.get('classification') or 'CONFIDENTIAL'
    gen_date = str(work.get('generated_at', ''))[:10] or 'Không xác định'
    raw_window = meta.get('assessment_period') or scan_ctx.get('scan_window') or gen_date
    clean_window = re.sub(r'\s*\(ghi trong[^)]*\)', '', str(raw_window)).strip()

    # -------------------- PAGE 1: COVER PAGE --------------------
    story.append(Spacer(1, 36))
    add('BÁO CÁO ĐÁNH GIÁ BẢO MẬT CHUYÊN SÂU', cover_kicker)
    add('BÁO CÁO KIỂM THỬ XÂM NHẬP\nỨNG DỤNG WEB & CƠ SỞ DỮ LIỆU', cover_title)
    add('Đánh giá Bảo mật theo Tiêu chuẩn OWASP Top 10 & OWASP Testing Guide', cover_sub)
    if sample_notice(work):
        add(sample_notice(work), bold_body)
    story.append(Spacer(1, 14))
    kv_table([
        ('Hệ thống mục tiêu', app_name),
        ('Đơn vị tiếp nhận (Prepared for)', client_name),
        ('Người thực hiện (Prepared by)', prepared_by),
        ('Ngày lập báo cáo (Date)', gen_date),
        ('Thời gian kiểm thử', clean_window),
        ('Phân loại bảo mật (Classification)', classification),
    ])
    story.append(Spacer(1, 18))
    add('Tài liệu Mật — Chỉ sử dụng cho mục đích rà soát, khắc phục lỗ hổng bảo mật trong phạm vi được ủy quyền.', small)

    # -------------------- PAGE 2: TABLE OF CONTENTS --------------------
    story.append(PageBreak())
    add('MỤC LỤC', heading)
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle('toc', parent=body, leading=19, spaceAfter=3)]
    story.extend([toc, Spacer(1, 16)])

    # -------------------- 1. EXECUTIVE SUMMARY --------------------
    section(1, 'Tóm tắt điều hành')
    target_urls = list(dict.fromkeys(e['url'] for e in entries)) or list(
        dict.fromkeys(str(r.get('location', '')).split(' (parameter=')[0] for r in work.get('findings', []))
    )
    primary_url = ', '.join(u for u in target_urls[:3] if u) or 'mục tiêu kiểm thử'
    owasp_group_count = len({e['owasp_label'] for e in entries})
    add(
        f"Đợt kiểm thử xâm nhập được thực hiện trên hệ thống {app_name} tại địa chỉ {primary_url} "
        f"trong khoảng thời gian {clean_window}, do {prepared_by} thực hiện cho {client_name}. "
        'Quy trình đánh giá tập trung vào kiểm soát dữ liệu đầu vào, an toàn truy vấn cơ sở dữ liệu, xác thực phiên làm việc '
        'và cấu hình máy chủ theo phương pháp luận OWASP Web Security Testing Guide (v4.2) và khung phân loại OWASP Top 10.'
    )
    add(
        f"Đánh giá mức độ rủi ro tổng thể: {view['overall_posture']}. "
        f"Đợt kiểm thử xác nhận tổng cộng {len(entries)} lỗ hổng bảo mật thuộc {owasp_group_count} nhóm danh mục OWASP.",
        bold_body,
    )
    callout('Tác động đối với hoạt động & nghiệp vụ (Tóm tắt phi kỹ thuật dành cho Quản lý)', view['business_summary'])
    for ai_line in view['exec_ai_lines'][:2]:
        add(ai_line)

    # -------------------- 2. SCOPE AND METHODOLOGY --------------------
    section(2, 'Phạm vi và Phương pháp kiểm thử')
    tools_used = sorted({str(r.get('tool', '')) for r in work.get('findings', []) if r.get('tool')})
    scope_exclude = (
        meta.get('excluded_areas')
        or scan_ctx.get('scope_rule')
        or 'Không trích xuất hàng loạt dữ liệu nhạy cảm (--dump); không thực hiện tấn công từ chối dịch vụ (DoS).'
    )
    auth_tested = meta.get('roles') or scan_ctx.get('auth_context') or 'Kiểm thử từ phía mạng ngoài / Phiên người dùng tiêu chuẩn'
    stack_bits = []
    for r in work.get('findings', []):
        d = r.get('details') or {}
        tel = d.get('scan_telemetry') or {}
        if tel.get('web_tech') and tel['web_tech'] not in stack_bits:
            stack_bits.append(tel['web_tech'])
        if tel.get('os_banner') and tel['os_banner'] not in stack_bits:
            stack_bits.append(tel['os_banner'])
        if d.get('dbms') and d['dbms'] not in stack_bits:
            stack_bits.append(d['dbms'])
    scope_rows = [
        ('URL / Mục tiêu trong phạm vi', '\n'.join(target_urls) or 'Không xác định'),
        ('Vai trò & Ngữ cảnh xác thực', auth_tested),
        ('Giới hạn & Vùng loại trừ', scope_exclude),
        ('Hạng mục kiểm thử theo OWASP', 'Injection (SQL Injection, XSS), Quản lý Phiên & Xác thực, Cấu hình Bảo mật & Thành phần Máy chủ'),
        ('Công cụ sử dụng', ', '.join(tools_used) if tools_used else 'Bộ công cụ kiểm thử bảo mật tiêu chuẩn'),
    ]
    if stack_bits:
        scope_rows.append(('Nền tảng kỹ thuật ghi nhận', ' | '.join(stack_bits)))
    if scan_ctx.get('db_identity'):
        scope_rows.append(('Ngữ cảnh tài khoản CSDL', scan_ctx['db_identity']))
    kv_table(scope_rows)
    add(
        'Phương pháp kiểm thử: Kết hợp dò quét có kiểm soát, phân tích phản hồi giao thức HTTP thực tế và rà soát đối chiếu thủ công '
        'để loại bỏ cảnh báo nhiễu (false positive) trước khi xếp hạng CVSS v3.1 và xây dựng khuyến nghị khắc phục.',
        small,
    )

    # -------------------- 3. FINDINGS SUMMARY BY OWASP CATEGORY --------------------
    section(3, 'Tổng hợp lỗ hổng theo Danh mục OWASP')
    grouped: dict[str, list[dict]] = {}
    for e in entries:
        grouped.setdefault(e['owasp_label'], []).append(e)
    cat_table_rows = []
    for cat_name, items in grouped.items():
        best = min(items, key=lambda x: SEVERITY_ORDER.index(x['severity_key']) if x['severity_key'] in SEVERITY_ORDER else 99)
        cat_table_rows.append([cat_name, str(len(items)), best['severity_label']])
    table(
        ['Danh mục OWASP', 'Số lượng lỗ hổng', 'Mức độ nghiêm trọng cao nhất'],
        cat_table_rows or [['Không ghi nhận lỗ hổng xác nhận trong phạm vi quét', '0', 'Không áp dụng']],
        [width * 0.56, width * 0.16, width * 0.28],
    )

    # -------------------- 4. DETAILED FINDINGS --------------------
    section(4, 'Chi tiết lỗ hổng bảo mật')
    if not entries:
        add('Không có lỗ hổng bảo mật đã xác nhận nào được ghi nhận trong đợt kiểm thử này.')
    for e in entries:
        story.append(CondPageBreak(180))
        add(f"{e['pentest_id']}: {e['title']}", sub)
        cvss_line = (
            f"{e['cvss_score']} — {e['cvss_vector']}" if e['cvss_score'] and e['cvss_vector']
            else (e['cvss_score'] if e['cvss_score'] else 'Đánh giá theo mức độ nghiêm trọng của công cụ kiểm thử')
        )
        url_with_param = (
            f"{e['url']} (Tham số: {e['parameter']})"
            if e['parameter'] != 'Không áp dụng' else e['url']
        )
        kv_table([
            ('Mức độ nghiêm trọng (Severity)', e['severity_label']),
            ('Điểm CVSS v3.1', cvss_line),
            ('Danh mục OWASP', e['owasp_label']),
            ('Mã điểm yếu (CWE)', e['cwe_label']),
            ('URL & Tham số ảnh hưởng', url_with_param),
            ('Phương thức HTTP', e['method']),
        ])

        add('Mô tả kỹ thuật (Description)', label_h)
        block(e['description'])

        add('Tác động kinh doanh & vận hành (Impact — Ngôn ngữ phi kỹ thuật)', label_h)
        block(e['business_impact'])

        exchanges = e['http_exchanges']
        if exchanges:
            # Show concise primary proof pair cleanly right inside Section 4 (Error/UNION preferred first for immediate visual proof)
            ranked = sorted(
                exchanges,
                key=lambda m: 0 if re.search(r'UNION|EXTRACTVALUE|XPATH|<script|<svg', str(m.get('request', '')) + str(m.get('response', '')), re.I) else 1,
            )
            primary_ex = ranked[0]
            add('Yêu cầu HTTP minh chứng (Request)', label_h)
            block(primary_ex.get('request', ''), mono=True)
            add('Phản hồi HTTP minh chứng (Response)', label_h)
            block(primary_ex.get('response', ''), mono=True)
        elif e['raw_requests']:
            add('Yêu cầu HTTP minh chứng (Request)', label_h)
            block(e['raw_requests'][0], mono=True)
        elif e['evidence']:
            add('Bằng chứng kỹ thuật ghi nhận', label_h)
            block(e['evidence'][0], mono=True)

        rem = e['remediation']
        add('Hướng khắc phục cụ thể (Remediation)', label_h)
        for b_item in rem['bullets']:
            add('• ' + b_item)
        if rem.get('code'):
            add(rem['code_label'] + ':', small)
            block(rem['code'], mono=True)
        if rem.get('urls'):
            add('Tài liệu tham chiếu OWASP: ' + ' | '.join(rem['urls'][:2]), small)

    # -------------------- 5. RISK RATINGS --------------------
    section(5, 'Thang đánh giá mức độ rủi ro')
    tier_defs = [
        ('Nghiêm trọng — Critical (9.0 – 10.0)', 'Thực thi mã từ xa (RCE), vượt xác thực hoàn toàn, tiêm nhiễm SQL làm lộ lọt diện rộng dữ liệu trọng yếu không cần đăng nhập.', sum(e['severity_key'] == 'critical' for e in entries)),
        ('Cao — High (7.0 – 8.9)', 'SQL Injection trong phiên xác thực, leo thang đặc quyền, truy cập CSDL trái phép, Stored XSS hoặc IDOR làm lộ dữ liệu người dùng.', sum(e['severity_key'] == 'high' for e in entries)),
        ('Trung bình — Medium (4.0 – 6.9)', 'Reflected XSS, CSRF trên chức năng quan trọng, rò rỉ thông tin cấu hình nội bộ hoặc quản lý phiên chưa chặt chẽ.', sum(e['severity_key'] == 'medium' for e in entries)),
        ('Thấp — Low (0.1 – 3.9)', 'Thiếu HTTP Security Headers, thông báo lỗi chi tiết, thiếu cờ bảo vệ phụ trên cookie hoặc thành phần phần mềm cũ.', sum(e['severity_key'] == 'low' for e in entries)),
    ]
    table(
        ['Mức độ rủi ro (CVSS v3.1)', 'Ý nghĩa đánh giá chuẩn Pentest', 'Số lỗ hổng'],
        [[t[0], t[1], str(t[2])] for t in tier_defs],
        [width * 0.28, width * 0.58, width * 0.14],
    )
    has_input_cvss = any(bool(e['cvss_score']) for e in entries)
    if has_input_cvss:
        add(
            'Lưu ý chấm điểm: Điểm số và chuỗi vector CVSS v3.1 tại Mục 4 được giữ nguyên trực tiếp từ dữ liệu kiểm thử đầu vào kèm ngữ cảnh xác thực thực tế của phiên kiểm thử.',
            small,
        )
    else:
        add(
            'Lưu ý chấm điểm: Mức độ nghiêm trọng được giữ nguyên theo kết quả đánh giá của công cụ kiểm thử; trong chuẩn CVSS v3.1, điểm số cụ thể phụ thuộc vào quyền truy cập cần thiết (PR:N hoặc PR:L).',
            small,
        )

    # -------------------- 6. REMEDIATION RECOMMENDATIONS --------------------
    section(6, 'Khuyến nghị khắc phục tổng thể')
    recs = view['global_recommendations']
    if recs:
        for idx_r, rec in enumerate(recs, 1):
            add(f"{idx_r}. [{rec['priority']}] {rec['title']}", bold_body)
            add(rec['body'])
            if rec.get('ref'):
                add('Tham chiếu OWASP: ' + rec['ref'], small)
    else:
        add('Duy trì kiểm thử bảo mật định kỳ và áp dụng danh mục kiểm tra bảo mật ứng dụng theo OWASP ASVS.')

    # -------------------- 7. APPENDIX --------------------
    section(7, 'Phụ lục bằng chứng kỹ thuật')
    any_http = [ex for e in entries for ex in e['http_exchanges']]
    if any_http:
        add('Phụ lục A — Bằng chứng Giao dịch HTTP Request / Response chi tiết', sub)
        for e in entries:
            for idx_h, ex in enumerate(e['http_exchanges'][:4], 1):
                add(f"{e['pentest_id']} — Gói tin minh chứng #{idx_h} ({ex.get('id', '')}):", bold_body)
                if ex.get('request'):
                    block(ex['request'], mono=True)
                if ex.get('response'):
                    block(ex['response'], mono=True)

    add('Phụ lục B — Kết quả Trích xuất Công cụ Kiểm thử & Ghi nhận Hạ tầng', sub)
    for e in entries:
        if e['evidence']:
            add(f"Trích xuất kết quả cho {e['pentest_id']} ({e['title']}):", bold_body)
            block(e['evidence'][0], mono=True)
    if view['eol_clean']:
        add('Ghi nhận vòng đời phần mềm nền tảng máy chủ:', bold_body)
        for note in view['eol_clean']:
            add('• ' + note)

    while story and isinstance(story[-1], Spacer):
        story.pop()
    end_style = ParagraphStyle('end_mark', parent=small, alignment=1, spaceBefore=10, spaceAfter=0)
    story.append(Paragraph('— Hết báo cáo —', end_style))

    def footer(canvas, doc):
        canvas.setStrokeColor(border_col)
        canvas.line(44, 39, A4[0] - 44, 39)
        canvas.setFont('RagText', 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(44, 25, f'{classification} — Báo cáo Kiểm thử Xâm nhập')
        canvas.drawRightString(A4[0] - 44, 25, f'Trang {doc.page}')

    class ReportDoc(BaseDocTemplate):
        def afterFlowable(self, flowable):
            if hasattr(flowable, 'toc_label'):
                self.notify('TOCEntry', (0, flowable.toc_label, self.page))

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = ReportDoc(
        str(path), pagesize=A4, leftMargin=44, rightMargin=44, topMargin=44, bottomMargin=55,
        title='Báo cáo Kiểm thử Xâm nhập Ứng dụng Web', author=prepared_by,
    )
    doc.addPageTemplates(
        PageTemplate(id='report', frames=[Frame(44, 55, width, A4[1] - 99, id='main', leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=footer)
    )
    doc.multiBuild(story)
    return path
