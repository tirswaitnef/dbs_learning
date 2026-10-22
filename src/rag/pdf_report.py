"""Exact layout replica of `web-pentest-report-template.pdf`, filled strictly from scan input."""
from __future__ import annotations

import html
import re
from pathlib import Path


def render_pdf(report, path):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        BaseDocTemplate, Flowable, Frame, PageBreak, PageTemplate,
        Paragraph, Spacer, Table, TableStyle,
    )

    from .pentest_polish import collect_template_fields, prepare_pentest_view
    from .top10 import enforce

    enforce(report)
    view = prepare_pentest_view(report)
    en = view['lang'] == 'en'
    tf = collect_template_fields(view)
    entries = view['entries']

    fonts_dir = Path(__file__).parent / 'fonts'
    for fname, file_name in [('RagText', 'DejaVuSans.ttf'), ('RagBold', 'DejaVuSans-Bold.ttf')]:
        fpath = fonts_dir / file_name
        if fname not in pdfmetrics.getRegisteredFontNames() and fpath.is_file():
            pdfmetrics.registerFont(TTFont(fname, str(fpath)))
    pdfmetrics.registerFontFamily('RagText', normal='RagText', bold='RagBold', italic='RagText', boldItalic='RagBold')

    # Exact palette extracted from `web-pentest-report-template.pdf`
    col_black = colors.HexColor('#000000')
    col_heading = colors.HexColor('#1A1A1A')
    col_body = colors.HexColor('#333333')
    col_subtitle = colors.HexColor('#666666')
    col_red = colors.HexColor('#CC0000')
    col_blue = colors.HexColor('#2B579A')
    col_zebra = colors.HexColor('#F2F2F2')
    col_code_bg = colors.HexColor('#F5F6F8')

    margin_x = 60.0
    margin_y = 48.0
    width = A4[0] - (2.0 * margin_x)  # 475.28 pt (matches 475 pt in reference template)

    class ObliqueSubtitle(Flowable):
        def __init__(self, text: str, avail_w: float):
            super().__init__()
            self.text = text
            self.width = avail_w
            self.height = 18.0
            self.spaceAfter = 34.0

        def wrap(self, availWidth, availHeight):
            self.width = availWidth
            return (availWidth, self.height)

        def draw(self):
            c = self.canv
            c.saveState()
            c.setFillColor(col_subtitle)
            c.setFont('RagText', 13.5)
            tw = pdfmetrics.stringWidth(self.text, 'RagText', 13.5)
            c.transform(1.0, 0.0, 0.20, 1.0, (self.width - tw) / 2.0, 4.0)
            c.drawString(0, 0, self.text)
            c.restoreState()

    cover_title_st = ParagraphStyle(
        'cover_title', fontName='RagBold', fontSize=21.5, leading=28, alignment=TA_CENTER,
        textColor=col_black, spaceAfter=20,
    )
    cover_meta_st = ParagraphStyle(
        'cover_meta', fontName='RagText', fontSize=11.5, leading=14.5, alignment=TA_CENTER,
        textColor=col_body, spaceAfter=2,
    )
    cover_class_st = ParagraphStyle(
        'cover_class', fontName='RagBold', fontSize=11.5, leading=15, alignment=TA_CENTER,
        textColor=col_red, spaceBefore=14,
    )

    toc_title_st = ParagraphStyle(
        'toc_title', fontName='RagBold', fontSize=18, leading=24, alignment=TA_LEFT,
        textColor=col_black, spaceAfter=14,
    )
    toc_item_st = ParagraphStyle(
        'toc_item', fontName='RagText', fontSize=11, leading=14.2, alignment=TA_LEFT,
        textColor=col_blue, spaceAfter=2,
    )

    sec_heading_st = ParagraphStyle(
        'sec_heading', fontName='RagBold', fontSize=15.0, leading=20, alignment=TA_LEFT,
        textColor=col_heading, spaceBefore=13, spaceAfter=6, keepWithNext=True,
    )
    finding_heading_st = ParagraphStyle(
        'finding_heading', fontName='RagBold', fontSize=11.5, leading=15.5, alignment=TA_LEFT,
        textColor=col_heading, spaceBefore=8, spaceAfter=4, keepWithNext=True,
    )
    body_st = ParagraphStyle(
        'body', fontName='RagText', fontSize=9.8, leading=13.8, alignment=TA_LEFT,
        textColor=col_body, spaceAfter=5.0, splitLongWords=True,
    )
    plain_line_st = ParagraphStyle(
        'plain_line', fontName='RagText', fontSize=9.8, leading=13.6, alignment=TA_LEFT,
        textColor=col_body, spaceAfter=4.0, splitLongWords=True,
    )
    kv_line_st = ParagraphStyle(
        'kv_line', fontName='RagText', fontSize=9.8, leading=13.6, alignment=TA_LEFT,
        textColor=col_body, spaceAfter=4.0, splitLongWords=True,
    )
    code_st = ParagraphStyle(
        'code_block', fontName='RagText', fontSize=7.7, leading=10.5, alignment=TA_LEFT,
        textColor=col_body, backColor=col_code_bg, borderPadding=4.5, leftIndent=6, rightIndent=0,
        spaceAfter=4.5, splitLongWords=True,
    )
    tbl_hdr_st = ParagraphStyle(
        'tbl_hdr', fontName='RagBold', fontSize=8.3, leading=11, textColor=colors.white,
    )
    tbl_cell_st = ParagraphStyle(
        'tbl_cell', fontName='RagText', fontSize=8.3, leading=11.5, textColor=col_body, splitLongWords=True,
    )
    end_st = ParagraphStyle(
        'end_mark', fontName='RagBold', fontSize=10, leading=14, alignment=TA_CENTER,
        textColor=col_body, spaceBefore=18, spaceAfter=4,
    )

    def esc(val) -> str:
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(val or ''))
        return html.escape(cleaned, quote=True).replace('\n', '<br/>')

    story = []

    def add_plain_line(label: str, val: str):
        story.append(Paragraph(f"{esc(label)}: {esc(val)}", plain_line_st))

    def add_bold_kv(label: str, val: str):
        story.append(Paragraph(f"<b>{esc(label)}:</b> {esc(val)}", kv_line_st))

    def add_code_kv(label: str, raw_val: str):
        text = str(raw_val or '').strip()
        if text in {
            'Not captured in input',
            'Not captured in scanner input',
            'Không ghi nhận trong đầu vào',
            'Không có bản ghi gói phản hồi riêng trong đầu vào',
            'Không có bản ghi gói yêu cầu riêng trong đầu vào',
        }:
            add_bold_kv(label, text)
            return
        story.append(Paragraph(f"<b>{esc(label)}:</b>", ParagraphStyle('kv_lbl_only', parent=kv_line_st, spaceAfter=2, keepWithNext=True)))
        for start in range(0, len(text), 2400):
            story.append(Paragraph(esc(text[start:start + 2400]), code_st))

    s_titles = (
        [
            '1. Executive Summary',
            '2. Scope and Methodology',
            '3. Findings Summary by OWASP Category',
            '4. Detailed Findings',
            '5. Risk Ratings',
            '6. Remediation Recommendations',
            '7. Appendix',
        ]
        if en
        else [
            '1. Tóm tắt điều hành',
            '2. Phạm vi và Phương pháp kiểm thử',
            '3. Tổng hợp phát hiện theo Danh mục OWASP',
            '4. Chi tiết các phát hiện',
            '5. Phân loại mức độ rủi ro',
            '6. Khuyến nghị khắc phục',
            '7. Phụ lục',
        ]
    )

    # ==================== PAGE 1: CLEAN CENTERED COVER PAGE ====================
    story.append(Spacer(1, 96))
    cover_title = (
        'Web Application Penetration Testing<br/>Report'
        if en
        else 'Báo cáo Kiểm thử Xâm nhập<br/>Ứng dụng Web'
    )
    cover_sub = (
        'OWASP-Based Web Application Security Assessment'
        if en
        else 'Đánh giá Bảo mật Ứng dụng Web dựa trên OWASP'
    )
    story.append(Paragraph(cover_title, cover_title_st))
    story.append(ObliqueSubtitle(cover_sub, width))
    story.append(Paragraph(f"{'Prepared for' if en else 'Đơn vị tiếp nhận'}: {esc(tf['client_name'])}", cover_meta_st))
    story.append(Paragraph(f"{'Prepared by' if en else 'Thực hiện bởi'}: {esc(tf['prepared_by'])}", cover_meta_st))
    story.append(Paragraph(f"{'Date' if en else 'Ngày báo cáo'}: {esc(tf['report_date'])}", cover_meta_st))
    story.append(Paragraph(f"{'Classification' if en else 'Phân loại'}: {esc(tf['classification'])}", cover_class_st))

    # ==================== PAGE 2: DEDICATED TABLE OF CONTENTS ====================
    story.append(PageBreak())
    story.append(Spacer(1, 6))
    story.append(Paragraph('Table of Contents' if en else 'Mục lục', toc_title_st))
    for idx_s, st in enumerate(s_titles, 1):
        story.append(Paragraph(f'<a href="#sec{idx_s}" color="#2B579A">{esc(st)}</a>', toc_item_st))

    # ==================== PAGE 3+: CONTINUOUS SECTIONS 1..7 ====================
    story.append(PageBreak())

    def add_sec_heading(idx_s: int):
        style = ParagraphStyle(f'sec_{idx_s}', parent=sec_heading_st, spaceBefore=(4 if idx_s == 1 else 13))
        story.append(Paragraph(f'<a name="sec{idx_s}"/>{esc(s_titles[idx_s - 1])}', style))

    # 1. Executive Summary
    add_sec_heading(1)
    for p_txt in tf['exec_paragraphs']:
        story.append(Paragraph(esc(p_txt), body_st))

    # 2. Scope and Methodology
    add_sec_heading(2)
    add_plain_line('Target URL(s)' if en else 'URL mục tiêu', tf['target_urls'])
    add_plain_line('Authenticated Roles Tested' if en else 'Vai trò xác thực đã kiểm thử', tf['auth_roles'])
    add_plain_line('Excluded Areas' if en else 'Phạm vi loại trừ', tf['excluded_areas'])
    add_plain_line('Testing Areas per OWASP Top 10' if en else 'Hạng mục kiểm thử theo OWASP Top 10', tf['testing_areas'])
    add_plain_line('Tools' if en else 'Công cụ sử dụng', tf['tools_str'])

    # 3. Findings Summary by OWASP Category
    add_sec_heading(3)
    hdr_row = (
        ['OWASP Category', 'Finding Count', 'Highest Severity']
        if en
        else ['Danh mục OWASP', 'Số lượng phát hiện', 'Mức độ cao nhất']
    )
    tbl_data = [[Paragraph(esc(h), tbl_hdr_st) for h in hdr_row]]
    for cat_c, cnt_c, sev_c in tf['summary_rows']:
        tbl_data.append([Paragraph(esc(cat_c), tbl_cell_st), Paragraph(esc(cnt_c), tbl_cell_st), Paragraph(esc(sev_c), tbl_cell_st)])

    tbl_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), col_blue),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 5),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 5),
        ('TOPPADDING', (0, 1), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
    ]
    for r_i in range(1, len(tbl_data)):
        if r_i % 2 == 1:
            tbl_styles.append(('BACKGROUND', (0, r_i), (-1, r_i), col_zebra))
    t_sum = Table(tbl_data, colWidths=[width / 3.0, width / 3.0, width / 3.0], repeatRows=1, hAlign='LEFT')
    t_sum.setStyle(TableStyle(tbl_styles))
    story.extend([t_sum, Spacer(1, 6)])

    # 4. Detailed Findings
    add_sec_heading(4)
    if not entries:
        story.append(Paragraph(
            esc('No confirmed vulnerabilities were identified in the supplied input.' if en else 'Không có lỗ hổng bảo mật đã xác nhận trong dữ liệu đầu vào.'),
            body_st,
        ))
    for e in entries:
        story.append(Paragraph(esc(f"{e['pentest_id']}: {e['title']}"), finding_heading_st))
        cvss_line = (
            f"{e['cvss_score']} — {e['cvss_vector']}" if e['cvss_score'] and e['cvss_vector']
            else (e['cvss_score'] or ('Not provided in scanner input' if en else 'Không có trong dữ liệu đầu vào'))
        )
        affected_url = (
            f"{e['url']} (parameter: {e['parameter']})"
            if e['parameter'] not in {'N/A', 'Không áp dụng'}
            else e['url']
        )
        add_bold_kv('Severity' if en else 'Mức độ nghiêm trọng', e['severity_label'])
        add_bold_kv('CVSS 3.1 Score' if en else 'Điểm CVSS 3.1', cvss_line)
        add_bold_kv('OWASP Category' if en else 'Danh mục OWASP', e['owasp_label'])
        add_bold_kv('CWE', e['cwe_label'])
        add_bold_kv('Affected URL' if en else 'URL ảnh hưởng', affected_url)
        add_bold_kv('HTTP Method' if en else 'Phương thức HTTP', e['method'])
        add_bold_kv('Description' if en else 'Mô tả', e['description'])
        add_code_kv('Request' if en else 'Yêu cầu (Request)', e['request_text'])
        add_code_kv('Response' if en else 'Phản hồi (Response)', e['response_text'])
        add_bold_kv('Impact' if en else 'Tác động', e['impact_text'])

    # 5. Risk Ratings
    add_sec_heading(5)
    risk_defs = (
        [
            ('Critical (9.0-10.0)', 'Unauthenticated SQL injection, RCE, authentication bypass, mass data exposure.'),
            ('High (7.0-8.9)', 'Authenticated SQL injection, stored XSS, IDOR with sensitive data, privilege escalation.'),
            ('Medium (4.0-6.9)', 'Reflected XSS, CSRF, information disclosure, session fixation.'),
            ('Low (0.1-3.9)', 'Missing headers, verbose errors, cookie attributes, outdated component banners.'),
        ]
        if en
        else [
            ('Critical — Nghiêm trọng (9.0-10.0)', 'SQL Injection không cần xác thực, thực thi mã từ xa (RCE), vượt xác thực, lộ dữ liệu diện rộng.'),
            ('High — Cao (7.0-8.9)', 'SQL Injection qua phiên xác thực, Stored XSS, leo thang đặc quyền, truy cập trái phép dữ liệu nhạy cảm.'),
            ('Medium — Trung bình (4.0-6.9)', 'Reflected XSS, CSRF, lộ thông tin cấu trúc nội bộ, điểm yếu quản lý phiên.'),
            ('Low — Thấp (0.1-3.9)', 'Thiếu HTTP Security Headers, thông báo lỗi chi tiết, thiếu cờ bảo vệ cookie, phiên bản phần mềm cũ.'),
        ]
    )
    for r_lbl, r_desc in risk_defs:
        add_plain_line(r_lbl, r_desc)

    # 6. Remediation Recommendations
    add_sec_heading(6)
    if view['global_recommendations']:
        for idx_r, rec in enumerate(view['global_recommendations'], 1):
            raw_t = str(rec['title'] or '')
            if raw_t.startswith('[') and '] ' in raw_t:
                tag_part, rest_part = raw_t.split('] ', 1)
                story.append(Paragraph(f"<b>{idx_r}. {esc(tag_part + ']')}</b> {esc(rest_part)}", plain_line_st))
            else:
                story.append(Paragraph(f"{idx_r}. {esc(raw_t)}", plain_line_st))
    else:
        story.append(Paragraph(
            esc('1. No confirmed remediation actions required based on supplied input.' if en else '1. Chưa ghi nhận hạng mục cần khắc phục từ dữ liệu đầu vào.'),
            plain_line_st,
        ))

    # 7. Appendix
    add_sec_heading(7)
    for letter, heading_txt in tf['appendix_lines']:
        story.append(Paragraph(f"{letter}. {esc(heading_txt)}", plain_line_st))

    story.append(Paragraph('— End of Report —' if en else '— Kết thúc Báo cáo —', end_st))

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = BaseDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=margin_x,
        rightMargin=margin_x,
        topMargin=margin_y,
        bottomMargin=margin_y,
        title='Web Application Penetration Testing Report' if en else 'Báo cáo Kiểm thử Xâm nhập Ứng dụng Web',
        author=tf['prepared_by'],
    )
    doc.addPageTemplates(
        PageTemplate(
            id='report',
            frames=[Frame(margin_x, margin_y, width, A4[1] - (2.0 * margin_y), id='main', leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)],
        )
    )
    doc.build(story)
    return path
