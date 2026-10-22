"""A4 PDF Exporter for the Official 10-Section Database Security & OWASP Remediation Report."""
from __future__ import annotations

import html
import re
from pathlib import Path

from .dbsec_report import prepare_dbsec_report
from .top10 import enforce

_BOLD_RE = re.compile(r'\*\*(.+?)\*\*')
_CODE_RE = re.compile(r'`([^`]+)`')


def _fmt_inline(val) -> str:
    """Escape XML safely and render **bold** and `code` spans using full-Unicode RagText."""
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(val or ''))
    escaped = html.escape(cleaned, quote=True)
    escaped = _BOLD_RE.sub(r'<b>\1</b>', escaped)
    escaped = _CODE_RE.sub(r'<font color="#1E3A5F">\1</font>', escaped)
    return escaped.replace('\n', '<br/>')


def _fmt_raw(val) -> str:
    """Escape verbatim evidence / code snippets without markdown interpretation."""
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(val or ''))
    return html.escape(cleaned, quote=True).replace('\n', '<br/>')


def render_pdf(report, path):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        BaseDocTemplate,
        Flowable,
        Frame,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    enforce(report)
    m = prepare_dbsec_report(report)

    fonts_dir = Path(__file__).parent / 'fonts'
    for fname, file_name in [('RagText', 'DejaVuSans.ttf'), ('RagBold', 'DejaVuSans-Bold.ttf')]:
        fpath = fonts_dir / file_name
        if fname not in pdfmetrics.getRegisteredFontNames() and fpath.is_file():
            pdfmetrics.registerFont(TTFont(fname, str(fpath)))
    pdfmetrics.registerFontFamily('RagText', normal='RagText', bold='RagBold', italic='RagText', boldItalic='RagBold')

    col_black = colors.HexColor('#111827')
    col_heading = colors.HexColor('#1E3A5F')
    col_subhead = colors.HexColor('#1F2937')
    col_body = colors.HexColor('#2D3748')
    col_muted = colors.HexColor('#6B7280')
    col_blue = colors.HexColor('#1E4E8C')
    col_border = colors.HexColor('#CBD5E1')
    col_zebra = colors.HexColor('#F8FAFC')
    col_code_bg = colors.HexColor('#F1F5F9')

    margin_x = 50.0
    margin_y = 48.0
    width = A4[0] - (2.0 * margin_x)  # 495.28 pt

    class ObliqueSubtitle(Flowable):
        def __init__(self, text: str, avail_w: float):
            super().__init__()
            self.text = text
            self.width = avail_w
            self.height = 18.0
            self.spaceAfter = 26.0

        def wrap(self, availWidth, availHeight):
            self.width = availWidth
            return (availWidth, self.height)

        def draw(self):
            c = self.canv
            c.saveState()
            c.setFillColor(col_muted)
            c.setFont('RagText', 10.5)
            tw = pdfmetrics.stringWidth(self.text, 'RagText', 10.5)
            c.transform(1.0, 0.0, 0.20, 1.0, max(0.0, (self.width - tw) / 2.0), 4.0)
            c.drawString(0, 0, self.text)
            c.restoreState()

    cover_title_st = ParagraphStyle(
        'cover_title', fontName='RagBold', fontSize=18.5, leading=25, alignment=TA_CENTER,
        textColor=col_heading, spaceAfter=14,
    )
    toc_title_st = ParagraphStyle(
        'toc_title', fontName='RagBold', fontSize=16, leading=22, alignment=TA_LEFT,
        textColor=col_heading, spaceAfter=12,
    )
    toc_item_st = ParagraphStyle(
        'toc_item', fontName='RagText', fontSize=10.5, leading=16, alignment=TA_LEFT,
        textColor=col_blue, spaceAfter=2,
    )
    sec_st = ParagraphStyle(
        'sec_heading', fontName='RagBold', fontSize=13.5, leading=18.5, alignment=TA_LEFT,
        textColor=col_heading, spaceBefore=13, spaceAfter=6, keepWithNext=True,
    )
    sub_st = ParagraphStyle(
        'sub_heading', fontName='RagBold', fontSize=11.0, leading=15.0, alignment=TA_LEFT,
        textColor=col_subhead, spaceBefore=9, spaceAfter=4, keepWithNext=True,
    )
    sub2_st = ParagraphStyle(
        'sub2_heading', fontName='RagBold', fontSize=9.8, leading=13.5, alignment=TA_LEFT,
        textColor=col_blue, spaceBefore=6, spaceAfter=2.5, keepWithNext=True,
    )
    body_st = ParagraphStyle(
        'body', fontName='RagText', fontSize=9.4, leading=13.5, alignment=TA_LEFT,
        textColor=col_body, spaceAfter=4.5, splitLongWords=True,
    )
    bullet_st = ParagraphStyle(
        'bullet', fontName='RagText', fontSize=9.3, leading=13.3, alignment=TA_LEFT,
        textColor=col_body, leftIndent=11, spaceAfter=3.5, splitLongWords=True,
    )
    note_st = ParagraphStyle(
        'note', fontName='RagText', fontSize=8.5, leading=12.0, alignment=TA_LEFT,
        textColor=col_muted, spaceBefore=3, spaceAfter=5, splitLongWords=True,
    )
    code_st = ParagraphStyle(
        'code_block', fontName='RagText', fontSize=7.6, leading=10.4, alignment=TA_LEFT,
        textColor=col_black, backColor=col_code_bg, borderPadding=5.0,
        leftIndent=12, rightIndent=2, spaceAfter=4.5, splitLongWords=True,
    )
    tbl_hdr_st = ParagraphStyle(
        'tbl_hdr', fontName='RagBold', fontSize=8.4, leading=11.2, textColor=colors.white,
    )
    tbl_hdr_num_st = ParagraphStyle(
        'tbl_hdr_num', fontName='RagBold', fontSize=8.4, leading=11.2, alignment=TA_RIGHT, textColor=colors.white,
    )
    tbl_cell_st = ParagraphStyle(
        'tbl_cell', fontName='RagText', fontSize=8.3, leading=11.4, textColor=col_body, splitLongWords=True,
    )
    tbl_cell_bold_st = ParagraphStyle(
        'tbl_cell_bold', fontName='RagBold', fontSize=8.3, leading=11.4, textColor=col_subhead, splitLongWords=True,
    )
    tbl_num_st = ParagraphStyle(
        'tbl_num', fontName='RagText', fontSize=8.5, leading=11.4, alignment=TA_RIGHT, textColor=col_body,
    )

    def make_table(rows_data, col_widths, *, has_header=True):
        t = Table(rows_data, colWidths=col_widths, repeatRows=(1 if has_header else 0), hAlign='LEFT')
        styles = [
            ('GRID', (0, 0), (-1, -1), 0.45, col_border),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4.5),
        ]
        if has_header:
            styles.append(('BACKGROUND', (0, 0), (-1, 0), col_blue))
            start_r = 1
        else:
            start_r = 0
        for r_i in range(start_r, len(rows_data)):
            if (r_i - start_r) % 2 == 1:
                styles.append(('BACKGROUND', (0, r_i), (-1, r_i), col_zebra))
        t.setStyle(TableStyle(styles))
        return t

    story = []

    def add_sec(idx: int):
        st = ParagraphStyle(f'sec_{idx}', parent=sec_st, spaceBefore=(4 if idx == 1 else 14))
        story.append(Paragraph(f'<a name="sec{idx}"/>{_fmt_raw(m["section_titles"][idx - 1])}', st))

    def add_bullet(text: str):
        story.append(Paragraph(f'• {_fmt_inline(text)}', bullet_st))

    def add_snippet_block(text: str):
        raw = str(text or '').strip()
        if not raw:
            return
        for start in range(0, len(raw), 2200):
            story.append(Paragraph(_fmt_raw(raw[start:start + 2200]), code_st))

    # ==================== PAGE 1: ACADEMIC COVER PAGE ====================
    story.append(Spacer(1, 68))
    story.append(Paragraph(
        'BÁO CÁO KIỂM THỬ BẢO MẬT CSDL<br/>VÀ ĐỀ XUẤT REMEDIATION THEO OWASP',
        cover_title_st,
    ))
    story.append(ObliqueSubtitle(m['subtitle'], width))

    cover_rows = [
        [Paragraph(_fmt_raw(k), tbl_cell_bold_st), Paragraph(_fmt_inline(v), tbl_cell_st)]
        for k, v in m['general_info']
    ]
    story.append(make_table(cover_rows, [width * 0.31, width * 0.69], has_header=False))

    # ==================== PAGE 2: TABLE OF CONTENTS ====================
    story.append(PageBreak())
    story.append(Spacer(1, 6))
    story.append(Paragraph('Mục lục báo cáo', toc_title_st))
    for idx_s, title_s in enumerate(m['section_titles'], 1):
        story.append(Paragraph(f'<a href="#sec{idx_s}" color="#1E4E8C">{_fmt_raw(title_s)}</a>', toc_item_st))

    # ==================== PAGE 3+: SECTIONS 1..10 ====================
    story.append(PageBreak())

    # 1. Thông tin chung
    add_sec(1)
    sec1_rows = [
        [Paragraph(_fmt_raw(k), tbl_cell_bold_st), Paragraph(_fmt_inline(v), tbl_cell_st)]
        for k, v in m['general_info']
    ]
    story.extend([make_table(sec1_rows, [width * 0.30, width * 0.70], has_header=False), Spacer(1, 6)])

    # 2. Đánh giá dữ liệu đầu vào
    add_sec(2)
    story.append(Paragraph('2.1. Nguồn dữ liệu', sub_st))
    src_tbl = [[
        Paragraph('Mã', tbl_hdr_st),
        Paragraph('Tên dữ liệu', tbl_hdr_st),
        Paragraph('Nguồn', tbl_hdr_st),
        Paragraph('Trạng thái', tbl_hdr_st),
    ]]
    for s in m['input_sources']:
        src_tbl.append([
            Paragraph(_fmt_raw(s['id']), tbl_cell_bold_st),
            Paragraph(_fmt_raw(s['name']), tbl_cell_st),
            Paragraph(_fmt_raw(s['source']), tbl_cell_st),
            Paragraph(_fmt_raw(s['status']), tbl_cell_st),
        ])
    story.extend([make_table(src_tbl, [width * 0.10, width * 0.28, width * 0.30, width * 0.32]), Spacer(1, 5)])

    qa = m['quality_assessment']
    story.append(Paragraph('2.2. Chất lượng dữ liệu', sub_st))
    add_bullet(f"**Thông tin đã có:** {qa['present']}")
    add_bullet(f"**Thông tin còn thiếu:** {qa['missing']}")
    add_bullet(f"**Giới hạn phân tích:** {qa['analytic_limits']}")

    # 3. Phương pháp phân tích
    add_sec(3)
    meth = m['methodology']
    add_bullet(f"**Phương pháp:** {meth['method']}")
    add_bullet(f"**Công cụ hỗ trợ:** {meth['tools']}")
    add_bullet(f"**Tài liệu đối chiếu:** {meth['references']}")
    add_bullet(f"**Tiêu chí phân loại:** {meth['criteria']}")

    # 4. Tóm tắt kết quả
    add_sec(4)
    story.append(Paragraph('4.1. Tổng quan phát hiện', sub_st))
    mat_tbl = [[
        Paragraph('Mức độ', tbl_hdr_st),
        Paragraph('Đã xác nhận', tbl_hdr_num_st),
        Paragraph('Có dấu hiệu', tbl_hdr_num_st),
        Paragraph('Chưa đủ dữ liệu', tbl_hdr_num_st),
    ]]
    for sev_lbl, c_conf, c_tent, c_insuf in m['matrix_rows']:
        mat_tbl.append([
            Paragraph(_fmt_raw(sev_lbl), tbl_cell_bold_st),
            Paragraph(str(c_conf), tbl_num_st),
            Paragraph(str(c_tent), tbl_num_st),
            Paragraph(str(c_insuf), tbl_num_st),
        ])
    story.append(make_table(mat_tbl, [width * 0.34, width * 0.22, width * 0.22, width * 0.22]))
    story.append(Paragraph(
        'Ghi chú: Chỉ thống kê các phát hiện thực tế từ dữ liệu đầu vào. Không tự tạo số liệu hoặc tự gán mức độ nghiêm trọng khi công cụ gốc không cung cấp.',
        note_st,
    ))
    story.append(Paragraph('4.2. Nhận xét tổng quan', sub_st))
    for p_txt in m['overview_paras']:
        story.append(Paragraph(_fmt_inline(p_txt), body_st))

    # 5. Danh sách phát hiện
    add_sec(5)
    f_tbl = [[
        Paragraph('ID', tbl_hdr_st),
        Paragraph('Phát hiện', tbl_hdr_st),
        Paragraph('Thành phần', tbl_hdr_st),
        Paragraph('OWASP', tbl_hdr_st),
        Paragraph('Mức độ', tbl_hdr_st),
        Paragraph('Trạng thái', tbl_hdr_st),
    ]]
    if not m['findings']:
        f_tbl.append([
            Paragraph('—', tbl_cell_st),
            Paragraph('Không ghi nhận cảnh báo lỗ hổng trong dữ liệu đầu vào', tbl_cell_st),
            Paragraph('—', tbl_cell_st),
            Paragraph('Chưa xác định', tbl_cell_st),
            Paragraph('Chưa xác định', tbl_cell_st),
            Paragraph('Không xác nhận được', tbl_cell_st),
        ])
    else:
        for f in m['findings']:
            f_tbl.append([
                Paragraph(_fmt_raw(f['id']), tbl_cell_bold_st),
                Paragraph(_fmt_raw(f['title']), tbl_cell_st),
                Paragraph(_fmt_inline(f['component']), tbl_cell_st),
                Paragraph(_fmt_raw(f['owasp_category']), tbl_cell_st),
                Paragraph(_fmt_raw(f['severity_label']), tbl_cell_st),
                Paragraph(_fmt_raw(f['state']), tbl_cell_bold_st),
            ])
    story.extend([
        make_table(f_tbl, [width * 0.07, width * 0.21, width * 0.25, width * 0.17, width * 0.15, width * 0.15]),
        Spacer(1, 6),
    ])

    # 6. Phân tích chi tiết phát hiện
    add_sec(6)
    if not m['findings']:
        story.append(Paragraph('Không có phát hiện nào trong dữ liệu đầu vào cần phân tích chi tiết.', body_st))
    for f in m['findings']:
        story.append(Paragraph(_fmt_raw(f"{f['id']}: {f['title']}"), sub_st))
        story.append(Paragraph('6.1. Trạng thái phát hiện', sub2_st))
        add_bullet(f['state_detail'])

        story.append(Paragraph('6.2. Vị trí và thành phần bị ảnh hưởng', sub2_st))
        add_bullet(f"{f['component']} (`{f['cwe_label']}`)")

        story.append(Paragraph('6.3. Bằng chứng', sub2_st))
        if not f['evidences']:
            add_bullet(f"Không có trích đoạn bằng chứng phản hồi chi tiết trong nguồn `{f['source_id']}`.")
        for ev in f['evidences']:
            add_bullet(f"**Mã bằng chứng:** `{ev['id']}` — **Nguồn:** `{ev['source_id']}` ({ev['kind']})")
            add_snippet_block(ev['snippet'])
            add_bullet(f"**Giải thích bằng chứng:** {ev['explanation']}")
        if f['excluded_http_note']:
            add_bullet(f"**Lưu ý lọc nhiễu bằng chứng:** {f['excluded_http_note']}")
        for ai_n in f.get('ai_notes') or []:
            add_bullet(f"**Diễn giải kỹ thuật từ dữ liệu đầu vào:** {ai_n}")

        story.append(Paragraph('6.4. Phân loại OWASP', sub2_st))
        add_bullet(f"**Tài liệu:** {f['owasp_doc']} | **Phiên bản:** {f['owasp_version']}")
        add_bullet(f"**Danh mục:** {f['owasp_category']}")
        add_bullet(f"**Lý do phân loại:** {f['owasp_reason']}")
        add_bullet(f"**Nguồn tham khảo:** {f['owasp_url']}")

        story.append(Paragraph('6.5. Đánh giá mức độ nghiêm trọng', sub2_st))
        add_bullet(f"**Mức độ:** {f['severity_label']}")
        add_bullet(f"**Cơ sở đánh giá:** {f['severity_basis']}")
        add_bullet(f"**Các yếu tố chưa xác định:** {f['unknown_factors']}")

        story.append(Paragraph('6.6. Nguyên nhân', sub2_st))
        add_bullet(f['root_cause'])

        story.append(Paragraph('6.7. Ảnh hưởng tiềm tàng', sub2_st))
        add_bullet(f['potential_impact'])

    # 7. Đề xuất remediation
    add_sec(7)
    if not m['findings']:
        story.append(Paragraph('Không phát sinh đề xuất khắc phục bắt buộc do dữ liệu đầu vào không ghi nhận phát hiện lỗ hổng.', body_st))
    for f in m['findings']:
        ref_str = (
            '; '.join(
                f"{r['section']}" + (f" ({r['url']})" if r['url'] else '')
                for r in f['rem_refs']
            )
            if f['rem_refs']
            else f"{f['owasp_doc']} {f['owasp_version']} — {f['owasp_category']} ({f['owasp_url']})"
        )
        story.append(Paragraph(_fmt_raw(f"{f['id']}: {f['title']}"), sub_st))
        story.append(Paragraph('7.1. Mục tiêu khắc phục', sub2_st))
        add_bullet(f['rem_goal'])

        story.append(Paragraph('7.2. Biện pháp đề xuất', sub2_st))
        for st_line in f['rem_steps']:
            add_bullet(st_line)
        for code_ex in f['code_examples']:
            add_bullet(f"**Ví dụ mã an toàn trích xuất từ `{code_ex['section']}`:**")
            add_snippet_block(code_ex['code'])

        story.append(Paragraph('7.3. Cơ sở của đề xuất', sub2_st))
        add_bullet(f"**Phát hiện liên quan:** `{f['id']}` | **Bằng chứng liên quan:** {', '.join(f'`{eid}`' for eid in f['evidence_ids']) or 'Chưa có'}")
        add_bullet(f"**Tài liệu tham khảo:** {ref_str}")
        add_bullet(f"**Lý do lựa chọn:** {f['rem_reason']}")

        story.append(Paragraph('7.4. Ưu tiên khắc phục', sub2_st))
        add_bullet(f['priority'])

        story.append(Paragraph('7.5. Kế hoạch kiểm tra lại', sub2_st))
        add_bullet(f"**Nội dung cần kiểm tra:** {f['retest_check']}")
        add_bullet(f"**Phương pháp xác minh:** {f['retest_method']}")
        add_bullet(f"**Kết quả kiểm tra:** {f['retest_result']}")
        add_bullet(f"**Bằng chứng sau khắc phục:** {f['retest_evidence']}")

    # 8. Giới hạn và độ tin cậy của báo cáo
    add_sec(8)
    story.append(Paragraph('8.1. Giới hạn', sub_st))
    for lb in m['limits_bullets']:
        add_bullet(lb)
    story.append(Paragraph('8.2. Những nội dung cần xác minh', sub_st))
    for vi in m['verify_items']:
        add_bullet(vi)
    story.append(Paragraph('8.3. Độ tin cậy', sub_st))
    for rp in m['reliability_paras']:
        story.append(Paragraph(_fmt_inline(rp), body_st))

    # 9. Kết luận
    add_sec(9)
    for cp in m['conclusion_paras']:
        story.append(Paragraph(_fmt_inline(cp), body_st))

    # 10. Phụ lục
    add_sec(10)
    story.append(Paragraph('10.1. Danh sách dữ liệu đầu vào', sub_st))
    for s in m['input_sources']:
        sha_bit = f" | SHA-256: `{s['sha256']}`" if s['sha256'] else ''
        add_bullet(f"**`{s['id']}`** — `{s['name']}` ({s['source']}) — {s['status']}{sha_bit}")

    story.append(Paragraph('10.2. Danh mục bằng chứng kiểm thử', sub_st))
    if not m['all_evidences']:
        add_bullet('Không có trích đoạn bằng chứng chi tiết trong dữ liệu đầu vào.')
    else:
        for ev in m['all_evidences']:
            add_bullet(f"**`{ev['id']}`** (thuộc `{ev['finding_id']}`, nguồn `{ev['source_id']}`): {ev['kind']}")

    story.append(Paragraph('10.3. Tài liệu OWASP được đối chiếu', sub_st))
    if not m['cited_owasp_docs']:
        add_bullet('OWASP Top 10:2025 (https://owasp.org/Top10/2025/)')
    else:
        for doc in m['cited_owasp_docs']:
            add_bullet(f"**{doc['type']}:** {doc['title']}" + (f" — {doc['url']}" if doc['url'] else ''))
    if m['knowledge_sha256'] and m['knowledge_sha256'] != 'not_used':
        add_bullet(f"**Mã băm toàn vẹn kho tri thức OWASP cục bộ (SHA-256):** `{m['knowledge_sha256']}`")

    story.append(Paragraph('10.4. Kết quả kiểm tra lại', sub_st))
    add_bullet(f"**Trạng thái hiện tại:** {m['retest_status']}")
    add_bullet(f"**Bằng chứng kiểm tra lại:** {m['retest_evidence']}")

    def _draw_page(canvas, doc_obj):
        pnum = canvas.getPageNumber()
        if pnum <= 1:
            return
        canvas.saveState()
        canvas.setFont('RagText', 8.0)
        canvas.setFillColor(col_muted)
        canvas.drawString(margin_x, 24.0, 'Báo cáo Kiểm thử Bảo mật CSDL & Đề xuất Remediation theo OWASP')
        canvas.drawRightString(A4[0] - margin_x, 24.0, f'Trang {pnum}')
        canvas.restoreState()

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = BaseDocTemplate(
        str(out),
        pagesize=A4,
        leftMargin=margin_x,
        rightMargin=margin_x,
        topMargin=margin_y,
        bottomMargin=margin_y,
        title=m['title'],
        author='DBSec OWASP Report Engine',
    )
    frame = Frame(margin_x, margin_y, width, A4[1] - (2.0 * margin_y), leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id='dbsec', frames=[frame], onPage=_draw_page)])
    doc.build(story)
    return out
