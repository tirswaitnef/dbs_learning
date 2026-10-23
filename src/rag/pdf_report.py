"""A4 PDF Exporter for the Official 10-Section Database Security & OWASP Remediation Report.

Supports two presentation profiles:
- `compact` (default — Executive / Presentation, 2–4 pages for 1 finding): single continuous flow,
  zero duplicate General Info, crisp high-signal typography, inline clickable section index.
- `full` (Audit Archive): dedicated TOC page + full unminified multi-packet & multi-chunk archive
  (still strictly free of duplicate `Thông tin chung`).
"""
from __future__ import annotations

import html
import re
from pathlib import Path

from .dbsec_report import normalize_report_profile, prepare_dbsec_report
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


def render_pdf(report, path, *, profile: str | None = None):
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
    resolved_profile = normalize_report_profile(profile, (report.get('report_metadata') if isinstance(report, dict) else None))
    is_compact = (resolved_profile == 'compact')
    m = prepare_dbsec_report(report, profile=resolved_profile)

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

    margin_x = 32.0 if is_compact else 46.0
    margin_y = 21.0 if is_compact else 44.0
    width = A4[0] - (2.0 * margin_x)

    class ObliqueSubtitle(Flowable):
        def __init__(self, text: str, avail_w: float, *, compact: bool = True):
            super().__init__()
            self.text = text
            self.width = avail_w
            self.compact = compact
            self.height = 13.0 if compact else 18.0
            self.spaceAfter = 5.0 if compact else 18.0

        def wrap(self, availWidth, availHeight):
            self.width = availWidth
            return (availWidth, self.height)

        def draw(self):
            c = self.canv
            c.saveState()
            c.setFillColor(col_muted)
            fsize = 8.6 if self.compact else 10.2
            c.setFont('RagText', fsize)
            tw = pdfmetrics.stringWidth(self.text, 'RagText', fsize)
            c.transform(1.0, 0.0, 0.20, 1.0, max(0.0, (self.width - tw) / 2.0), 3.0)
            c.drawString(0, 0, self.text)
            c.restoreState()

    cover_title_st = ParagraphStyle(
        'cover_title', fontName='RagBold',
        fontSize=(13.2 if is_compact else 17.5),
        leading=(17.0 if is_compact else 23.5),
        alignment=TA_CENTER,
        textColor=col_heading,
        spaceAfter=(3.0 if is_compact else 10.0),
    )
    toc_inline_st = ParagraphStyle(
        'toc_inline', fontName='RagText', fontSize=7.4, leading=10.2, alignment=TA_CENTER,
        textColor=col_blue, backColor=col_zebra, borderPadding=3.5, spaceAfter=6.0,
    )
    toc_title_st = ParagraphStyle(
        'toc_title', fontName='RagBold', fontSize=15, leading=20, alignment=TA_LEFT,
        textColor=col_heading, spaceAfter=10,
    )
    toc_item_st = ParagraphStyle(
        'toc_item', fontName='RagText', fontSize=10.0, leading=15, alignment=TA_LEFT,
        textColor=col_blue, spaceAfter=2,
    )
    sec_st = ParagraphStyle(
        'sec_heading', fontName='RagBold',
        fontSize=(10.2 if is_compact else 13.0),
        leading=(12.8 if is_compact else 17.5),
        alignment=TA_LEFT, textColor=col_heading,
        spaceBefore=(5.0 if is_compact else 12.0),
        spaceAfter=(2.0 if is_compact else 5.0),
        keepWithNext=True,
    )
    sub_st = ParagraphStyle(
        'sub_heading', fontName='RagBold',
        fontSize=(8.8 if is_compact else 10.8),
        leading=(11.2 if is_compact else 14.5),
        alignment=TA_LEFT, textColor=col_subhead,
        spaceBefore=(3.6 if is_compact else 8.0),
        spaceAfter=(1.5 if is_compact else 3.5),
        keepWithNext=True,
    )
    sub2_st = ParagraphStyle(
        'sub2_heading', fontName='RagBold',
        fontSize=(8.0 if is_compact else 9.6),
        leading=(10.2 if is_compact else 13.0),
        alignment=TA_LEFT, textColor=col_blue,
        spaceBefore=(2.4 if is_compact else 5.5),
        spaceAfter=(1.0 if is_compact else 2.2),
        keepWithNext=True,
    )
    body_st = ParagraphStyle(
        'body', fontName='RagText',
        fontSize=(7.9 if is_compact else 9.2),
        leading=(10.4 if is_compact else 13.2),
        alignment=TA_LEFT, textColor=col_body,
        spaceAfter=(1.8 if is_compact else 4.0),
        splitLongWords=True,
    )
    bullet_st = ParagraphStyle(
        'bullet', fontName='RagText',
        fontSize=(7.8 if is_compact else 9.1),
        leading=(10.2 if is_compact else 13.0),
        alignment=TA_LEFT, textColor=col_body,
        leftIndent=(7 if is_compact else 11),
        spaceAfter=(1.2 if is_compact else 3.2),
        splitLongWords=True,
    )
    note_st = ParagraphStyle(
        'note', fontName='RagText',
        fontSize=(7.4 if is_compact else 8.3),
        leading=(9.8 if is_compact else 11.6),
        alignment=TA_LEFT, textColor=col_muted,
        spaceBefore=1.5, spaceAfter=(2.5 if is_compact else 4.5),
        splitLongWords=True,
    )
    code_st = ParagraphStyle(
        'code_block', fontName='RagText',
        fontSize=(7.1 if is_compact else 7.6),
        leading=(9.3 if is_compact else 10.4),
        alignment=TA_LEFT, textColor=col_black, backColor=col_code_bg,
        borderPadding=(3.2 if is_compact else 5.0),
        leftIndent=(9 if is_compact else 12), rightIndent=2,
        spaceAfter=(2.2 if is_compact else 4.2),
        splitLongWords=True,
    )
    tbl_hdr_st = ParagraphStyle(
        'tbl_hdr', fontName='RagBold', fontSize=(7.7 if is_compact else 8.3), leading=10.0, textColor=colors.white,
    )
    tbl_hdr_num_st = ParagraphStyle(
        'tbl_hdr_num', fontName='RagBold', fontSize=(7.7 if is_compact else 8.3), leading=10.0, alignment=TA_RIGHT, textColor=colors.white,
    )
    tbl_cell_st = ParagraphStyle(
        'tbl_cell', fontName='RagText', fontSize=(7.7 if is_compact else 8.2), leading=(10.0 if is_compact else 11.2), textColor=col_body, splitLongWords=True,
    )
    tbl_cell_bold_st = ParagraphStyle(
        'tbl_cell_bold', fontName='RagBold', fontSize=(7.7 if is_compact else 8.2), leading=(10.0 if is_compact else 11.2), textColor=col_subhead, splitLongWords=True,
    )
    tbl_num_st = ParagraphStyle(
        'tbl_num', fontName='RagText', fontSize=(7.8 if is_compact else 8.4), leading=10.0, alignment=TA_RIGHT, textColor=col_body,
    )

    pad_v = 2.4 if is_compact else 4.2
    pad_h = 4.5 if is_compact else 6.0

    def make_table(rows_data, col_widths, *, has_header=True):
        t = Table(rows_data, colWidths=col_widths, repeatRows=(1 if has_header else 0), hAlign='LEFT')
        styles = [
            ('GRID', (0, 0), (-1, -1), 0.4, col_border),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), pad_h),
            ('RIGHTPADDING', (0, 0), (-1, -1), pad_h),
            ('TOPPADDING', (0, 0), (-1, -1), pad_v),
            ('BOTTOMPADDING', (0, 0), (-1, -1), pad_v),
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
        st = ParagraphStyle(f'sec_{idx}', parent=sec_st, spaceBefore=(2 if idx == 1 else (7 if is_compact else 13)))
        story.append(Paragraph(f'<a name="sec{idx}"/>{_fmt_raw(m["section_titles"][idx - 1])}', st))

    def add_bullet(text: str):
        story.append(Paragraph(f'• {_fmt_inline(text)}', bullet_st))

    def add_snippet_block(text: str):
        raw = str(text or '').strip()
        if not raw:
            return
        for start in range(0, len(raw), 2200):
            story.append(Paragraph(_fmt_raw(raw[start:start + 2200]), code_st))

    # ==================== HEADER + NAVIGATION + SECTION 1 (PRINTED ONCE ONLY!) ====================
    if is_compact:
        story.append(Paragraph(
            'BÁO CÁO KIỂM THỬ BẢO MẬT CSDL VÀ ĐỀ XUẤT REMEDIATION THEO OWASP',
            cover_title_st,
        ))
        story.append(ObliqueSubtitle(m['subtitle'], width, compact=True))
        toc_links = ' &nbsp;·&nbsp; '.join(
            f'<a href="#sec{idx_s}" color="#1E4E8C">{_fmt_raw(title_s)}</a>'
            for idx_s, title_s in enumerate(m['section_titles'], 1)
        )
        story.append(Paragraph(toc_links, toc_inline_st))
    else:
        story.append(Spacer(1, 28))
        story.append(Paragraph(
            'BÁO CÁO KIỂM THỬ BẢO MẬT CSDL<br/>VÀ ĐỀ XUẤT REMEDIATION THEO OWASP',
            cover_title_st,
        ))
        story.append(ObliqueSubtitle(m['subtitle'], width, compact=False))
        story.append(Paragraph('Mục lục báo cáo (Hồ sơ kiểm toán đầy đủ)', toc_title_st))
        for idx_s, title_s in enumerate(m['section_titles'], 1):
            story.append(Paragraph(f'<a href="#sec{idx_s}" color="#1E4E8C">{_fmt_raw(title_s)}</a>', toc_item_st))
        story.append(PageBreak())

    # 1. Thông tin chung (SINGLE AUTHORITATIVE APPEARANCE — NEVER DUPLICATED!)
    add_sec(1)
    sec1_rows = [
        [Paragraph(_fmt_raw(k), tbl_cell_bold_st), Paragraph(_fmt_inline(v), tbl_cell_st)]
        for k, v in m['general_info']
    ]
    story.extend([make_table(sec1_rows, [width * 0.27, width * 0.73], has_header=False), Spacer(1, 3 if is_compact else 6)])

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
    story.extend([make_table(src_tbl, [width * 0.09, width * 0.29, width * 0.31, width * 0.31]), Spacer(1, 3 if is_compact else 5)])

    qa = m['quality_assessment']
    story.append(Paragraph('2.2. Chất lượng dữ liệu', sub_st))
    add_bullet(f"**Thông tin đã có:** {qa['present']}")
    add_bullet(f"**Thông tin còn thiếu:** {qa['missing']}")
    add_bullet(f"**Giới hạn phân tích:** {qa['analytic_limits']}")

    # 3. Phương pháp phân tích
    add_sec(3)
    meth = m['methodology']
    if is_compact:
        add_bullet(f"**Phương pháp & Công cụ:** {meth['method']} ({meth['tools']})")
        add_bullet(f"**Tài liệu & Tiêu chí:** {meth['references']} {meth['criteria']}")
    else:
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
    rows_to_render = (
        [r for r in m['matrix_rows'] if (r[1] or r[2] or r[3])]
        if (is_compact and any(r[1] or r[2] or r[3] for r in m['matrix_rows']))
        else m['matrix_rows']
    )
    for sev_lbl, c_conf, c_tent, c_insuf in rows_to_render:
        mat_tbl.append([
            Paragraph(_fmt_raw(sev_lbl), tbl_cell_bold_st),
            Paragraph(str(c_conf), tbl_num_st),
            Paragraph(str(c_tent), tbl_num_st),
            Paragraph(str(c_insuf), tbl_num_st),
        ])
    story.append(make_table(mat_tbl, [width * 0.34, width * 0.22, width * 0.22, width * 0.22]))
    story.append(Paragraph(
        'Ghi chú: Chỉ thống kê các phát hiện thực tế từ dữ liệu đầu vào (các mức độ bằng 0 ẩn trên bảng tóm tắt tinh gọn; không tự gán mức độ nghiêm trọng khi công cụ gốc không cung cấp).',
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
        make_table(f_tbl, [width * 0.07, width * 0.22, width * 0.26, width * 0.17, width * 0.14, width * 0.14]),
        Spacer(1, 3 if is_compact else 6),
    ])

    # 6. Phân tích chi tiết phát hiện
    add_sec(6)
    if not m['findings']:
        story.append(Paragraph('Không có phát hiện nào trong dữ liệu đầu vào cần phân tích chi tiết.', body_st))
    for f in m['findings']:
        story.append(Paragraph(_fmt_raw(f"{f['id']}: {f['title']}"), sub_st))
        if is_compact:
            add_bullet(f"**6.1. Trạng thái:** {f['state_detail']} | **6.2. Vị trí:** {f['component']} (`{f['cwe_label']}`)")
        else:
            story.append(Paragraph('6.1. Trạng thái phát hiện', sub2_st))
            add_bullet(f['state_detail'])
            story.append(Paragraph('6.2. Vị trí và thành phần bị ảnh hưởng', sub2_st))
            add_bullet(f"{f['component']} (`{f['cwe_label']}`)")

        story.append(Paragraph('6.3. Bằng chứng', sub2_st))
        if not f['evidences']:
            add_bullet(f"Không có trích đoạn bằng chứng phản hồi chi tiết trong nguồn `{f['source_id']}`.")
        for ev in f['evidences']:
            add_bullet(f"**`{ev['id']}`** (`{ev['source_id']}` — {ev['kind']}): {ev['explanation']}")
            add_snippet_block(ev['snippet'])
        if f['excluded_http_note']:
            add_bullet(f"**Lưu ý lọc nhiễu bằng chứng:** {f['excluded_http_note']}")
        for ai_n in f.get('ai_notes') or []:
            add_bullet(f"**Diễn giải kỹ thuật từ dữ liệu đầu vào:** {ai_n}")

        if is_compact:
            add_bullet(
                f"**6.4. Phân loại OWASP:** `{f['owasp_category']}` ({f['owasp_doc']} {f['owasp_version']} — {f['owasp_url']}) — {f['owasp_reason']}"
            )
            add_bullet(
                f"**6.5. Mức độ nghiêm trọng:** **{f['severity_label']}** — {f['severity_basis']} *Chưa xác định:* {f['unknown_factors']}"
            )
            add_bullet(f"**6.6. Nguyên nhân:** {f['root_cause']}")
            add_bullet(f"**6.7. Ảnh hưởng tiềm tàng:** {f['potential_impact']}")
        else:
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
        if is_compact:
            add_bullet(f"**7.1. Mục tiêu:** {f['rem_goal']}")
            story.append(Paragraph('7.2. Biện pháp đề xuất (Top khuyến nghị OWASP)', sub2_st))
            for st_line in f['rem_steps']:
                add_bullet(st_line)
            for code_ex in f['code_examples']:
                add_bullet(f"**Ví dụ mã an toàn (`{code_ex['section']}`):**")
                add_snippet_block(code_ex['code'])
            add_bullet(
                f"**7.3. Cơ sở OWASP:** Bằng chứng `{', '.join(f['evidence_ids']) or 'Chưa có'}` | Tham chiếu: {ref_str}"
            )
            add_bullet(f"**7.4. Ưu tiên:** {f['priority']}")
            add_bullet(
                f"**7.5. Kế hoạch kiểm tra lại:** {f['retest_check']} ({f['retest_method']}) — "
                f"**Kết quả kiểm tra:** {f['retest_result']} | **Bằng chứng sau khắc phục:** {f['retest_evidence']}"
            )
        else:
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
    if is_compact:
        src_summary = '; '.join(
            f"`{s['id']}` `{s['name']}`" + (f" (SHA-256: `{s['sha256'][:16]}…`)" if s['sha256'] else '')
            for s in m['input_sources']
        )
        ev_summary = '; '.join(
            f"`{ev['id']}`→`{ev['finding_id']}` ({ev['kind']})"
            for ev in m['all_evidences']
        ) or 'Chưa có'
        owasp_summary = '; '.join(
            f"{d['title']} ({d['url']})" for d in m['cited_owasp_docs']
        ) or 'OWASP Top 10:2025 (https://owasp.org/Top10/2025/)'
        add_bullet(f"**10.1. Nguồn đầu vào:** {src_summary}")
        add_bullet(f"**10.2. Danh mục bằng chứng:** {ev_summary}")
        add_bullet(f"**10.3. Tài liệu OWASP đối chiếu:** {owasp_summary}")
        add_bullet(f"**10.4. Kiểm tra lại:** Trạng thái `{m['retest_status']}` — {m['retest_evidence']}")
    else:
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
        canvas.saveState()
        canvas.setFont('RagText', 7.6)
        canvas.setFillColor(col_muted)
        mode_lbl = 'Bản Tinh gọn (Trình bày)' if is_compact else 'Bản Hồ sơ Đầy đủ (Audit)'
        canvas.drawString(margin_x, 16.0 if is_compact else 22.0, f'Báo cáo Kiểm thử Bảo mật CSDL & Đề xuất Remediation theo OWASP · {mode_lbl}')
        canvas.drawRightString(A4[0] - margin_x, 16.0 if is_compact else 22.0, f'Trang {pnum}')
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
