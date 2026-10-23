"""Clean Unicode PDF renderer for Pentest Reports.

Default mode (`profile='compact'`) renders strictly according to `Template báo cáo pentest gọn.pdf`:
  - Editorial serif headings (`DejaVuSerif` / `DejaVuSerif-Bold`), crisp sans body & tables (`DejaVuSans` / `DejaVuSans-Bold`),
    and clean monospace evidence/code blocks (`DejaVuSansMono`).
  - Exact warm neutral palette (`#1F1E1D` ink, `#52514E` muted labels, `#6B6B6B` running header/footer,
    `#F5F3ED` table header/key fill, `#F3F1EC` code fill, `#E8E5DC` hairline grid).
  - Exact 6-section structure (`1. Tóm tắt` -> `6. Phụ lục`) with `Page X of Y` footer via two-pass canvas
    and `"Quy tắc điền"` omitted upon export.

Secondary mode (`profile='full'`) renders the 10-section full audit archive (`render_full_audit_pdf`).
"""
from __future__ import annotations

from pathlib import Path
import re

from reportlab import platypus
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    KeepTogether,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from xml.sax.saxutils import escape as xml_escape

from .compact_pentest_template import prepare_compact_pentest
from .full_audit_pdf import render_full_audit_pdf

# Exact warm editorial color palette extracted from `Template báo cáo pentest gọn.pdf`
INK_PRIMARY = colors.HexColor('#1F1E1D')
INK_LABEL = colors.HexColor('#52514E')
INK_MUTED = colors.HexColor('#6B6B6B')
FILL_TABLE_HEAD = colors.HexColor('#F5F3ED')
FILL_CODE = colors.HexColor('#F3F1EC')
BORDER_HAIRLINE = colors.HexColor('#E8E5DC')

_FONT_REGISTERED = False
FONT_REG = 'DejaVuSans'
FONT_BOLD = 'DejaVuSans-Bold'
FONT_SERIF = 'DejaVuSerif'
FONT_SERIF_BOLD = 'DejaVuSerif-Bold'
FONT_MONO = 'DejaVuSansMono'


def _para(text: str, style):
    """Lookup `platypus.Paragraph` dynamically so unit-test spies on `reportlab.platypus.Paragraph` work cleanly."""
    return platypus.Paragraph(text, style)


def _register_unicode_fonts() -> tuple[str, str]:
    global _FONT_REGISTERED, FONT_REG, FONT_BOLD, FONT_SERIF, FONT_SERIF_BOLD, FONT_MONO
    if _FONT_REGISTERED:
        return FONT_REG, FONT_BOLD

    pkg_fonts = Path(__file__).resolve().parent / 'fonts'
    sys_dejavu = Path('/usr/share/fonts/truetype/dejavu')

    def _find_ttf(filename: str) -> Path | None:
        for base in (pkg_fonts, sys_dejavu):
            p = base / filename
            if p.is_file():
                return p
        return None

    sans_pair = (_find_ttf('DejaVuSans.ttf'), _find_ttf('DejaVuSans-Bold.ttf'))
    if sans_pair[0] and sans_pair[1]:
        pdfmetrics.registerFont(TTFont('DejaVuSans', str(sans_pair[0])))
        pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', str(sans_pair[1])))
        pdfmetrics.registerFontFamily('DejaVuSans', normal='DejaVuSans', bold='DejaVuSans-Bold')
        FONT_REG, FONT_BOLD = 'DejaVuSans', 'DejaVuSans-Bold'
    else:
        win_fonts = Path('C:/Windows/Fonts')
        if (win_fonts / 'arial.ttf').is_file() and (win_fonts / 'arialbd.ttf').is_file():
            pdfmetrics.registerFont(TTFont('ArialUnicode', str(win_fonts / 'arial.ttf')))
            pdfmetrics.registerFont(TTFont('ArialUnicode-Bold', str(win_fonts / 'arialbd.ttf')))
            pdfmetrics.registerFontFamily('ArialUnicode', normal='ArialUnicode', bold='ArialUnicode-Bold')
            FONT_REG, FONT_BOLD = 'ArialUnicode', 'ArialUnicode-Bold'
        else:
            FONT_REG, FONT_BOLD = 'Helvetica', 'Helvetica-Bold'

    serif_pair = (_find_ttf('DejaVuSerif.ttf'), _find_ttf('DejaVuSerif-Bold.ttf'))
    if serif_pair[0] and serif_pair[1]:
        pdfmetrics.registerFont(TTFont('DejaVuSerif', str(serif_pair[0])))
        pdfmetrics.registerFont(TTFont('DejaVuSerif-Bold', str(serif_pair[1])))
        pdfmetrics.registerFontFamily('DejaVuSerif', normal='DejaVuSerif', bold='DejaVuSerif-Bold')
        FONT_SERIF, FONT_SERIF_BOLD = 'DejaVuSerif', 'DejaVuSerif-Bold'
    else:
        FONT_SERIF, FONT_SERIF_BOLD = FONT_REG, FONT_BOLD

    mono_path = _find_ttf('DejaVuSansMono.ttf')
    if mono_path:
        pdfmetrics.registerFont(TTFont('DejaVuSansMono', str(mono_path)))
        FONT_MONO = 'DejaVuSansMono'
    else:
        FONT_MONO = FONT_REG

    _FONT_REGISTERED = True
    return FONT_REG, FONT_BOLD


def _mono_run(raw_text: str, mono_font: str, sans_font: str, size: str = '8.2') -> str:
    """Render ASCII code runs in crisp `DejaVuSansMono` and non-ASCII Unicode runs in `DejaVuSans` cleanly."""
    if not raw_text:
        return ''
    out: list[str] = []
    i = 0
    n = len(raw_text)
    while i < n:
        if ord(raw_text[i]) < 128:
            j = i + 1
            while j < n and ord(raw_text[j]) < 128:
                j += 1
            seg = xml_escape(raw_text[i:j]).replace('  ', '&nbsp;&nbsp;')
            out.append(f'<font name="{mono_font}" size="{size}">{seg}</font>')
            i = j
        else:
            j = i + 1
            while j < n and ord(raw_text[j]) >= 128:
                j += 1
            seg = xml_escape(raw_text[i:j])
            out.append(f'<font name="{sans_font}" size="{size}">{seg}</font>')
            i = j
    return ''.join(out)


def _md_inline_to_rl(text: str, bold_font: str | None = None, code_font: str | None = None) -> str:
    """Convert inline `**bold**` and `` `code` `` safely into ReportLab XML markup without losing Vietnamese glyphs."""
    bf = bold_font or FONT_BOLD
    cf = code_font or FONT_MONO
    sf = FONT_REG
    raw = str(text or '')
    parts = re.split(r'(`[^`]+`)', raw)
    rendered: list[str] = []
    for part in parts:
        if len(part) >= 2 and part.startswith('`') and part.endswith('`'):
            rendered.append(_mono_run(part[1:-1], cf, sf, '8.3'))
        else:
            esc = xml_escape(part)
            esc = re.sub(r'\*\*([^*]+)\*\*', rf'<font name="{bf}">\1</font>', esc)
            rendered.append(esc)
    return ''.join(rendered)


def _make_numbered_canvas_factory(running_header: str, reg_font: str):
    """Two-pass ReportLab canvas rendering running header (page >= 2) and exact 'Page X of Y' footer."""

    class _TemplateNumberedCanvas(rl_canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states: list[dict] = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self._draw_chrome(total_pages)
                super().showPage()
            super().save()

        def _draw_chrome(self, total_pages: int):
            self.saveState()
            page_w, page_h = A4
            margin_x = 18 * mm
            self.setFont(reg_font, 8.2)
            self.setFillColor(INK_MUTED)
            if self._pageNumber >= 2:
                self.drawString(margin_x, page_h - 12.5 * mm, running_header[:92])
            footer_txt = f"Page {self._pageNumber} of {total_pages}"
            self.drawCentredString(page_w / 2.0, 10.5 * mm, footer_txt)
            self.restoreState()

    return _TemplateNumberedCanvas


def _render_compact_template_pdf(report: dict, out_file: Path) -> Path:
    """Render exact `Template báo cáo pentest gọn.pdf` layout (6 sections, 2–3 pages, warm editorial theme)."""
    reg_font, bold_font = _register_unicode_fonts()
    m = prepare_compact_pentest(report)

    s_title = ParagraphStyle(
        'CompactDocTitle',
        fontName=FONT_SERIF,
        fontSize=15.5,
        leading=20.0,
        textColor=INK_PRIMARY,
        spaceBefore=0,
        spaceAfter=9,
    )
    s_h1 = ParagraphStyle(
        'CompactH1',
        fontName=FONT_SERIF,
        fontSize=12.2,
        leading=16.0,
        textColor=INK_PRIMARY,
        spaceBefore=11,
        spaceAfter=5,
        keepWithNext=True,
    )
    s_h2 = ParagraphStyle(
        'CompactFindingH2',
        fontName=FONT_SERIF,
        fontSize=10.8,
        leading=14.2,
        textColor=INK_PRIMARY,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    )
    s_body = ParagraphStyle(
        'CompactBody',
        fontName=reg_font,
        fontSize=9.2,
        leading=13.4,
        textColor=INK_PRIMARY,
        spaceAfter=4,
    )
    s_label_line = ParagraphStyle(
        'CompactLabelLine',
        fontName=bold_font,
        fontSize=9.2,
        leading=13.0,
        textColor=INK_PRIMARY,
        spaceBefore=2,
        spaceAfter=2.5,
        keepWithNext=True,
    )
    s_bullet = ParagraphStyle(
        'CompactBullet',
        fontName=reg_font,
        fontSize=9.0,
        leading=13.0,
        textColor=INK_PRIMARY,
        leftIndent=10,
        firstLineIndent=-7,
        spaceAfter=2.5,
    )
    s_th = ParagraphStyle(
        'CompactTH',
        fontName=bold_font,
        fontSize=8.4,
        leading=11.2,
        textColor=INK_LABEL,
    )
    s_key = ParagraphStyle(
        'CompactKeyCell',
        fontName=bold_font,
        fontSize=8.4,
        leading=11.4,
        textColor=INK_LABEL,
    )
    s_td = ParagraphStyle(
        'CompactTD',
        fontName=reg_font,
        fontSize=8.5,
        leading=11.6,
        textColor=INK_PRIMARY,
        wordWrap='CJK',
    )
    s_code = ParagraphStyle(
        'CompactMono',
        fontName=FONT_MONO,
        fontSize=7.7,
        leading=10.4,
        textColor=INK_PRIMARY,
        wordWrap='CJK',
    )

    page_w = A4[0] - 36 * mm
    doc = SimpleDocTemplate(
        str(out_file),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=17.5 * mm,
        bottomMargin=16.5 * mm,
        title=m['doc_title'],
        author='Pentest Report Assistant',
    )

    story: list = []

    # Title + 7-row Metadata Header Card (matches Page 1 top of `Template báo cáo pentest gọn.pdf`)
    story.append(_para(xml_escape(m['doc_title']), s_title))

    meta_rows = [
        [_para(xml_escape(k), s_key), _para(_md_inline_to_rl(v, bold_font), s_td)]
        for k, v in m['header_rows']
    ]
    meta_tbl = Table(meta_rows, colWidths=[38 * mm, page_w - 38 * mm])
    meta_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), FILL_TABLE_HEAD),
        ('BACKGROUND', (1, 0), (1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_HAIRLINE),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_tbl)

    # 1. Tóm tắt (3–5 line summary + 6-column table)
    story.append(_para('1. Tóm tắt', s_h1))
    story.append(_para(_md_inline_to_rl(m['summary_text'], bold_font), s_body))
    story.append(Spacer(1, 1.5 * mm))

    sum_header = [_para(h, s_th) for h in ('ID', 'Phát hiện', 'Thành phần', 'OWASP / CWE', 'Mức độ', 'Trạng thái')]
    sum_rows = [sum_header]
    if not m['findings']:
        sum_rows.append([
            _para('—', s_td),
            _para('Không ghi nhận lỗ hổng trong phạm vi quét', s_td),
            _para('—', s_td),
            _para('Chưa xác định', s_td),
            _para('Chưa xác định', s_td),
            _para('Không xác nhận được', s_td),
        ])
    else:
        for f in m['findings']:
            sum_rows.append([
                _para(xml_escape(f['id']), s_td),
                _para(_md_inline_to_rl(f['title'], bold_font), s_td),
                _para(_md_inline_to_rl(f['component'], bold_font), s_td),
                _para(xml_escape(f['owasp_cwe_short']), s_td),
                _para(xml_escape(f['severity_label']), s_td),
                _para(xml_escape(f['state']), s_td),
            ])

    sum_col_w = [12 * mm, 41 * mm, 44 * mm, 29 * mm, 24 * mm, page_w - 150 * mm]
    sum_tbl = Table(sum_rows, colWidths=sum_col_w, repeatRows=1)
    sum_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), FILL_TABLE_HEAD),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_HAIRLINE),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4.5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4.5),
    ]))
    story.append(sum_tbl)

    # 2. Chi tiết phát hiện
    story.append(_para('2. Chi tiết phát hiện', s_h1))
    if not m['findings']:
        story.append(_para('Không có phát hiện lỗ hổng cần phân tích chi tiết trong dữ liệu đầu vào.', s_body))

    def _code_box(raw_code: str) -> Table:
        html_lines: list[str] = []
        for raw_ln in str(raw_code or '').splitlines()[:10]:
            ln = raw_ln.rstrip()
            html_lines.append(_mono_run(ln, FONT_MONO, reg_font, '7.7'))
        box = Table([[_para('<br/>'.join(html_lines), s_code)]], colWidths=[page_w])
        box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), FILL_CODE),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_HAIRLINE),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        return box

    for f in m['findings']:
        f_head = _para(xml_escape(f"{f['id']}: {f['title']}"), s_h2)
        f_meta_rows = [
            [_para('Mức độ / CVSS', s_key), _para(_md_inline_to_rl(f['sev_cvss_display'], bold_font), s_td)],
            [_para('OWASP / CWE', s_key), _para(_md_inline_to_rl(f['owasp_cwe_full'], bold_font), s_td)],
            [_para('Thành phần', s_key), _para(_md_inline_to_rl(f['component'], bold_font), s_td)],
            [_para('Trạng thái', s_key), _para(xml_escape(f['state']), s_td)],
        ]
        f_meta_tbl = Table(f_meta_rows, colWidths=[34 * mm, page_w - 34 * mm])
        f_meta_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), FILL_TABLE_HEAD),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_HAIRLINE),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5.5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5.5),
        ]))
        story.append(KeepTogether([f_head, f_meta_tbl, Spacer(1, 1.5 * mm)]))

        story.append(_para(
            f'<font name="{bold_font}">Mô tả:</font> {_md_inline_to_rl(f["description"], bold_font)}',
            s_body,
        ))

        story.append(_para('Bằng chứng (tối đa 2):', s_label_line))
        if not f['evidences']:
            story.append(_para('• Không có trích đoạn phản hồi trực tiếp trong dữ liệu đầu vào.', s_bullet))
        else:
            for ev in f['evidences']:
                story.append(_code_box(ev['code']))
                story.append(Spacer(1, 1.5 * mm))

        story.append(_para(
            f'<font name="{bold_font}">Tác động:</font> {_md_inline_to_rl(f["impact"], bold_font)}',
            s_body,
        ))
        story.append(_para(
            f'<font name="{bold_font}">Khắc phục:</font> {_md_inline_to_rl(f["remediation"], bold_font)}',
            s_body,
        ))
        if f['code_example']:
            story.append(_code_box(f['code_example']))
            story.append(Spacer(1, 1 * mm))

        story.append(_para(
            f'<font name="{bold_font}">Nguồn:</font> {xml_escape(f["remediation_source_title"])} — '
            f'<font name="{FONT_MONO}" size="7.8">{xml_escape(f["remediation_source_url"])}</font>',
            s_body,
        ))
        story.append(_para(
            f'<font name="{bold_font}">Retest:</font> {xml_escape(f["retest"])}',
            s_body,
        ))

    # 3. Quan sát (chưa phải lỗ hổng)
    story.append(_para('3. Quan sát (chưa phải lỗ hổng)', s_h1))
    obs_header = [_para(h, s_th) for h in ('Dịch vụ', 'Vị trí', 'Quan sát', 'Ghi chú')]
    obs_rows = [obs_header]
    if not m['observations']:
        obs_rows.append([
            _para('—', s_td),
            _para('—', s_td),
            _para('Không ghi nhận banner/cổng mở thụ động riêng', s_td),
            _para('—', s_td),
        ])
    else:
        for ob in m['observations']:
            obs_rows.append([
                _para(xml_escape(ob['service']), s_td),
                _para(xml_escape(ob['location']), s_td),
                _para(xml_escape(ob['observation']), s_td),
                _para(xml_escape(ob['note']), s_td),
            ])
    obs_col_w = [22 * mm, 38 * mm, 52 * mm, page_w - 112 * mm]
    obs_tbl = Table(obs_rows, colWidths=obs_col_w, repeatRows=1)
    obs_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), FILL_TABLE_HEAD),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_HAIRLINE),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(obs_tbl)

    # 4. Kết quả âm tính
    story.append(_para('4. Kết quả âm tính', s_h1))
    for neg in m['negative_results']:
        story.append(_para(f'• {_md_inline_to_rl(neg, bold_font)}', s_bullet))

    # 5. Giới hạn & việc cần xác minh
    story.append(_para('5. Giới hạn & việc cần xác minh', s_h1))
    for lim in m['limitations_and_verify']:
        story.append(_para(f'• {_md_inline_to_rl(lim, bold_font)}', s_bullet))

    # 6. Phụ lục
    app = m['appendix']
    story.append(_para('6. Phụ lục', s_h1))
    story.append(_para(
        f'• <font name="{bold_font}">Lệnh đã chạy:</font> {_mono_run(app["command"], FONT_MONO, reg_font, "8.2")}',
        s_bullet,
    ))
    story.append(_para(
        f'• <font name="{bold_font}">Dữ liệu đầu vào:</font> {_mono_run(app["input_data"], FONT_MONO, reg_font, "8.2")}',
        s_bullet,
    ))
    story.append(_para(
        f'• <font name="{bold_font}">Bằng chứng đầy đủ:</font> {_md_inline_to_rl(app["full_evidence"], bold_font)}',
        s_bullet,
    ))

    doc.build(story, canvasmaker=_make_numbered_canvas_factory(m['running_header'], reg_font))
    return out_file


def render_pdf(report: dict, path, profile: str | None = None) -> Path:
    """Render report PDF:
    - Default (`profile='compact'`): exact 6-section `Template báo cáo pentest gọn.pdf` layout (2–3 pages).
    - Secondary (`profile='full'`): full 10-section audit archive (`render_full_audit_pdf`).
    """
    out_file = Path(path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    eff_profile = str(
        profile
        or ((report.get('report_metadata') or {}).get('report_profile'))
        or 'compact'
    ).strip().lower()
    if eff_profile == 'full':
        return Path(render_full_audit_pdf(report, out_file, profile='full'))
    return _render_compact_template_pdf(report, out_file)
