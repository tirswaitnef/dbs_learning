"""Data-driven, seven-section PDF report. No AI calls during export."""
import html
import re
from pathlib import Path


def render_pdf(report, path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, Paragraph, PageBreak, Spacer, Table, TableStyle, CondPageBreak
    from reportlab.platypus.tableofcontents import TableOfContents
    from .report_builder import guidance_reason, sample_notice
    from .report_view import MISSING, overview, category_rows, severity_counts, SEVERITIES, technical_fields, fallback_description, STATUS_LABELS
    from .analysis import narrative_lines
    from .top10 import enforce
    enforce(report)
    fonts=Path(__file__).parent/'fonts'
    for name,filename in [('RagText','DejaVuSans.ttf'),('RagBold','DejaVuSans-Bold.ttf')]:
        if name not in pdfmetrics.getRegisteredFontNames():pdfmetrics.registerFont(TTFont(name,str(fonts/filename)))
    pdfmetrics.registerFontFamily('RagText',normal='RagText',bold='RagBold',italic='RagText',boldItalic='RagBold')
    navy=colors.HexColor('#19364d'); muted=colors.HexColor('#607486')
    body=ParagraphStyle('body',fontName='RagText',fontSize=9,leading=14,spaceAfter=7,textColor=navy,splitLongWords=True)
    title=ParagraphStyle('title',parent=body,fontName='RagBold',fontSize=27,leading=36,spaceAfter=20)
    heading=ParagraphStyle('section',parent=body,fontName='RagBold',fontSize=16,leading=22,spaceBefore=14,spaceAfter=12,keepWithNext=True)
    sub=ParagraphStyle('sub',parent=heading,fontSize=11,leading=16,spaceBefore=10,spaceAfter=7)
    small=ParagraphStyle('small',parent=body,fontSize=7.5,leading=11,textColor=muted)
    def safe(v):return html.escape(re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',str(v)),quote=True).replace('\n','<br/>')
    story=[]
    def add(v,style=body):story.append(Paragraph(safe(v),style))
    def field(k,v):
        # Avoid unsplittable oversized metadata paragraphs.
        add(k,small)
        evidence(v)
    def evidence(v):
        text=str(v)
        for start in range(0,len(text),2200):add(text[start:start+2200])
    def section(n,label):
        p=Paragraph(safe(f'{n}. {label}'),heading);p.toc_label=f'{n}. {label}';story.append(p)
    def table(headers,rows,widths):
        data=[[Paragraph(safe(v),small if i else body) for v in row] for i,row in enumerate([headers]+rows)]
        t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e5edf3')),('VALIGN',(0,0),(-1,-1),'TOP'),('LINEBELOW',(0,0),(-1,0),.7,navy),('LINEBELOW',(0,1),(-1,-1),.3,colors.HexColor('#dbe3e9')),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]));story.append(t)
    meta=report.get('report_metadata') or {};rows=report['findings'];width=A4[0]-88
    add('AUDITNOTE  /  SECURITY REPORT',small);story.append(Spacer(1,62))
    add('BÁO CÁO PHÂN TÍCH\nKIỂM THỬ BẢO MẬT',title)
    add(meta.get('application','Ứng dụng / hệ thống chưa được cung cấp'),heading)
    if sample_notice(report):add(sample_notice(report),sub)
    for k,v in [('Khách hàng',meta.get('client',MISSING)),('Người lập báo cáo',meta.get('prepared_by',MISSING)),('Thời gian kiểm thử',meta.get('assessment_period',MISSING)),('Thời điểm sinh báo cáo (UTC)',report.get('generated_at',MISSING)),('Phân loại tài liệu',meta.get('classification','Chưa phân loại')),('Chế độ xử lý',report.get('mode',MISSING))]:field(k,v)
    add('Báo cáo phân tích kết quả được cung cấp. AuditNote không thực hiện kiểm thử lại hoặc xác nhận độc lập lỗ hổng.',small)
    story.append(PageBreak());add('MỤC LỤC',title)
    toc=TableOfContents();toc.levelStyles=[ParagraphStyle('toc',parent=body,leading=23)];story.append(toc)
    story.append(PageBreak());section(1,'Tổng quan điều hành')
    for line in overview(report):add(line)
    if report.get('mode')=='demo-no-ai':add('DEMO: không dùng AI hoặc vector embedding.',sub)
    if report.get('ai_summary'):
        add('Tổng quan AI',sub)
        for line in narrative_lines(report['ai_summary']):evidence(line)
    if not rows:add('Không có phát hiện trong đầu vào; không đồng nghĩa hệ thống an toàn.')
    section(2,'Phạm vi và phương pháp')
    field('Công cụ trong đầu vào',', '.join(sorted({str(r.get('tool','')) for r in rows})) or MISSING)
    field('Định dạng kiểm thử',report.get('input_format',MISSING))
    field('Các vị trí được ghi nhận','\n'.join(dict.fromkeys(str(r.get('location',MISSING)) for r in rows)) or MISSING)
    field('Vai trò / tài khoản kiểm thử',meta.get('roles',MISSING));field('Ngoài phạm vi',meta.get('excluded_areas',MISSING))
    add('Phương pháp: đọc kết quả công cụ, giữ bằng chứng, ánh xạ CWE được cung cấp với OWASP Top 10:2025, phân tích và chọn hướng dẫn có nguồn. Danh sách vị trí ở trên không chứng minh đã kiểm thử đầy đủ ứng dụng hoặc toàn bộ OWASP Top 10.')
    section(3,'Tổng hợp phát hiện theo OWASP')
    table(['Nhóm OWASP Top 10:2025','Số bản ghi','Mức cao nhất từ đầu vào'],category_rows(report) or [['Không có phát hiện','0','Không áp dụng']],[width*.59,width*.14,width*.27])
    add('Một CWE có thể thuộc nhiều nhóm; tổng các nhóm không nhất thiết bằng số bản ghi. Mức độ được giữ theo đầu vào, không suy ra từ tên lỗ hổng.',small)
    story.append(PageBreak());section(4,'Chi tiết phát hiện')
    for row in rows:
        story.append(CondPageBreak(180));add(f"{row['id']} — {row['title']}",sub);tech=technical_fields(row)
        for label,value in [('Vị trí / URL',row.get('location',MISSING)),('Mức độ / CWE',f"{row.get('severity',MISSING)} / {row.get('cwe',MISSING)}"),('Loại bản ghi / công cụ',f"{row.get('kind',MISSING)} / {row.get('tool',MISSING)}"),('HTTP method / tham số',tech['method']+' / '+str(tech['parameter'])),('CVSS score / vector',tech['cvss']+' / '+tech['cvss_vector'])]:field(label,value)
        field('OWASP Top 10:2025','; '.join(c['title'] for c in row['owasp_top10']['categories']) or row['owasp_top10']['reason'])
        add('Mô tả phát hiện',sub);evidence(tech['description'] or fallback_description(row))
        if row.get('ai_analysis'):
            add('Diễn giải AI',sub)
            for line in narrative_lines(row['ai_analysis']):evidence(line)
        else:add('Chưa có phân tích AI về tác động; không tự suy ra mức thiệt hại hoặc khả năng khai thác.')
        add('Bằng chứng kiểm thử',sub)
        if not row.get('evidence'):add('Chưa có bằng chứng đính kèm.')
        for i,item in enumerate(row.get('evidence',[]),1):field(f'E{i}',item)
        if tech['requests']:
            add('HTTP request từ đầu vào',sub)
            for item in tech['requests']:evidence(item)
        add('Khắc phục',sub)
        add('Xem hướng dẫn và nguồn tại mục 6, mã '+row['id']+'.' if row.get('guidance') else guidance_reason(row))
    section(5,'Xếp hạng rủi ro')
    counts=severity_counts(report);table(['Mức độ do kiểm thử cung cấp','Số bản ghi'],[[label,str(counts[key])] for key,label in SEVERITIES],[width*.75,width*.25])
    add('Không tự tính CVSS khi thiếu vector hoặc thông tin cần thiết. Không mặc định mọi SQL Injection có cùng mức độ. Các cảnh báo cần được xác minh độc lập trước khi coi là lỗ hổng đã được chứng minh.')
    story.append(PageBreak());section(6,'Hướng dẫn khắc phục')
    add('Chỉ các bản ghi có ánh xạ trực tiếp trong OWASP Top 10:2025, có bằng chứng và hướng dẫn được chọn mới xuất hiện dưới đây. Nội dung nguyên văn giữ ngôn ngữ nguồn.')
    for row in rows:
        if not row.get('guidance'):continue
        add(f"{row['id']} — {row['title']}",sub)
        for card in row['guidance']:
            if card.get('origin')=='official-corpus-extractive':
                add('Trích nguyên văn OWASP',small);evidence(card['guidance_vi'])
            else:
                add('Thẻ hướng dẫn cũ / demo — không coi là trích nguyên văn OWASP',small);evidence(card['guidance_vi'])
                field('Trích đoạn được lưu',card.get('source_excerpt',MISSING))
            for label,key in [('Điều kiện áp dụng','applicability_vi'),('Tài liệu nguồn','title'),('URL nguồn','url'),('Mục','section')]:field(label,card.get(key,MISSING))
            if card.get('source'):field('Vị trí nguồn',f"{card['source']} | ký tự {card.get('start')}:{card.get('end')}")
    if not any(r.get('guidance') for r in rows):add('Không có hướng dẫn đủ điều kiện trong lần xử lý này. Lý do theo từng bản ghi nằm tại mục 4.')
    section(7,'Phụ lục và dấu vết xử lý')
    for item in report.get('limitations',[]):evidence(item)
    for label,key in [('File kiểm thử','input_filename'),('SHA-256 kiểm thử','scan_sha256'),('SHA-256 kho hướng dẫn','knowledge_sha256'),('Model AI','model')]:field(label,report.get(key) or MISSING)
    for row in rows:
        a=row.get('ai_analysis') or {};add(f"{row['id']}: {STATUS_LABELS.get(a.get('status'),a.get('status','Không gọi AI'))}",small)
    add('Kiểm tra tự động nguồn và diễn giải không bảo đảm phát hiện là đúng hoặc loại bỏ hoàn toàn sai sót của AI.',small)
    def footer(canvas,doc):
        canvas.setStrokeColor(colors.HexColor('#dbe3e9'));canvas.line(44,39,A4[0]-44,39)
        canvas.setFont('RagText',7);canvas.setFillColor(muted);canvas.drawString(44,25,'AUDITNOTE | '+str(report.get('scan_sha256',''))[:12]);canvas.drawRightString(A4[0]-44,25,f'Trang {doc.page}')
    class ReportDoc(BaseDocTemplate):
        def afterFlowable(self,flowable):
            if hasattr(flowable,'toc_label'):self.notify('TOCEntry',(0,flowable.toc_label,self.page))
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    doc=ReportDoc(str(path),pagesize=A4,leftMargin=44,rightMargin=44,topMargin=44,bottomMargin=55,title='Báo cáo phân tích kiểm thử bảo mật',author='AuditNote')
    doc.addPageTemplates(PageTemplate(id='report',frames=[Frame(44,55,width,A4[1]-99,id='main',leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0)],onPage=footer))
    doc.multiBuild(story)
    return path
