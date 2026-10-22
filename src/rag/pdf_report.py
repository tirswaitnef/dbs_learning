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
    from .report_view import (
        MISSING, SEVERITIES, STATUS_LABELS, category_rows, cwe_text,
        defense_layer_label, evidence_profile, extract_scan_context,
        fallback_description, overview, severity_counts, technical_fields,
    )
    from .analysis import narrative_lines
    from .top10 import enforce
    enforce(report)
    fonts=Path(__file__).parent/'fonts'
    for name,filename in [('RagText','DejaVuSans.ttf'),('RagBold','DejaVuSans-Bold.ttf')]:
        if name not in pdfmetrics.getRegisteredFontNames():pdfmetrics.registerFont(TTFont(name,str(fonts/filename)))
    pdfmetrics.registerFontFamily('RagText',normal='RagText',bold='RagBold',italic='RagText',boldItalic='RagBold')
    navy=colors.HexColor('#19364d'); muted=colors.HexColor('#607486'); code_bg=colors.HexColor('#f2f6f9'); accent_bg=colors.HexColor('#e5edf3')
    body=ParagraphStyle('body',fontName='RagText',fontSize=9,leading=13.5,spaceAfter=6,textColor=navy,splitLongWords=True)
    bold_body=ParagraphStyle('bold_body',parent=body,fontName='RagBold',spaceAfter=4)
    title=ParagraphStyle('title',parent=body,fontName='RagBold',fontSize=26,leading=34,spaceAfter=16)
    heading=ParagraphStyle('section',parent=body,fontName='RagBold',fontSize=15,leading=20,spaceBefore=12,spaceAfter=8,keepWithNext=True)
    sub=ParagraphStyle('sub',parent=heading,fontSize=10.5,leading=15,spaceBefore=8,spaceAfter=5)
    small=ParagraphStyle('small',parent=body,fontSize=7.5,leading=10.5,spaceAfter=4,textColor=muted)
    code_style=ParagraphStyle('code',fontName='Courier',fontSize=7.8,leading=11,spaceAfter=6,textColor=navy,backColor=code_bg,borderPadding=6,splitLongWords=True)
    def safe(v):return html.escape(re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',str(v)),quote=True).replace('\n','<br/>')
    story=[]
    def add(v,style=body):story.append(Paragraph(safe(v),style))
    def field(k,v):
        add(k,small)
        evidence(v)
    def evidence(v, mono=False):
        text=str(v)
        st=code_style if mono else body
        for start in range(0,len(text),2200):add(text[start:start+2200],st)
    def section(n,label):
        story.append(CondPageBreak(130))
        p=Paragraph(safe(f'{n}. {label}'),heading);p.toc_label=f'{n}. {label}';story.append(p)
    def table(headers,rows,widths):
        data=[[Paragraph(safe(v),small if i==0 else body) for v in row] for i,row in enumerate([headers]+rows)]
        t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),accent_bg),('VALIGN',(0,0),(-1,-1),'TOP'),('LINEBELOW',(0,0),(-1,0),.7,navy),('LINEBELOW',(0,1),(-1,-1),.3,colors.HexColor('#dbe3e9')),('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]));story.append(t);story.append(Spacer(1,6))
    def kv_table(pairs):
        data=[[Paragraph(safe(k),small),Paragraph(safe(v),body)] for k,v in pairs]
        t=Table(data,colWidths=[width*.24,width*.76],hAlign='LEFT')
        t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('LINEBELOW',(0,0),(-1,-1),.3,colors.HexColor('#dbe3e9')),('BACKGROUND',(0,0),(0,-1),colors.HexColor('#f7fafc')),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]));story.append(t);story.append(Spacer(1,6))

    meta=report.get('report_metadata') or {};rows=report['findings'];width=A4[0]-88
    scan_ctx=report.get('scan_context') or extract_scan_context(report)
    app_cover=meta.get('application') or scan_ctx.get('application_hint') or 'Ứng dụng / hệ thống chưa được cung cấp'
    period_cover=meta.get('assessment_period') or scan_ctx.get('scan_window') or MISSING

    add('AUDITNOTE  /  SECURITY REPORT',small);story.append(Spacer(1,48))
    add('BÁO CÁO PHÂN TÍCH\nKIỂM THỬ BẢO MẬT',title)
    add(app_cover,heading)
    if sample_notice(report):add(sample_notice(report),sub)
    kv_table([
        ('Khách hàng',meta.get('client',MISSING)),
        ('Người lập báo cáo',meta.get('prepared_by',MISSING)),
        ('Thời gian kiểm thử',period_cover),
        ('Thời điểm sinh báo cáo (UTC)',report.get('generated_at',MISSING)),
        ('Phân loại tài liệu',meta.get('classification','Chưa phân loại')),
        ('Chế độ xử lý',report.get('mode',MISSING)),
    ])
    add('Báo cáo tổng hợp & đối chiếu kết quả kiểm thử đầu vào với OWASP Top 10:2025 và OWASP Cheat Sheet Series. AuditNote không tự quét lại mục tiêu.',small)

    story.append(PageBreak());add('MỤC LỤC',heading)
    toc=TableOfContents();toc.levelStyles=[ParagraphStyle('toc',parent=body,leading=18,spaceAfter=2)];story.append(toc);story.append(Spacer(1,14))

    section(1,'Tổng quan điều hành')
    for line in overview(report):add(line)
    if scan_ctx.get('lab'):
        add('Ngữ cảnh mục tiêu nhận diện: '+scan_ctx['lab']['note_vi'])
    if report.get('mode')=='demo-no-ai':add('DEMO: không dùng AI hoặc vector embedding.',sub)
    if report.get('ai_summary'):
        add('Tổng quan AI',sub)
        for line in narrative_lines(report['ai_summary']):evidence(line)
    if not rows:add('Không có phát hiện trong đầu vào; không đồng nghĩa hệ thống an toàn.')

    section(2,'Phạm vi, thông số phiên quét và phương pháp')
    scope_pairs=[
        ('Công cụ & định dạng',(', '.join(sorted({str(r.get('tool','')) for r in rows})) or MISSING)+'  |  '+str(report.get('input_format',MISSING))),
        ('Các vị trí ghi nhận','\n'.join(dict.fromkeys(str(r.get('location',MISSING)) for r in rows)) or MISSING),
    ]
    if scan_ctx.get('auth_context'):
        scope_pairs.append(('Ngữ cảnh xác thực',scan_ctx['auth_context']))
    if scan_ctx.get('telemetry_lines'):
        scope_pairs.append(('Thông số phiên quét','\n'.join(scan_ctx['telemetry_lines'])))
    if scan_ctx.get('db_identity'):
        scope_pairs.append(('Tài khoản & quyền CSDL',scan_ctx['db_identity']))
    if scan_ctx.get('schemas'):
        s_info=scan_ctx['schemas']
        scope_pairs.append(('Schema CSDL trích xuất',f"Ứng dụng: {', '.join(s_info['application']) or 'không có'}  |  Hệ thống DBMS: {', '.join(s_info['system']) or 'không có'}"))
    if scan_ctx.get('tables_by_db'):
        tbl_lines=[f"{dbn}: {', '.join(ts)}" for dbn,ts in scan_ctx['tables_by_db'].items()]
        scope_pairs.append(('Bảng CSDL đã liệt kê','\n'.join(tbl_lines)))
    if scan_ctx.get('eol_notes'):
        scope_pairs.append(('Đối chiếu vòng đời tĩnh (EOL)','\n'.join(scan_ctx['eol_notes'])))
    if scan_ctx.get('repro_gaps'):
        scope_pairs.append(('Giới hạn tái hiện log','\n'.join(scan_ctx['repro_gaps'])))
    if meta.get('roles') or meta.get('excluded_areas'):
        scope_pairs.append(('Vai trò / Ngoài phạm vi',f"{meta.get('roles',MISSING)}  |  {meta.get('excluded_areas',MISSING)}"))
    kv_table(scope_pairs)
    from .db_scope import frame_line, scope_lines
    for line in (report.get('db_scope') or {}).get('lines') or scope_lines(rows):evidence(line)
    probe=report.get('prose_check') or {}
    if probe:
        from .report_variety import prose_line
        add('Kiểm tra trùng lặp văn bản',sub);evidence(prose_line(probe))
    add('Phương pháp: trích xuất dữ kiện và thông số kỹ thuật từ log đầu vào, tách biệt cảnh báo lỗ hổng với quan sát heuristic/dịch vụ, ánh xạ CWE sang OWASP Top 10:2025 và truy xuất hướng dẫn phòng vệ đa lớp từ kho OWASP Cheat Sheet Series.',small)

    section(3,'Tổng hợp phát hiện theo OWASP Top 10:2025')
    table(['Nhóm OWASP Top 10:2025','Số bản ghi','Mức cao nhất từ đầu vào'],category_rows(report) or [['Không có phát hiện','0','Không áp dụng']],[width*.59,width*.14,width*.27])

    section(4,'Chi tiết phát hiện')
    for row in rows:
        story.append(CondPageBreak(160));add(f"{row['id']} — {row['title']}",sub);tech=technical_fields(row);prof=evidence_profile(row)
        row_pairs=[
            ('Vị trí / Endpoint',row.get('location',MISSING)),
            ('Mức độ công cụ / CWE',f"{row.get('severity',MISSING)}  |  {cwe_text(row)}"),
            ('Đánh giá chứng cứ log',f"{prof['label_vi']}\n{prof['note_vi']}"),
            ('Loại bản ghi / Giao thức',f"{row.get('kind',MISSING)} ({row.get('tool',MISSING)})  |  HTTP: {tech['method']}  |  Tham số: {tech['parameter']}"),
            ('OWASP Top 10:2025','; '.join(c['title'] for c in row['owasp_top10']['categories']) or row['owasp_top10']['reason']),
        ]
        if tech['cvss']!=MISSING or tech['cvss_vector']!=MISSING:
            row_pairs.append(('CVSS score / vector',tech['cvss']+' / '+tech['cvss_vector']))
        if row.get('db_frame'):
            row_pairs.append(('Phạm vi CSDL',frame_line(row['db_frame'])))
        kv_table(row_pairs)
        if tech['description']:
            add('Mô tả từ công cụ',sub);evidence(tech['description'])
        if row.get('ai_analysis'):
            add('Diễn giải AI',sub)
            for line in narrative_lines(row['ai_analysis']):evidence(line)
        else:add('Chưa có phân tích AI về tác động; không tự suy ra mức thiệt hại hoặc khả năng khai thác.')
        add('Bằng chứng kiểm thử gốc',sub)
        if not row.get('evidence'):add('Chưa có bằng chứng đính kèm.')
        for i,item in enumerate(row.get('evidence',[]),1):evidence(f"[E{i}]\n{item}",mono=True)
        if tech.get('exchanges') and any(ex.get('response') for ex in tech['exchanges']):
            add('Giao dịch HTTP Request / Response thực tế (Traffic Capture)',sub)
            row_techs=(row.get('details') or {}).get('techniques') or []
            if any('blind' in str(t).lower() for t in row_techs):
                add('Lưu ý đối chiếu kỹ thuật Blind SQLi: với error-based và UNION query, dữ liệu/lỗi SQL hiển thị trực tiếp trong thân HTTP Response; riêng với boolean-based blind và time-based blind, bằng chứng khai thác nằm ở sự khác biệt hành vi phản hồi giữa mệnh đề TRUE/FALSE và độ trễ thời gian phản hồi (RTT) do hàm SLEEP() gây ra so với request nền.',small)
            for idx_ex,ex in enumerate(tech['exchanges'][:6],1):
                if ex.get('request'):evidence(f"[HTTP Request #{idx_ex}]\n{ex['request']}",mono=True)
                if ex.get('response'):evidence(f"[HTTP Response #{idx_ex}]\n{ex['response']}",mono=True)
        elif tech['requests']:
            add('HTTP request từ đầu vào',sub)
            for item in tech['requests']:evidence(item,mono=True)
        add('Khắc phục: '+('Xem hướng dẫn đa lớp tại mục 6, mã '+row['id']+'.' if row.get('guidance') else guidance_reason(row)),small)

    section(5,'Xếp hạng rủi ro & phân tầng chứng cứ')
    counts=severity_counts(report)
    tier_counts={}
    for r in rows:
        lbl=evidence_profile(r)['label_vi'].split(' (',1)[0]
        tier_counts[lbl]=tier_counts.get(lbl,0)+1
    sev_rows=[[label,str(counts[key])] for key,label in SEVERITIES if counts[key]] or [['Không có bản ghi','0']]
    table(['Mức độ gốc do công cụ gán','Số bản ghi'],sev_rows,[width*.75,width*.25])
    if tier_counts:
        table(['Phân tầng độ mạnh chứng cứ kỹ thuật trong log','Số bản ghi'],[[k,str(v)] for k,v in tier_counts.items()],[width*.75,width*.25])
    has_input_cvss=any(technical_fields(r)['cvss']!=MISSING for r in rows)
    if has_input_cvss:
        add('Lưu ý phương pháp chấm điểm: điểm số và vector CVSS hiển thị tại mục 4 được giữ nguyên trực tiếp từ dữ liệu kiểm thử đầu vào cung cấp sẵn kèm ngữ cảnh xác thực phiên (hệ thống và AI không tự tính hay tự gán lại CVSS); các bản ghi còn lại không có CVSS giữ nguyên mức độ gốc do công cụ ghi nhận.',small)
    else:
        add('Lưu ý phương pháp chấm điểm: các công cụ như sqlmap/nmap không xuất điểm CVSS. Khi log thiếu thông tin xác thực (ví dụ PR:N không cần đăng nhập ~9.8 so với PR:L cần cookie phiên đăng nhập như DVWA ~8.8), hệ thống giữ nguyên mức gốc và hiển thị rõ mức độ chứng cứ khai thác thay vì tự bịa con số CVSS sai lệch.',small)

    section(6,'Hướng dẫn khắc phục đa lớp theo OWASP')
    add('Các đoạn dưới đây được trích nguyên văn từ OWASP Cheat Sheet Series (giữ nguyên mã nguồn mẫu và thuật ngữ gốc) nhằm bao phủ phòng vệ theo chiều sâu.',small)
    for row in rows:
        if not row.get('guidance'):continue
        add(f"{row['id']} — {row['title']}",sub)
        for idx_card,card in enumerate(row['guidance'],1):
            layer_title=defense_layer_label(card) if card.get('origin')=='official-corpus-extractive' else 'Thẻ hướng dẫn tham chiếu'
            add(f"{idx_card}) {layer_title}",bold_body)
            is_code_excerpt=str(card.get('guidance_vi','')).lstrip().startswith('```')
            evidence(card['guidance_vi'],mono=is_code_excerpt)
            if card.get('origin')!='official-corpus-extractive':
                evidence(card.get('source_excerpt',MISSING),mono=True)
            loc_str=f"{card['source']} [{card.get('start')}:{card.get('end')}]" if card.get('source') else card.get('title',MISSING)
            add(f"Nguồn OWASP: {card.get('section',MISSING)}  |  {loc_str}\nURL: {card.get('url',MISSING)}",small)
            story.append(Spacer(1,4))
    if not any(r.get('guidance') for r in rows):add('Không có hướng dẫn đủ điều kiện trong lần xử lý này. Lý do theo từng bản ghi nằm tại mục 4.')
    if scan_ctx.get('eol_notes'):
        add('Đối chiếu vòng đời hạ tầng từ banner đầu vào (quy tắc tĩnh trong code, ngoài phạm vi code ứng dụng)',sub)
        for note in scan_ctx['eol_notes']:
            add('• '+note)

    section(7,'Phụ lục và dấu vết xử lý')
    for item in report.get('limitations',[]):add('• '+str(item),small)
    ai_trace=[]
    if report.get('ai_summary'):
        ai_trace.append(f"Tổng quan AI: {STATUS_LABELS.get((report.get('ai_summary') or {}).get('status'),'Không gọi AI')}")
    ai_trace.extend(f"{r['id']}: {STATUS_LABELS.get((r.get('ai_analysis') or {}).get('status'),'Không gọi AI')}" for r in rows)
    kv_table([
        ('File kiểm thử',report.get('input_filename') or MISSING),
        ('SHA-256 kiểm thử',report.get('scan_sha256') or MISSING),
        ('SHA-256 kho hướng dẫn OWASP',report.get('knowledge_sha256') or MISSING),
        ('Model AI',report.get('model') or MISSING),
        ('Trạng thái kiểm tra AI','; '.join(ai_trace) or MISSING),
    ])
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
