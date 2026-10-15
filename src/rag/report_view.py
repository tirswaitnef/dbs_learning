"""Shared data-driven presentation. No findings, severities or target facts invented."""
import json
from collections import Counter
from pathlib import Path

META_FIELDS={'application':180,'client':180,'prepared_by':180,'assessment_period':180,'classification':80,'roles':1000,'excluded_areas':1000}
MISSING='Không được cung cấp trong đầu vào.'
SEVERITIES=[('critical','Nghiêm trọng'),('high','Cao'),('medium','Trung bình'),('low','Thấp'),('informational','Thông tin'),('unknown','Chưa xác định')]
STATUS_LABELS={'ai_reviewed':'Có diễn giải AI đã qua kiểm tra tự động','rejected_output':'Diễn giải AI chưa đạt kiểm tra','api_error':'Lỗi gọi AI','not_requested':'Không gọi AI'}


def clean_metadata(value):
    if value is None:return {}
    if not isinstance(value,dict) or set(value)-set(META_FIELDS):raise ValueError('Invalid report metadata fields')
    result={}
    for key,text in value.items():
        if not isinstance(text,str) or len(text)>META_FIELDS[key]:raise ValueError('Invalid report metadata value: '+key)
        if text.strip():result[key]=text.strip()
    return result


def attach_context(report,scan_path,format_,metadata=None,display_filename=None):
    base={}
    if format_=='normalized':base=clean_metadata(json.loads(Path(scan_path).read_text(encoding='utf-8-sig')).get('report_metadata'))
    report['report_metadata']={**base,**clean_metadata(metadata)}
    report['input_filename']=display_filename or Path(scan_path).name
    report['input_format']=format_
    report['report_layout_version']='0.10'
    return report


def severity(value):
    s=str(value).lower().strip()
    return {'info':'informational','moderate':'medium','information':'informational'}.get(s,s if s in dict(SEVERITIES) else 'unknown')


def severity_counts(report):return Counter(severity(f.get('severity','unknown')) for f in report['findings'])


def overview(report):
    rows=report['findings'];obs=sum(f.get('kind')=='observation' for f in rows)
    counts=severity_counts(report)
    severity_text=', '.join(f'{label.lower()}: {counts[key]}' for key,label in SEVERITIES if counts[key]) or 'không có bản ghi'
    titles=[]
    for f in rows:
        if f['title'] not in titles:titles.append(f['title'])
    return [f"File kiểm thử: {report.get('input_filename','Không có tên file gốc trong báo cáo cũ')}. Mã đối chiếu: {report.get('scan_sha256','')[:12]}.",
            f"Đầu vào gồm {len(rows)} bản ghi: {len(rows)-obs} cảnh báo và {obs} quan sát. Mức độ do đầu vào cung cấp: {severity_text}.",
            'Các phát hiện được ghi nhận: '+('; '.join(titles[:5]) if titles else 'không có')+(' và các bản ghi khác trong mục 4.' if len(titles)>5 else '.'),
            f"Có {sum(bool(f.get('guidance')) for f in rows)} bản ghi được chọn hướng dẫn OWASP. Không suy ra trạng thái an toàn tổng thể hoặc xác nhận lỗ hổng chỉ từ thống kê này."]


def category_rows(report):
    groups={};unmapped=[]
    for f in report['findings']:
        cats=f.get('owasp_top10',{}).get('categories',[]) if f.get('owasp_top10',{}).get('status')=='in_scope' else []
        if not cats:unmapped.append(f)
        for cat in cats:
            item=groups.setdefault(cat['id'],{'title':cat['title'],'rows':[]})
            item['rows'].append(f)
    order={k:i for i,(k,_) in enumerate(SEVERITIES)}
    result=[]
    for key,item in sorted(groups.items()):
        highest=min((severity(f['severity']) for f in item['rows']),key=lambda s:order[s])
        result.append([item['title'],str(len(item['rows'])),dict(SEVERITIES)[highest]])
    if unmapped:result.append(['Chưa ánh xạ / ngoài bảng / quan sát',str(len(unmapped)),'Giữ mức độ từng bản ghi'])
    return result


def technical_fields(row):
    d=row.get('details') or {};raw=d.get('raw_result') or {};inst=d.get('raw_instance') or {}
    messages=d.get('http_messages') or []
    requests=[m.get('request','') for m in messages if isinstance(m,dict) and m.get('request')]
    if isinstance(raw,dict) and raw.get('request'):requests.append(str(raw['request']))
    method=d.get('method') or inst.get('method') if isinstance(inst,dict) else d.get('method')
    if not method and requests:
        candidate=requests[0].split(' ',1)[0]
        if candidate in {'GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'}:method=candidate
    return {'method':method or MISSING,'parameter':d.get('parameter') or d.get('insertion_point') or MISSING,
            'cvss':str(d.get('cvss_score')) if d.get('cvss_score') not in (None,'') else MISSING,
            'cvss_vector':str(d.get('cvss_vector') or MISSING),'confidence':str(d.get('confidence') or MISSING),
            'description':str(d.get('description') or (d.get('raw_alert') or {}).get('desc') or ''),
            'requests':requests}


def fallback_description(row):
    return (f"{row['tool']} ghi nhận “{row['title']}” tại {row['location']}. "
            f"Phân loại đầu vào: {row['cwe']}; mức độ đầu vào: {row['severity']}. "
            f"Có {len(row.get('evidence',[]))} mục bằng chứng đính kèm.")


def claim_lines(narrative,section):
    if narrative.get('status')!='ai_reviewed':return []
    result=[]
    for c in narrative.get('claims',{}).get(section,[]):
        refs=', '.join(dict.fromkeys(ref['source_id'] for ref in c['citations']))
        result.append(c['text_vi']+' ['+refs+']')
    return result


def references(narrative):
    if narrative.get('status')!='ai_reviewed':return []
    return list(dict.fromkeys((r['source_id'],r['quote']) for claims in narrative.get('claims',{}).values() for c in claims for r in c['citations']))
