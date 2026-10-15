"""Deterministic scope gate. Never infer category from an LLM, title or similarity."""
import json
import re
from functools import lru_cache
from pathlib import Path

@lru_cache(maxsize=1)
def mapping():
    data=json.loads((Path(__file__).parent/'data/top10-2025.json').read_text(encoding='utf-8'))
    if data['version']!='2025' or {c['id'] for c in data['categories']}!={f'A{i:02}:2025' for i in range(1,11)}:
        raise ValueError('Invalid OWASP scope mapping')
    return data


def classify(finding):
    cwe=finding.cwe if hasattr(finding,'cwe') else finding.get('cwe','unknown')
    kind=finding.kind if hasattr(finding,'kind') else finding.get('kind','scanner_alert')
    data=mapping()
    result={'version':'2025','cwe':cwe,'categories':[], 'mapping_commit':data['commit'],
            'basis':'Exact CWE membership in OWASP List of Mapped CWEs; CWE is supplied by input, not independently verified.'}
    if kind=='observation':
        return {**result,'status':'observation','reason':'Quan sát dịch vụ; chưa phải phát hiện lỗ hổng để đề xuất khắc phục.'}
    if not isinstance(cwe,str) or not re.fullmatch(r'CWE-[1-9]\d*',cwe):
        return {**result,'status':'unknown','reason':'Chưa xác định CWE duy nhất từ kiểm thử; chưa đủ căn cứ phân loại OWASP Top 10:2025.'}
    result['categories']=[{'id':c['id'],'title':c['title'],'url':c['url']} for c in data['categories'] if cwe in c['cwes']]
    if not result['categories']:
        return {**result,'status':'unmapped','reason':'CWE không nằm trong bảng ánh xạ trực tiếp OWASP Top 10:2025 của project. Không đề xuất khắc phục; cần xác minh phạm vi. Không suy ra chắc chắn ngoài mọi nhóm Top 10.'}
    return {**result,'status':'in_scope','reason':'Có ánh xạ trực tiếp CWE trong OWASP Top 10:2025; đây không phải xác nhận lỗ hổng thực tế.'}


def allowed(finding):
    return classify(finding)['status']=='in_scope'


def enforce(report):
    """Run even when exporting a legacy report JSON; block old/injected guidance."""
    for row in report['findings']:
        scope=classify(row)
        row['owasp_top10']=scope
        if scope['status']!='in_scope' or not row.get('evidence'):
            row['guidance']=[]
            row['status']='scope_blocked' if scope['status']!='in_scope' else 'missing_evidence'
            row['guidance_reason']=scope['reason'] if scope['status']!='in_scope' else 'Thiếu bằng chứng kiểm thử đính kèm; chưa chọn hướng dẫn khắc phục.'
    report['scope_policy']={'name':'OWASP Top 10 Web Application Security','version':'2025',
                            'mapping_commit':mapping()['commit'],'rule':'Only directly mapped CWEs with input evidence may receive OWASP remediation. All other findings remain in the report.'}
    return report
