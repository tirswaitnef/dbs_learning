"""Deterministic scope gate. Never infer category from an LLM, title or similarity."""
import json
import re
from functools import lru_cache
from pathlib import Path

CWE_ID = re.compile(r'CWE-[1-9]\d*')


@lru_cache(maxsize=1)
def mapping():
    data=json.loads((Path(__file__).parent/'data/top10-2025.json').read_text(encoding='utf-8'))
    if data['version']!='2025' or {c['id'] for c in data['categories']}!={f'A{i:02}:2025' for i in range(1,11)}:
        raise ValueError('Invalid OWASP scope mapping')
    return data


def _field(finding, key, default=None):
    return finding.get(key, default) if isinstance(finding, dict) else getattr(finding, key, default)


def finding_cwes(finding):
    """CWEs supplied by the input. Never derived from titles or similarity.

    A single valid ``cwe`` wins. Otherwise the tool's full list in ``details['cwes']``
    (Burp, Nuclei and Nessus can attach several CWEs to one issue). A malformed list is
    treated as absent, so the finding stays out of scope.
    """
    cwe = _field(finding, 'cwe', 'unknown')
    if isinstance(cwe, str) and CWE_ID.fullmatch(cwe):
        return [cwe]
    details = _field(finding, 'details') or {}
    values = details.get('cwes') if isinstance(details, dict) else None
    if not isinstance(values, list) or not values:
        return []
    if any(not isinstance(value, str) or not CWE_ID.fullmatch(value) for value in values):
        return []
    return list(dict.fromkeys(values))


def cwe_label(finding, missing='unknown'):
    cwes = finding_cwes(finding)
    return ', '.join(cwes) if cwes else missing


def _category(c):
    return {'id': c['id'], 'title': c['title'], 'url': c['url']}


def classify(finding):
    cwe = _field(finding, 'cwe', 'unknown')
    kind = _field(finding, 'kind', 'scanner_alert')
    cwes = finding_cwes(finding)
    data = mapping()
    result = {'version': '2025', 'cwe': cwe, 'cwes': cwes, 'categories': [], 'mapping_commit': data['commit'],
              'basis': 'Exact CWE membership in OWASP List of Mapped CWEs; CWE is supplied by input, not independently verified.'}
    if kind == 'observation':
        return {**result, 'status': 'observation', 'reason': 'Quan sát dịch vụ; chưa phải phát hiện lỗ hổng để đề xuất khắc phục.'}
    if not cwes:
        return {**result, 'status': 'unknown', 'reason': 'Chưa xác định CWE duy nhất từ kiểm thử; chưa đủ căn cứ phân loại OWASP Top 10:2025.'}
    if len(cwes) == 1:
        result['categories'] = [_category(c) for c in data['categories'] if cwes[0] in c['cwes']]
        if not result['categories']:
            return {**result, 'status': 'unmapped', 'reason': 'CWE không nằm trong bảng ánh xạ trực tiếp OWASP Top 10:2025 của project. Không đề xuất khắc phục; cần xác minh phạm vi. Không suy ra chắc chắn ngoài mọi nhóm Top 10.'}
        return {**result, 'status': 'in_scope', 'reason': 'Có ánh xạ trực tiếp CWE trong OWASP Top 10:2025; đây không phải xác nhận lỗ hổng thực tế.'}
    # Several CWEs from the tool (Burp lists CWE-89, CWE-94, CWE-116 for SQL injection).
    # None is picked or dropped: the finding is in scope only if every CWE sits in one category.
    result['basis'] = ('Every CWE supplied by input is directly mapped to the same OWASP Top 10:2025 category; '
                       'no CWE is chosen or dropped. CWEs are supplied by input, not independently verified.')
    listed = ', '.join(cwes)
    unmapped = [w for w in cwes if not any(w in c['cwes'] for c in data['categories'])]
    if unmapped:
        return {**result, 'status': 'unmapped', 'reason': f"Đầu vào gắn {len(cwes)} CWE ({listed}); {', '.join(unmapped)} không nằm trong bảng ánh xạ trực tiếp OWASP Top 10:2025. Không đề xuất khắc phục; cần xác minh phạm vi."}
    shared = [c for c in data['categories'] if all(w in c['cwes'] for w in cwes)]
    if not shared:
        groups = sorted({c['id'] for c in data['categories'] for w in cwes if w in c['cwes']})
        return {**result, 'status': 'unknown', 'reason': f"Đầu vào gắn {len(cwes)} CWE ({listed}) thuộc nhiều nhóm OWASP Top 10:2025 khác nhau ({', '.join(groups)}); chưa đủ căn cứ chọn một nhóm. Không đề xuất khắc phục."}
    result['categories'] = [_category(c) for c in shared]
    return {**result, 'status': 'in_scope', 'reason': f"Cả {len(cwes)} CWE do đầu vào cung cấp ({listed}) đều có ánh xạ trực tiếp vào {', '.join(c['id'] for c in shared)}; đây không phải xác nhận lỗ hổng thực tế."}


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
                            'mapping_commit':mapping()['commit'],
                            'rule':('Only findings whose input CWE is directly mapped (when the input lists several CWEs, '
                                    'all of them in one category) and that carry input evidence may receive OWASP remediation. '
                                    'All other findings remain in the report.')}
    return report
