"""Shared data-driven presentation. No findings, severities or target facts invented."""
import json
import re
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


SYSTEM_SCHEMAS={'information_schema','mysql','performance_schema','sys','pg_catalog','pg_toast','master','tempdb','model','msdb'}
LAB_SIGNATURES=[
    ('dvwa','DVWA (Damn Vulnerable Web Application)','Ứng dụng web thực hành bảo mật có lỗ hổng chủ đích (PHP/MySQL)'),
    ('mutillidae','OWASP Mutillidae II','Ứng dụng web thực hành bảo mật có lỗ hổng chủ đích'),
    ('juice-shop','OWASP Juice Shop','Ứng dụng web thực hành bảo mật có lỗ hổng chủ đích (Node.js/SQLite)'),
    ('juiceshop','OWASP Juice Shop','Ứng dụng web thực hành bảo mật có lỗ hổng chủ đích (Node.js/SQLite)'),
    ('webgoat','OWASP WebGoat','Ứng dụng thực hành bảo mật có lỗ hổng chủ đích (Java)'),
    ('bwapp','bWAPP (Buggy Web Application)','Ứng dụng web thực hành bảo mật có lỗ hổng chủ đích (PHP/MySQL)'),
    ('crapi','OWASP crAPI','API thực hành bảo mật có lỗ hổng chủ đích'),
    ('vampi','VAmPI','API thực hành bảo mật có lỗ hổng chủ đích'),
]
EOL_SIGNATURES=[
    (re.compile(r'Debian\s+9\b',re.I),'Linux Debian 9 (stretch) đã kết thúc hỗ trợ LTS từ 06/2022 (EOL)'),
    (re.compile(r'Debian\s+8\b',re.I),'Linux Debian 8 (jessie) đã kết thúc hỗ trợ (EOL)'),
    (re.compile(r'Ubuntu\s+1[468]\.04\b',re.I),'Phiên bản Ubuntu LTS cũ đã hết hỗ trợ tiêu chuẩn (EOL)'),
    (re.compile(r'CentOS(?:\s+Linux)?\s+[67]\b',re.I),'CentOS 6/7 đã kết thúc vòng đời hỗ trợ (EOL)'),
    (re.compile(r'Apache[/\s]+2\.4\.(?:[0-9]|1[0-9]|2[0-9])\b',re.I),'Apache HTTP Server nhánh 2.4 cũ (phát hành giai đoạn 2012–2017, thiếu nhiều bản vá mới)'),
    (re.compile(r'Apache[/\s]+2\.2\b',re.I),'Apache HTTP Server 2.2 đã kết thúc hỗ trợ từ 07/2017 (EOL)'),
    (re.compile(r'\bPHP[/\s]+[57]\.\d+',re.I),'Nhánh PHP 5.x/7.x đã kết thúc hỗ trợ bảo mật (EOL)'),
    (re.compile(r'\bMySQL\s+5\.[01567]\b',re.I),'Nhánh MySQL 5.x đã kết thúc vòng đời hỗ trợ chính thức (EOL)'),
]


def split_schemas(names):
    app,sys_names=[],[]
    for name in names or []:
        clean=str(name).strip()
        if not clean:continue
        (sys_names if clean.lower() in SYSTEM_SCHEMAS else app).append(clean)
    return app,sys_names


def _row_corpus_text(row):
    d=row.get('details') if isinstance(row.get('details'),dict) else {}
    parts=[str(row.get('title','')),str(row.get('location','')),*map(str,row.get('evidence') or [])]
    tel=d.get('scan_telemetry') if isinstance(d.get('scan_telemetry'),dict) else {}
    for k in ('os_banner','web_tech','dbms'):
        if d.get(k):parts.append(str(d[k]))
        if tel.get(k):parts.append(str(tel[k]))
    if isinstance(d.get('service'),dict):
        parts.extend(str(v) for v in d['service'].values() if v)
    return '\n'.join(parts)


def detect_lab_indicator(rows):
    for row in rows:
        d=row.get('details') if isinstance(row.get('details'),dict) else {}
        tel=d.get('scan_telemetry') if isinstance(d.get('scan_telemetry'),dict) else {}
        schemas=[str(x) for x in (tel.get('databases') or [])]
        blob=_row_corpus_text(row)
        for token,label,desc in LAB_SIGNATURES:
            basis=[]
            if any(s.lower()==token for s in schemas):basis.append(f"schema CSDL '{token}'")
            if re.search(rf'(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])',str(row.get('location','')),re.I):
                basis.append(f"đường dẫn '{token}'")
            if token=='dvwa' and 'Submit=Submit' in blob:
                basis.append("tham số 'Submit=Submit'")
            if basis:
                return {'name':label,'description':desc,'basis':', '.join(basis),
                        'note_vi':f"Dấu hiệu đầu vào ({', '.join(basis)}) trùng khớp {label} — {desc.lower()} [quy tắc nhận diện tĩnh trong code dự án]."}
    return None


def detect_eol_banners(rows):
    found=[]
    seen_notes=set()
    for row in rows:
        blob=_row_corpus_text(row)
        for pattern,note in EOL_SIGNATURES:
            m=pattern.search(blob)
            if m and note not in seen_notes:
                seen_notes.add(note)
                banner=re.sub(r'\s+',' ',m.group(0)).strip()
                found.append(f"Banner đầu vào '{banner}' -> {note} [quy tắc đối chiếu tĩnh trong code dự án, không do AI suy đoán]")
    return found


def evidence_profile(row):
    d=row.get('details') if isinstance(row.get('details'),dict) else {}
    tel=d.get('scan_telemetry') if isinstance(d.get('scan_telemetry'),dict) else {}
    kind=row.get('kind','scanner_alert')
    techs=d.get('techniques') or []
    dbs=tel.get('databases') or []
    app_dbs,sys_dbs=split_schemas(dbs)
    if kind=='observation':
        conf=str(d.get('confidence') or '')
        if 'heuristic' in conf.lower():
            return {'tier':'heuristic','label_vi':'Cảnh báo heuristic chưa xác nhận (cần kiểm chứng thủ công)',
                    'note_vi':'Công cụ mới ghi nhận dấu hiệu phản xạ đầu vào sơ bộ, chưa gửi payload khai thác XSS thực tế.'}
        return {'tier':'observation','label_vi':'Quan sát dịch vụ / bề mặt mạng (chưa phải lỗ hổng độc lập)',
                'note_vi':'Ghi nhận trạng thái cổng hoặc banner dịch vụ để hỗ trợ phân tích phạm vi.'}
    if techs and dbs:
        schema_parts=[]
        if app_dbs:schema_parts.append("schema ứng dụng '"+', '.join(app_dbs)+"'")
        if sys_dbs:schema_parts.append("schema hệ thống '"+', '.join(sys_dbs)+"'")
        tbl_cnt=sum(len(v) for v in (tel.get('tables_by_db') or {}).values())
        tbl_suffix=f", {tbl_cnt} bảng" if tbl_cnt else ""
        http_cnt=len(d.get('http_messages') or [])
        http_suffix=f"; kèm {http_cnt} cặp HTTP Request/Response" if http_cnt else ""
        if d.get('cvss_score'):
            auth_tail=f"mức CVSS được khai báo kèm ngữ cảnh xác thực: {d['cvss_score']}"+(f" ({d['cvss_vector']})" if d.get('cvss_vector') else "")+"."
        elif tel.get('auth_context'):
            auth_tail=f"giữ 'unknown' ở trường gốc vì công cụ không tự xuất điểm CVSS (ngữ cảnh xác thực ghi nhận: {tel['auth_context']})."
        else:
            auth_tail="giữ 'unknown' ở trường gốc vì công cụ không xuất CVSS và thiếu ngữ cảnh xác thực (PR:N/PR:L)."
        return {'tier':'exploited_in_log',
                'label_vi':f"Đã khai thác trích xuất dữ liệu trong log (1 điểm tiêm / {len(techs)} kỹ thuật; đọc {len(dbs)} schema{tbl_suffix}{http_suffix})",
                'note_vi':(f"Log chứng minh khai thác thành công bằng {len(techs)} kỹ thuật ({', '.join(techs)}) và đã liệt kê {', '.join(schema_parts)}. "
                           "Nhóm lỗi SQL Injection trích xuất được dữ liệu thường thuộc mức Cao/Nghiêm trọng trong thực tế; "+auth_tail)}
    if techs:
        return {'tier':'confirmed_payload',
                'label_vi':f"Công cụ xác nhận payload phản hồi (1 điểm tiêm / {len(techs)} kỹ thuật)",
                'note_vi':f"Công cụ ghi nhận {len(techs)} kỹ thuật phản hồi ({', '.join(techs)}); chưa kèm kết quả trích xuất dữ liệu trong log."}
    if d.get('scanner_rule') and row.get('evidence'):
        return {'tier':'active_script',
                'label_vi':'Xác nhận kiểm tra chủ động từ script/plugin công cụ',
                'note_vi':'Script/plugin chuyên biệt trả về kết quả dương tính trực tiếp trên dịch vụ mục tiêu; giữ nguyên mức độ gốc do công cụ cung cấp.'}
    if row.get('evidence'):
        return {'tier':'tool_evidence',
                'label_vi':'Có bằng chứng phản hồi từ công cụ kiểm thử (chưa kiểm chứng thủ công)',
                'note_vi':'Đã đính kèm trích đoạn phản hồi của công cụ; cần đối chiếu ngữ cảnh xác thực và nghiệp vụ thực tế.'}
    return {'tier':'unverified','label_vi':'Thiếu bằng chứng phản hồi trực tiếp',
            'note_vi':'Chỉ có tên cảnh báo từ đầu vào, chưa có trích đoạn phản hồi đi kèm.'}


def extract_scan_context(report, scan_path=None, format_=None):
    rows=report.get('findings') or []
    ctx={'lab':detect_lab_indicator(rows),'eol_notes':detect_eol_banners(rows),'telemetry_lines':[],'repro_gaps':[]}
    seen_tel=set()
    scan_windows=[]
    for r in rows:
        d=r.get('details') if isinstance(r.get('details'),dict) else {}
        tel=d.get('scan_telemetry') if isinstance(d.get('scan_telemetry'),dict) else {}
        if not tel:continue
        if tel.get('scan_start'):
            win=(f"{tel['scan_start']} – {tel['scan_end']} (ghi trong log {r.get('tool','')})"
                 if tel.get('scan_end') else f"{tel['scan_start']} (ghi trong log {r.get('tool','')})")
            if win not in scan_windows:
                scan_windows.append(win)
        parts=[]
        if tel.get('tool_version'):parts.append(f"{r.get('tool','tool')} {tel['tool_version']}")
        if tel.get('target_site'):parts.append(f"mục tiêu {tel['target_site']}")
        if tel.get('plugin_family'):parts.append(f"nhóm plugin: {tel['plugin_family']}")
        if tel.get('protocol'):parts.append(f"giao thức: {tel['protocol']}")
        if tel.get('matcher'):parts.append(f"matcher: {tel['matcher']}")
        if tel.get('request_count'):parts.append(f"{tel['request_count']} HTTP requests")
        if tel.get('level') is not None and tel.get('risk') is not None:
            ext=' (mở rộng bài kiểm tra theo DBMS)' if tel.get('extended_dbms_tests') else ''
            parts.append(f"level={tel['level']}, risk={tel['risk']}{ext}")
        if tel.get('waf_status'):parts.append(f"WAF/IPS: {tel['waf_status']}")
        if tel.get('non_dynamic_parameters'):
            parts.append("tham số cảnh báo không dynamic: "+', '.join(tel['non_dynamic_parameters']))
        if tel.get('reflection_filtered'):parts.append('đã lọc giá trị phản xạ (reflective values filtered)')
        if tel.get('not_string'):parts.append(f'chuỗi đối chiếu boolean: --not-string="{tel["not_string"]}"')
        if tel.get('stopped_after_first_vulnerable_param'):
            parts.append('dừng kiểm thử các tham số còn lại sau phát hiện đầu tiên ([y/N] N)')
        elif tel.get('tested_all_parameters'):
            parts.append('đã mở rộng kiểm thử các tham số còn lại ([y/N] Y)')
        if tel.get('cli_hint'):parts.append(f"lệnh ghi nhận: {tel['cli_hint']}")
        if tel.get('auth_context') and not ctx.get('auth_context'):
            ctx['auth_context']=tel['auth_context']
        if any(k in tel for k in ('current_user','current_db','is_dba')) and not ctx.get('db_identity'):
            id_bits=[]
            if tel.get('current_user'):id_bits.append(f"user='{tel['current_user']}'")
            if tel.get('current_db'):id_bits.append(f"current_db='{tel['current_db']}'")
            if tel.get('is_dba') is not None:id_bits.append(f"quyền DBA={'CÓ (rủi ro đặc quyền cao)' if tel['is_dba'] else 'Không'}")
            ctx['db_identity']='; '.join(id_bits)
        if tel.get('tables_by_db') and not ctx.get('tables_by_db'):
            ctx['tables_by_db']=tel['tables_by_db']
        if parts:
            line='; '.join(parts)
            if line not in seen_tel:
                seen_tel.add(line);ctx['telemetry_lines'].append(line)
        dbs=tel.get('databases') or []
        if dbs and not ctx.get('schemas'):
            app_s,sys_s=split_schemas(dbs)
            ctx['schemas']={'application':app_s,'system':sys_s}
    # Deduplicate any shorter telemetry summary whose clauses are already covered by a fuller record in the same file.
    kept_tel=[]
    for line in sorted(ctx['telemetry_lines'],key=len,reverse=True):
        clauses={c.strip() for c in line.split(';')}
        if not any(clauses.issubset({c.strip() for c in big.split(';')}) for big in kept_tel):
            kept_tel.append(line)
    ctx['telemetry_lines']=kept_tel
    if scan_windows and not ctx.get('scan_window'):
        ctx['scan_window']='; '.join(scan_windows)
    if scan_path and not ctx.get('scan_window') and Path(scan_path).is_file():
        if format_=='zap':
            try:
                raw_json=json.loads(Path(scan_path).read_text(encoding='utf-8-sig',errors='replace'))
                if raw_json.get('@generated'):ctx['scan_window']=f"{raw_json['@generated']} (ghi trong file ZAP)"
            except Exception:pass
    fmt=format_ or report.get('input_format','')
    sqlmap_rows=[r for r in rows if str(r.get('tool','')).lower()=='sqlmap']
    if fmt=='sqlmap-log' or sqlmap_rows:
        target_rows=sqlmap_rows or rows
        missing_bits=[]
        if any('sqlmap output log' in str(r.get('location','')) or 'not established' in str(r.get('location','')) for r in target_rows):
            missing_bits.append('URL/endpoint đầy đủ')
        if not ctx.get('auth_context'):
            missing_bits.append('cookie/phiên đăng nhập (PR:N hay PR:L)')
        if not ctx.get('db_identity'):
            missing_bits.append('quyền tài khoản CSDL hiện tại (--current-user / --privileges)')
        if missing_bits:
            ctx['repro_gaps'].append('Stdout mặc định của sqlmap không lưu câu lệnh CLI đã chạy nên thiếu '+', '.join(missing_bits)+'.')
    if ctx['lab']:
        ctx['application_hint']=f"{ctx['lab']['name']} (nhận diện từ {ctx['lab']['basis']})"
    return ctx


def context_source_text(row):
    """Deterministic single-record context note (C1) grounded strictly in parsed fields."""
    d=row.get('details') if isinstance(row.get('details'),dict) else {}
    tel=d.get('scan_telemetry') if isinstance(d.get('scan_telemetry'),dict) else {}
    prof=evidence_profile(row)
    if row.get('kind')=='observation':
        if str(row.get('cwe',''))=='CWE-79':
            refl=' và đã ghi nhận giá trị đầu vào phản xạ lại trong HTTP response (reflective values found)' if tel.get('reflection_filtered') else ''
            return (f"Đánh giá chứng cứ theo code: {prof['label_vi']}. "
                    f"Phép kiểm tra heuristic sơ bộ của {row.get('tool','công cụ')} ghi nhận tham số {d.get('place','')} '{d.get('parameter','')}' "
                    f"có dấu hiệu phản xạ ký tự đặc biệt phía trình duyệt (XSS - CWE-79){refl}. "
                    "Bản ghi thuộc tầng giao diện web (ngoài phạm vi CSDL); log chưa kiểm tra ngữ cảnh mã hóa HTML/JS hay Content-Security-Policy.")
        svc=d.get('service') if isinstance(d.get('service'),dict) else {}
        svc_desc=' '.join(str(svc.get(k,'')) for k in ('name','product','version','extrainfo') if svc.get(k)).strip()
        return (f"Đánh giá chứng cứ theo code: {prof['label_vi']}. "
                f"Ghi nhận trạng thái cổng {d.get('state','open')} tại {row.get('location','')} "
                f"{('với banner dịch vụ '+svc_desc) if svc_desc else ''}; chưa tự suy ra lỗ hổng chỉ từ việc mở cổng.").replace('  ',' ')
    parts=[f"Đánh giá chứng cứ theo code: {prof['label_vi']}."]
    techs=d.get('techniques') or []
    if techs:
        parts.append(f"Đây là 1 điểm lỗ hổng SQL Injection duy nhất trên tham số {d.get('place','')} '{d.get('parameter','')}', được xác nhận qua {len(techs)} kỹ thuật kiểm thử ({', '.join(techs)}) — không phải {len(techs)} lỗ hổng riêng lẻ.")
        blind_kinds=[t for t in techs if 'blind' in str(t).lower()]
        if blind_kinds and d.get('http_messages'):
            parts.append("Lưu ý đọc bằng chứng HTTP thô cho kỹ thuật mù ("+", ".join(blind_kinds)+"): bản chất khai thác mù được xác minh qua sự chênh lệch phản hồi giữa điều kiện TRUE/FALSE (boolean-based) hoặc độ trễ thời gian phản hồi RTT so với mức nền (time-based SLEEP), trong khi error-based và UNION query hiển thị trực tiếp dữ liệu/lỗi SQL ngay trong thân HTTP response.")
    dbs=tel.get('databases') or []
    if dbs:
        app_s,sys_s=split_schemas(dbs)
        seg=[]
        if app_s:seg.append("schema ứng dụng: "+", ".join(app_s))
        if sys_s:seg.append("schema hệ thống mặc định của DBMS (không phải CSDL ứng dụng): "+", ".join(sys_s))
        tbl_note=""
        if tel.get('tables_by_db'):
            tbl_strs=[f"{dbn} ({', '.join(ts)})" for dbn,ts in tel['tables_by_db'].items()]
            tbl_note="; các bảng đã liệt kê: "+"; ".join(tbl_strs)+" (dừng ở mức cấu trúc bảng, không trích xuất bản ghi)"
        else:
            tbl_note=" (phép quét mới dừng ở liệt kê tên schema, chưa trích xuất các bảng và bản ghi bên trong schema ứng dụng)"
        parts.append("Dữ liệu đã trích xuất thực tế trong log — "+"; ".join(seg)+tbl_note+".")
    if any(k in tel for k in ('current_user','current_db','is_dba')):
        id_seg=[]
        if tel.get('current_user'):id_seg.append(f"current user='{tel['current_user']}'")
        if tel.get('current_db'):id_seg.append(f"current database='{tel['current_db']}'")
        if tel.get('is_dba') is not None:id_seg.append(f"quyền DBA={'True' if tel['is_dba'] else 'False'}")
        parts.append("Thông tin tài khoản CSDL từ log: "+"; ".join(id_seg)+".")
    if d.get('cvss_score') or d.get('cvss_vector'):
        cv_seg=str(d.get('cvss_score') or '')
        if d.get('cvss_vector'):cv_seg=(cv_seg+' | '+str(d['cvss_vector'])).strip(' |')
        parts.append(f"Điểm và vector CVSS đã cung cấp sẵn từ đầu vào: {cv_seg}.")
    if tel.get('auth_context'):
        parts.append("Ngữ cảnh xác thực đã cung cấp đầy đủ: "+tel['auth_context']+" (giá trị token phiên được che [REDACTED] có chủ đích để bảo mật báo cáo, đã xác định rõ quyền phiên đăng nhập).")
    lab=detect_lab_indicator([row])
    if lab:parts.append(lab['note_vi'])
    eol=detect_eol_banners([row])
    if eol:parts.append("Đối chiếu vòng đời nền tảng từ banner (quy tắc tĩnh trong code): "+"; ".join(eol)+".")
    t_bits=[]
    if tel.get('tool_version'):t_bits.append(f"phiên bản công cụ {tel['tool_version']}")
    if tel.get('scan_start'):t_bits.append(f"thời gian {tel['scan_start']}"+(f" đến {tel['scan_end']}" if tel.get('scan_end') else ""))
    if tel.get('request_count'):t_bits.append(f"{tel['request_count']} HTTP requests")
    if tel.get('level') is not None:t_bits.append(f"level={tel['level']}/risk={tel['risk']}")
    if tel.get('waf_status'):t_bits.append(f"WAF/IPS: {tel['waf_status']}")
    if tel.get('non_dynamic_parameters'):t_bits.append("cảnh báo không dynamic trên "+", ".join(tel['non_dynamic_parameters']))
    if tel.get('reflection_filtered'):t_bits.append("lọc giá trị phản xạ")
    if tel.get('not_string'):t_bits.append(f'--not-string="{tel["not_string"]}"')
    if tel.get('stopped_after_first_vulnerable_param'):t_bits.append("bỏ qua kiểm thử các tham số khác ([y/N] N)")
    elif tel.get('tested_all_parameters'):t_bits.append("đã kiểm thử mở rộng toàn bộ tham số ([y/N] Y)")
    if d.get('http_messages'):t_bits.append(f"đính kèm {len(d['http_messages'])} cặp giao dịch HTTP Request/Response thực tế")
    if t_bits:parts.append("Thông số phiên quét: "+"; ".join(t_bits)+".")
    if 'sqlmap output log' in str(row.get('location','')) or 'not established' in str(row.get('location','')):
        parts.append("Giới hạn tái hiện: log stdout không lưu URL đầy đủ, cookie xác thực phiên hay quyền tài khoản CSDL hiện tại.")
    return ' '.join(parts)


def defense_layer_label(card):
    sec=str(card.get('section','')).lower()
    src=str(card.get('source','')).lower()
    if 'using php' in sec:
        return 'Mẫu mã nguồn an toàn OWASP — Prepared Statement (PHP PDO)'
    if 'using java' in sec:
        return 'Mẫu mã nguồn an toàn OWASP — Prepared Statement (Java)'
    if 'using .net' in sec or 'asp .net' in sec:
        return 'Mẫu mã nguồn an toàn OWASP — Prepared Statement (.NET)'
    if 'using ruby' in sec:
        return 'Mẫu mã nguồn an toàn OWASP — Prepared Statement (Ruby)'
    if 'using rust' in sec:
        return 'Mẫu mã nguồn an toàn OWASP — Prepared Statement (Rust SQLx)'
    if 'oracle using pl/sql' in sec:
        return 'Mẫu mã nguồn an toàn OWASP — Stored Procedure tham số hóa (Oracle PL/SQL)'
    if 'sql server using transact-sql' in sec:
        return 'Mẫu mã nguồn an toàn OWASP — Stored Procedure tham số hóa (SQL Server T-SQL)'
    if 'query_parameterization' in src or 'prepared statement example' in sec:
        return 'Nguyên lý tham số hóa truy vấn CSDL — OWASP Query Parameterization'
    if 'defense option 1' in sec:
        return 'Phòng vệ gốc — Truy vấn tham số hóa (Prepared Statements)'
    if 'defense option 2' in sec:
        return 'Phòng vệ thay thế — Thủ tục lưu trữ tham số hóa (Stored Procedures)'
    if 'least privilege' in sec:
        return 'Phòng vệ chiều sâu CSDL — Nguyên tắc đặc quyền tối thiểu (Least Privilege)'
    if 'input validation' in sec:
        return 'Phòng vệ chiều sâu ứng dụng — Kiểm tra/ép kiểu đầu vào theo Allow-list'
    if 'error_handling' in src or 'error handling' in sec:
        return 'Kiểm soát phản hồi lỗi — Ẩn chi tiết lỗi CSDL phía client'
    if 'transport layer protection' in sec:
        return 'Mã hóa đường truyền CSDL — Bảo vệ kết nối bằng TLS/SSL'
    if 'configuring secure authentication' in sec:
        return 'Xác thực CSDL — Bắt buộc mật khẩu mạnh & tài khoản riêng biệt'
    if 'protecting the backend database' in sec:
        return 'Cô lập mạng CSDL — Chỉ bind nội bộ / giới hạn cổng TCP qua tường lửa'
    if 'creating secure permissions' in sec:
        return 'Phân quyền CSDL — Loại bỏ sử dụng tài khoản quản trị mặc định (root/sa/postgres)'
    if 'hardening' in sec or 'configuration and hardening' in sec or sec.endswith('/ mongodb'):
        return 'Cứng hóa máy chủ CSDL (Database Server Hardening)'
    return 'Trích nguyên văn hướng dẫn phòng vệ OWASP'


def attach_context(report,scan_path,format_,metadata=None,display_filename=None):
    base={}
    if format_=='normalized':base=clean_metadata(json.loads(Path(scan_path).read_text(encoding='utf-8-sig')).get('report_metadata'))
    report['report_metadata']={**base,**clean_metadata(metadata)}
    report['input_filename']=display_filename or Path(scan_path).name
    report['input_format']=format_
    report['scan_context']=extract_scan_context(report,scan_path,format_)
    report['report_layout_version']='0.11'
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
    exchanges=[{'request':m.get('request',''),'response':m.get('response','')} for m in messages if isinstance(m,dict) and (m.get('request') or m.get('response'))]
    if isinstance(raw,dict) and raw.get('request'):requests.append(str(raw['request']))
    method=d.get('method') or inst.get('method') if isinstance(inst,dict) else d.get('method')
    if not method and requests:
        candidate=requests[0].split(' ',1)[0]
        if candidate in {'GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'}:method=candidate
    return {'method':method or MISSING,'parameter':d.get('parameter') or d.get('insertion_point') or MISSING,
            'cvss':str(d.get('cvss_score')) if d.get('cvss_score') not in (None,'') else MISSING,
            'cvss_vector':str(d.get('cvss_vector') or MISSING),'confidence':str(d.get('confidence') or MISSING),
            'description':str(d.get('description') or (d.get('raw_alert') or {}).get('desc') or ''),
            'requests':requests,'exchanges':exchanges}


def cwe_origin(row):
    """Where the CWE came from: the input, several CWEs from the tool, or a project rule."""
    from .top10 import finding_cwes
    cwes=finding_cwes(row)
    details=row.get('details') if isinstance(row.get('details'),dict) else {}
    if not cwes:return 'không có CWE trong đầu vào'
    if details.get('cwe_mapping'):return 'gán theo quy tắc ánh xạ của dự án; công cụ không ghi CWE'
    if len(cwes)>1:return 'công cụ gắn nhiều CWE'
    return 'đầu vào'


def cwe_text(row, missing='unknown'):
    from .top10 import cwe_label
    label=cwe_label(row,missing);origin=cwe_origin(row)
    return label if origin in ('đầu vào','không có CWE trong đầu vào') else f'{label} ({origin})'


def fallback_description(row):
    return (f"{row['tool']} ghi nhận “{row['title']}” tại {row['location']}. "
            f"CWE: {cwe_text(row)}; mức độ đầu vào: {row['severity']}. "
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
