"""Deterministic database-scope frame for one finding.

Everything here is read from the record itself: the port/service string in
`location`, the CWE the tool supplied, the project rule id in
`details.scanner_rule` (src/rag/data/scanner-rules.json), or the documented
sqlmap line `back-end DBMS:`. Nothing is inferred from a title, guessed from
free text, or produced by AI. The frame tells the model which database layer and
which control the input actually shows, so its prose stays about that control
instead of generic database advice.

Control buckets follow the sections the OWASP Database Security Cheat Sheet
itself uses (authentication, authorization/least privilege, encryption, network
surface, patching, logging). The mapping is from CWE to control, not from a
CWE to a promised impact.
"""
import re

# Engine known from the TCP port in the record (Nmap/Nessus location strings).
ENGINES = {3306: 'MySQL/MariaDB', 3307: 'MySQL/MariaDB', 5432: 'PostgreSQL', 5433: 'PostgreSQL',
           1433: 'Microsoft SQL Server', 1521: 'Oracle Database', 27017: 'MongoDB', 6379: 'Redis'}
# Engine of a project rule; test_scanner_rules keeps this in sync with scanner-rules.json.
RULE_ENGINES = {'nessus-10481': 'MySQL/MariaDB', 'nessus-10483': 'PostgreSQL',
                'nessus-10673': 'Microsoft SQL Server', 'nessus-81777': 'MongoDB',
                'nessus-100634': 'Redis', 'nessus-57558': 'MySQL/MariaDB',
                'nessus-63347': 'PostgreSQL', 'nessus-55786': 'Oracle Database',
                'nessus-64784': 'Microsoft SQL Server', 'nessus-73756': 'Microsoft SQL Server',
                'nmap-mysql-empty-password': 'MySQL/MariaDB',
                'nmap-ms-sql-empty-password': 'Microsoft SQL Server'}
# Control at stake, keyed by the CWE that the tool or a project rule supplied.
CONTROLS = {'CWE-89': ('query_handling', 'Xử lý truy vấn (SQL injection)'),
            'CWE-564': ('query_handling', 'Xử lý truy vấn (Hibernate injection)'),
            'CWE-943': ('query_handling', 'Xử lý truy vấn (NoSQL injection)'),
            'CWE-1393': ('authentication', 'Xác thực / mật khẩu mặc định'),
            'CWE-306': ('authentication', 'Xác thực bắt buộc'),
            'CWE-521': ('authentication', 'Chính sách mật khẩu'),
            'CWE-798': ('credentials', 'Thông tin đăng nhập hard-code'),
            'CWE-1104': ('patching', 'Phiên bản / bản vá bảo mật'),
            'CWE-311': ('encryption', 'Thiếu mã hoá dữ liệu lưu trữ'),
            'CWE-319': ('encryption', 'Truyền dữ liệu không mã hoá')}
SERVER_TOOLS = {'nessus', 'nmap'}
# Query handling is code that builds a query, so the finding lives at the application
# layer even when the tool name is unknown; the other buckets are server configuration.
APP_CONTROLS = {'query_handling'}
PORT = re.compile(r':(\d{2,5})(?:/tcp|/udp)?\b')
HTTP_LOCATION = re.compile(r'(?i)^https?://')
DBMS_LINE = re.compile(r'(?im)^\s*back-end DBMS:\s*([A-Za-z0-9 ._+\-]+?)\s*$')


def record_cwes(row):
    """CWEs the input itself carries: the single known CWE, or the recorded list."""
    details = row.get('details') or {}
    if row.get('cwe') and row.get('cwe') != 'unknown':
        return [row['cwe']]
    return [str(item) for item in details.get('cwes') or []]


def control_of(cwes):
    """One control only when every CWE maps into the same bucket; label from the first."""
    buckets = {CONTROLS[c][0] for c in cwes if c in CONTROLS}
    if len(buckets) != 1:
        return '', ''
    for cwe in cwes:
        if cwe in CONTROLS:
            return CONTROLS[cwe]
    return '', ''


def db_frame(row):
    """Return the database facts this record states, plus where each came from."""
    basis = []
    details = row.get('details') or {}
    rule = str(details.get('scanner_rule') or '')
    tool = str(row.get('tool') or '').strip().lower()
    location = str(row.get('location') or '').strip()
    port = None
    match = PORT.search(location)
    if match and int(match.group(1)) in ENGINES:
        port = int(match.group(1))
        basis.append(f'cổng {port} trong trường vị trí')
    if rule:
        basis.append(f'quy tắc dự án {rule}')
    # A project rule names the engine explicitly, so it wins over the port heuristic.
    if rule in RULE_ENGINES:
        engine = RULE_ENGINES[rule]
        basis.append('engine theo bảng quy tắc của dự án')
    elif port:
        engine = ENGINES[port]
    elif details.get('dbms'):
        engine = str(details['dbms']).strip()
        basis.append('dòng "back-end DBMS" do adapter ghi lại')
    else:
        engine = ''
        for item in row.get('evidence') or []:
            found = DBMS_LINE.search(str(item))
            if found:
                engine = found.group(1).strip()
                basis.append('dòng "back-end DBMS" trong bằng chứng')
                break
    cwes = record_cwes(row)
    control, control_label = control_of(cwes)
    has_query_cwe = any(CONTROLS.get(c, ('',))[0] in APP_CONTROLS for c in cwes)
    # Generic server/transport CWEs (e.g. CWE-311 HTTP Only Site, CWE-319 missing HSTS)
    # on a plain http(s):// URL without a DB port, rule, or DBMS belong to the web layer.
    if HTTP_LOCATION.match(location) and not (engine or port or rule or has_query_cwe):
        control = control_label = ''
        db_signal = False
    else:
        if control_label:
            basis.append('CWE do công cụ hoặc quy tắc cung cấp: ' + ', '.join(cwes))
            unmapped = [c for c in cwes if c not in CONTROLS]
            if unmapped:
                basis.append('CWE chưa có trong bảng kiểm soát: ' + ', '.join(unmapped))
        db_signal = bool(control_label) or any(c in CONTROLS for c in cwes)
    is_server_tool = any(token in tool for token in SERVER_TOOLS)
    if rule in RULE_ENGINES or (is_server_tool and engine):
        relevance, layer = 'server_db', 'máy chủ CSDL'
    elif control in APP_CONTROLS:
        relevance, layer = 'app_db', 'tầng ứng dụng (truy vấn tới CSDL)'
    elif db_signal or engine:
        relevance, layer = 'db_related', 'chưa xác định được tầng từ bản ghi'
    else:
        relevance, layer = 'unrelated', ''
    return {'relevance': relevance, 'layer': layer, 'engine': engine,
            'port': port or 0, 'control': control, 'control_label': control_label,
            'rule': rule, 'basis': basis}


def frame_line(frame):
    """One Vietnamese line for the report; anything unknown stays unknown."""
    if frame['relevance'] == 'unrelated':
        return 'Không thấy thông tin riêng về CSDL trong bản ghi này.'
    parts = ['Phạm vi CSDL: ' + (frame['layer'] or 'không xác định')]
    if frame['engine']:
        # Show the port only when it belongs to that engine; a port that contradicts the
        # rule (e.g. PostgreSQL plugin on 3306) is not repeated as if it confirmed it.
        shown = f" (cổng {frame['port']})" if ENGINES.get(frame['port']) == frame['engine'] else ''
        parts.append('engine: ' + frame['engine'] + shown)
    parts.append('kiểm soát: ' + frame['control_label'] if frame['control_label']
                 else 'chưa xác định kiểm soát từ CWE')
    return '; '.join(parts) + '.'


def ai_source(row):
    """Source string handed to the model as K1; derived by code, not by AI."""
    frame = db_frame(row)
    if frame['relevance'] == 'unrelated':
        return ('Phân loại CSDL do code thực hiện từ chính bản ghi này: không có dấu hiệu riêng về CSDL. '
                'Không tự gán tầng, engine hay kiểm soát CSDL cho bản ghi này.')
    basis = ('; '.join(frame['basis'])) or 'chỉ các trường đã nêu, không có căn cứ nào khác'
    return ('Phân loại CSDL do code thực hiện từ chính bản ghi này (không do AI suy đoán): '
            f"mức liên quan={frame['relevance']}; tầng={frame['layer'] or 'chưa xác định'}; "
            f"engine={frame['engine'] or 'chưa xác định'}; "
            f"kiểm soát={frame['control_label'] or 'chưa xác định'}; căn cứ={basis}.")


RELEVANCE_LABELS = {'server_db': 'máy chủ CSDL', 'app_db': 'tầng ứng dụng (truy vấn tới CSDL)',
                    'db_related': 'có kiểm soát CSDL nhưng chưa rõ tầng', 'unrelated': 'ngoài phạm vi CSDL'}


def scope_summary(rows):
    """Report-level counts over the frames, for the scope section."""
    summary = {'by_relevance': {}, 'by_control': {}, 'by_engine': {}, 'total': len(rows)}
    for row in rows:
        frame = db_frame(row)
        summary['by_relevance'][frame['relevance']] = summary['by_relevance'].get(frame['relevance'], 0) + 1
        if frame['control_label']:
            summary['by_control'][frame['control_label']] = summary['by_control'].get(frame['control_label'], 0) + 1
        if frame['engine']:
            summary['by_engine'][frame['engine']] = summary['by_engine'].get(frame['engine'], 0) + 1
    return summary


def scope_lines(rows):
    """Lines for section 2 of the report: only what the input itself supports."""
    if not rows:
        return ['Không có bản ghi nào để xác định phạm vi CSDL.']
    summary = scope_summary(rows)
    order = ['server_db', 'app_db', 'db_related', 'unrelated']
    parts = [f"{RELEVANCE_LABELS[key]}: {summary['by_relevance'][key]}"
             for key in order if summary['by_relevance'].get(key)]
    lines = ['Phạm vi CSDL nhận diện từ đầu vào (code phân loại theo cổng/dịch vụ, CWE và quy tắc dự án, '
             'không do AI suy đoán) — ' + '; '.join(parts) + '.']
    if summary['by_engine']:
        lines.append('Engine được đầu vào nêu tên: ' + '; '.join(
            f'{name}: {count}' for name, count in sorted(summary['by_engine'].items())) + '.')
    if summary['by_control']:
        lines.append('Kiểm soát CSDL mà đầu vào nhắc tới: ' + '; '.join(
            f'{name}: {count}' for name, count in sorted(summary['by_control'].items())) + '.')
    lines.append('Các mục trên chỉ là phân loại lại thông tin đầu vào; không xác nhận lỗ hổng, không chứng minh '
                 'CSDL đã được kiểm thử đầy đủ và không thay thế quét có xác thực (quyền, mã hoá, logging).')
    return lines


def attach_db_scope(report):
    """Attach the deterministic database frame to every record and the report summary."""
    rows = report.get('findings') or []
    for row in rows:
        row['db_frame'] = db_frame(row)
    report['db_scope'] = {'summary': scope_summary(rows), 'lines': scope_lines(rows)}
    return report
