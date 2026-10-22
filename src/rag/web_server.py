"""Single-user loopback web UI for the 10-Section DB Security & OWASP Remediation Report Engine."""
import base64
import copy
from dataclasses import asdict
import hashlib
import json
import os
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .config import ROOT, load_settings
from .dbsec_report import prepare_dbsec_report, render_dbsec_markdown
from .llm import check_ollama
from .parsers import SUPPORTED_FORMATS, decode_text, load_findings
from .pdf_report import render_pdf

MAX_UPLOAD = 10 * 1024 * 1024
MAX_BUNDLE_BODY = 15 * 1024 * 1024
TERMINAL = {'completed', 'partial', 'failed'}
FORMATS = {
    'normalized': 'JSON chuẩn hóa',
    'zap': 'OWASP ZAP · JSON',
    'burp': 'Burp Suite · XML',
    'nuclei': 'Nuclei · JSONL',
    'sqlmap-log': 'sqlmap · log',
    'nessus': 'Nessus · XML',
    'nmap': 'Nmap · XML',
}


def now():
    return datetime.now(timezone.utc).isoformat()


def detect_format(path):
    raw = Path(path).read_bytes()
    if raw.startswith(b'%PDF'):
        raise ValueError('PDF đầu vào chưa được hỗ trợ. Hãy xuất JSON, XML, JSONL hoặc log từ công cụ; PDF là báo cáo đầu ra.')
    text = decode_text(raw, errors='replace').lstrip()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            if data.get('schema_version') == 1:
                return 'normalized'
            if isinstance(data.get('site'), list):
                return 'zap'
            if 'template-id' in data and isinstance(data.get('info'), dict):
                return 'nuclei'
    except ValueError:
        pass
    for root, fmt in [('issues', 'burp'), ('NessusClientData_v2', 'nessus'), ('nmaprun', 'nmap')]:
        if re.search(r'<' + root + r'(?:\s|>)', text[:4096]):
            return fmt
    try:
        first = json.loads(next(line for line in text.splitlines() if line.strip()))
        if isinstance(first, dict) and 'template-id' in first:
            return 'nuclei'
    except (ValueError, StopIteration):
        pass
    if re.search(r'(?m)^Parameter:\s*.+\(.+\)\s*$', text) or 'all tested parameters do not appear to be injectable' in text.lower():
        return 'sqlmap-log'
    raise ValueError('Chưa nhận diện được định dạng. Chọn đúng công cụ trong ô Định dạng hoặc dùng JSON chuẩn hóa của project.')


def safe_error(exc):
    if isinstance(exc, FileNotFoundError):
        return 'Thiếu file cấu hình, tài liệu OWASP hoặc vector store. Chạy ingest OWASP hoặc dùng start-web.bat.'
    if isinstance(exc, ImportError):
        return 'Thiếu thư viện Python. Chạy .\\.venv\\Scripts\\python.exe -m pip install -e ".[retrieval,pdf]" rồi khởi động lại web.'
    raw = str(exc)
    text = raw.lower()
    if 'run: ollama pull' in text:
        cmd = raw.split('run: ', 1)[1].strip()
        return f'Model chưa tải trong Ollama. Mở PowerShell chạy lệnh: {cmd} rồi gửi lại file.'
    if 'ollama' in text:
        return 'Chưa gọi được Ollama local. Kiểm tra ứng dụng Ollama đang chạy (ollama serve), OLLAMA_MODEL và OLLAMA_TIMEOUT trong .env.'
    if 'gemini' in text or 'api_key' in text or 'chat_model' in text:
        return 'Chưa gọi được Gemini. Kiểm tra API key, model và quota trong .env (hoặc đặt LLM_PROVIDER=ollama để chạy AI local).'
    if any(x in text for x in ('store', 'corpus', 'chunk', 'embedding', 'model limit', 'revision')):
        return 'Kho vector, tài liệu hoặc cấu hình embedding chưa khớp. Giữ chunk/overlap đúng với lần ingest và kiểm tra kho OWASP.'
    return 'Không hoàn tất xử lý (' + type(exc).__name__ + '). File đã được giữ cục bộ. Kiểm tra định dạng, cấu hình và thử lại bằng một lần gửi mới.'


class JobManager:
    def __init__(self, directory, *, demo=False, runner=None, settings_loader=load_settings):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.demo = demo
        self.runner = runner
        self.settings_loader = settings_loader
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='report')
        self.jobs = {}
        for path in self.directory.glob('*/job.json'):
            if not re.fullmatch(r'[a-f0-9]{32}', path.parent.name):
                continue
            try:
                job = json.loads(path.read_text(encoding='utf-8'))
                if job.get('id') != path.parent.name:
                    continue
                if job.get('status') not in TERMINAL:
                    job.update(
                        status='failed',
                        stage='Phiên xử lý bị gián đoạn',
                        error='Ứng dụng đã dừng trước khi hoàn tất. Gửi lại file để tạo một lần xử lý mới.',
                        updated_at=now(),
                    )
                    self._save(job)
                self.jobs[job['id']] = job
            except (OSError, ValueError):
                continue

    def _save(self, job):
        folder = self.directory / job['id']
        folder.mkdir(exist_ok=True)
        tmp = folder / 'job.tmp'
        tmp.write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding='utf-8')
        os.replace(tmp, folder / 'job.json')

    def get(self, id_):
        with self.lock:
            if id_ not in self.jobs:
                raise KeyError(id_)
            return copy.deepcopy(self.jobs[id_])

    def list(self):
        with self.lock:
            return [copy.deepcopy(j) for j in sorted(self.jobs.values(), key=lambda j: j['created_at'], reverse=True)[:100]]

    def update(self, id_, **values):
        with self.lock:
            job = self.jobs[id_]
            job.update(values, updated_at=now())
            self._save(job)

    def progress(self, id_, message):
        raw = str(message or '').strip()
        step = None
        pct = None
        tag_m = re.match(r'^\[step=(\d+)\|pct=(\d+)\]\s*(.*)$', raw)
        if tag_m:
            step = int(tag_m.group(1))
            pct = int(tag_m.group(2))
            raw = tag_m.group(3).strip()
        label = raw
        match = re.match(r'AI analysis (\d+)/(\d+)(?:\s*—\s*(.*))?', raw)
        if match:
            suffix = f" ({match.group(3)})" if match.group(3) else ''
            label = f"Đang phân tích phát hiện {match.group(1)}/{match.group(2)}{suffix}"
        elif raw.startswith('AI summary'):
            label = 'Đang tổng hợp và kiểm chứng Nhận xét tổng quan (Mục 4.2)'
        with self.lock:
            job = self.jobs[id_]
            cur_step = max(int(job.get('step') or 1), step or int(job.get('step') or 1))
            cur_pct = max(int(job.get('percent') or 5), pct or int(job.get('percent') or 5))
            events = (job.get('events', []) + [{'at': now(), 'text': label, 'step': cur_step, 'percent': cur_pct}])[-80:]
            self.update(id_, stage=label, step=cur_step, percent=cur_pct, stage_started_at=now(), events=events)

    def submit(self, body, filename, format_, note='', metadata=None):
        from .report_view import clean_metadata
        merged_meta = dict(metadata or {})
        if note and note.strip() and 'note' not in merged_meta:
            merged_meta['note'] = note.strip()
        metadata = clean_metadata(merged_meta)
        if not body or len(body) > MAX_UPLOAD:
            raise ValueError('File phải có nội dung và không vượt quá 10 MB.')
        if format_ not in ('auto', *SUPPORTED_FORMATS):
            raise ValueError('Định dạng không được hỗ trợ.')
        if len(note) > 1000:
            raise ValueError('Ghi chú tối đa 1000 ký tự.')
        with self.lock:
            if sum(j['status'] not in TERMINAL for j in self.jobs.values()) >= 4:
                raise ValueError('Hàng đợi đã có 4 file. Chờ một báo cáo hoàn tất rồi gửi tiếp.')
            id_ = secrets.token_hex(16)
            folder = self.directory / id_
            folder.mkdir()
            path = folder / 'input.scan'
            path.write_bytes(body)
            try:
                fmt = detect_format(path) if format_ == 'auto' else format_
                findings = load_findings(path, fmt)
                if len(findings) > 100:
                    raise ValueError('Mỗi báo cáo hỗ trợ tối đa 100 phát hiện. Hãy chia nhỏ file.')
            except Exception as exc:
                path.unlink(missing_ok=True)
                folder.rmdir()
                if isinstance(exc, ValueError) and str(exc).startswith(('PDF đầu', 'Chưa nhận', 'Mỗi báo cáo')):
                    raise
                raise ValueError('File không đúng cấu trúc ' + FORMATS.get(format_, 'công cụ') + '. Hãy chọn đúng định dạng hoặc kiểm tra file export; chưa gọi AI.') from None
            name = filename.replace('\\', '/').split('/')[-1]
            name = re.sub(r'[\x00-\x1f\x7f]', '', name)[:160] or 'kiem-thu'
            sha = hashlib.sha256(body).hexdigest()
            input_sources = [{
                'name': name,
                'format': fmt,
                'sha256': sha,
                'size_bytes': len(body),
                'finding_count': len(findings),
                'finding_ids': [str(f.id) for f in findings],
            }]
            job = {
                'id': id_,
                'filename': name,
                'report_metadata': metadata,
                'input_sources': input_sources,
                'format': fmt,
                'note': note,
                'status': 'queued',
                'stage': 'Đã nhận dữ liệu đầu vào, đang chờ xử lý',
                'step': 1,
                'percent': 5,
                'started_at': None,
                'stage_started_at': now(),
                'created_at': now(),
                'updated_at': now(),
                'count': len(findings),
                'size': len(body),
                'input_sha256': sha,
                'demo': self.demo,
                'events': [{'at': now(), 'text': f'Đã tiếp nhận I-01: {name} ({len(findings)} bản ghi)', 'step': 1, 'percent': 5}],
                'error': None,
                'summary': None,
            }
            self.jobs[id_] = job
            self._save(job)
            self.executor.submit(self._run, id_)
            return copy.deepcopy(job)

    def submit_bundle(self, payload, note='', metadata=None):
        from .report_view import clean_metadata
        import shutil
        merged_meta = dict(metadata or {})
        if note and note.strip() and 'note' not in merged_meta:
            merged_meta['note'] = note.strip()
        metadata = clean_metadata(merged_meta)
        if len(note) > 1000:
            raise ValueError('Ghi chú tối đa 1000 ký tự.')
        if not isinstance(payload, dict) or payload.get('bundle_version') != 1 or not isinstance(payload.get('files'), list):
            raise ValueError('Gói nhiều file không hợp lệ.')
        items = payload['files']
        if not 1 <= len(items) <= 10:
            raise ValueError('Mỗi lần gửi tối đa 10 file kiểm thử.')
        with self.lock:
            if sum(j['status'] not in TERMINAL for j in self.jobs.values()) >= 4:
                raise ValueError('Hàng đợi đã có 4 file. Chờ một báo cáo hoàn tất rồi gửi tiếp.')
            id_ = secrets.token_hex(16)
            folder = self.directory / id_
            inputs_dir = folder / 'inputs'
            inputs_dir.mkdir(parents=True)
            total_size = 0
            merged_rows = []
            seen_ids = set()
            safe_names = []
            detected_formats = []
            tools = []
            input_sources = []
            hasher = hashlib.sha256()
            try:
                for idx, item in enumerate(items):
                    if not isinstance(item, dict):
                        raise ValueError('Mục file trong gói không hợp lệ.')
                    raw_name = str(item.get('filename') or f'kiem-thu-{idx + 1}')
                    safe_name = re.sub(r'[\x00-\x1f\x7f]', '', raw_name.replace('\\', '/').split('/')[-1])[:120] or f'kiem-thu-{idx + 1}'
                    item_fmt = str(item.get('format') or 'auto')
                    if item_fmt not in ('auto', *SUPPORTED_FORMATS):
                        raise ValueError('Định dạng không được hỗ trợ.')
                    b64 = item.get('content_b64')
                    if not isinstance(b64, str) or not b64:
                        raise ValueError(f'File {safe_name} rỗng hoặc không hợp lệ.')
                    try:
                        data_bytes = base64.b64decode(b64, validate=True)
                    except Exception:
                        raise ValueError(f'Không giải mã được nội dung file {safe_name}.') from None
                    total_size += len(data_bytes)
                    if not data_bytes or total_size > MAX_UPLOAD:
                        raise ValueError('Tổng dung lượng các file phải lớn hơn 0 và không vượt quá 10 MB.')
                    raw_path = inputs_dir / f'{idx:02d}_{re.sub(r"[^A-Za-z0-9._-]", "_", safe_name)}'
                    raw_path.write_bytes(data_bytes)
                    hasher.update(safe_name.encode('utf-8') + b'\0' + data_bytes + b'\0')
                    fmt = detect_format(raw_path) if item_fmt == 'auto' else item_fmt
                    parsed = load_findings(raw_path, fmt)
                    safe_names.append(safe_name)
                    detected_formats.append(fmt)
                    src_fids = []
                    for f in parsed:
                        row = asdict(f)
                        row['evidence'] = list(row['evidence'])
                        base_id = row['id']
                        uid = base_id
                        n = 2
                        while uid in seen_ids:
                            uid = f'{base_id}#{n}'
                            n += 1
                        seen_ids.add(uid)
                        row['id'] = uid
                        src_fids.append(uid)
                        if row['tool'] not in tools:
                            tools.append(row['tool'])
                        merged_rows.append(row)
                    input_sources.append({
                        'name': safe_name,
                        'format': fmt,
                        'sha256': hashlib.sha256(data_bytes).hexdigest(),
                        'size_bytes': len(data_bytes),
                        'finding_count': len(parsed),
                        'finding_ids': src_fids,
                    })
                if len(merged_rows) > 100:
                    raise ValueError('Mỗi báo cáo hỗ trợ tối đa 100 phát hiện. Hãy chia nhỏ file.')
                normalized_doc = {'schema_version': 1, 'tool': ' + '.join(tools) if tools else 'multi-scanner', 'findings': merged_rows}
                scan_bytes = json.dumps(normalized_doc, ensure_ascii=False, indent=2).encode('utf-8')
                (folder / 'input.scan').write_bytes(scan_bytes)
            except Exception as exc:
                shutil.rmtree(folder, ignore_errors=True)
                if isinstance(exc, ValueError) and str(exc).startswith(('PDF đầu', 'Chưa nhận', 'Mỗi báo cáo', 'Mỗi lần', 'Tổng dung lượng', 'Gói nhiều', 'Định dạng', 'Không giải mã', 'File ')):
                    raise
                raise ValueError('Một trong các file gửi lên không đúng cấu trúc công cụ kiểm thử. Hãy kiểm tra lại từng file; chưa gọi AI.') from None
            display_name = (' + '.join(safe_names))[:160]
            job = {
                'id': id_,
                'filename': display_name,
                'report_metadata': metadata,
                'input_sources': input_sources,
                'format': 'normalized',
                'input_formats': list(dict.fromkeys(detected_formats)),
                'note': note,
                'status': 'queued',
                'step': 1,
                'percent': 5,
                'started_at': None,
                'stage_started_at': now(),
                'stage': f'Đã nhận {len(items)} nguồn dữ liệu (I-01..I-{len(items):02d}), đang chờ xử lý',
                'created_at': now(),
                'updated_at': now(),
                'count': len(merged_rows),
                'size': total_size,
                'input_sha256': hasher.hexdigest(),
                'demo': self.demo,
                'events': [{'at': now(), 'text': f'Đã gộp {len(items)} nguồn dữ liệu ({len(merged_rows)} bản ghi)', 'step': 1, 'percent': 5}],
                'error': None,
                'summary': None,
            }
            self.jobs[id_] = job
            self._save(job)
            self.executor.submit(self._run, id_)
            return copy.deepcopy(job)

    def _run(self, id_):
        import time as _time
        t0 = _time.monotonic()
        folder = self.directory / id_
        job = self.get(id_)
        try:
            init_stage = 'Đang chuẩn hóa dữ liệu đầu vào & dựng khung báo cáo 10 mục' if self.demo else 'Đang khởi tạo pipeline RAG & nạp kho OWASP chuyên biệt CSDL'
            with self.lock:
                cur = self.jobs[id_]
                ev = (cur.get('events', []) + [{'at': now(), 'text': init_stage, 'step': 2 if not self.demo else 1, 'percent': 10}])[-80:]
                self.update(id_, status='running', started_at=now(), stage_started_at=now(), step=2 if not self.demo else 1, percent=10, stage=init_stage, events=ev)
            if self.runner:
                paths = self.runner(folder / 'input.scan', folder / 'output', job, lambda m: self.progress(id_, m))
            elif self.demo:
                from .pipeline import run_report
                from .config import Settings
                self.progress(id_, '[step=3|pct=45] Đang ánh xạ CWE sang OWASP Top 10:2025 và đối chiếu khuyến nghị OWASP...')
                paths = run_report(
                    folder / 'input.scan', ROOT / 'data/raw/owasp/cards.json', folder / 'output',
                    Settings(), format_=job['format'], report_metadata=job.get('report_metadata'),
                    display_filename=job['filename'],
                )
                self.progress(id_, '[step=6|pct=95] Đang kết xuất Báo cáo 10 mục chuẩn PDF, Markdown và JSON...')
            else:
                from .official_report import run_corpus_report
                settings = self.settings_loader()
                paths = run_corpus_report(
                    folder / 'input.scan', folder / 'output', settings, format_=job['format'],
                    raw_directory=ROOT / 'data/raw/owasp/official/CheatSheetSeries-master/cheatsheets',
                    store_directory=ROOT / 'data/processed/owasp-official', offline=True,
                    progress=lambda m: self.progress(id_, m),
                    report_metadata=job.get('report_metadata'), display_filename=job['filename'],
                )

            report = json.loads(Path(paths[1]).read_text(encoding='utf-8'))
            if job.get('input_sources'):
                report['input_sources'] = job['input_sources']
                Path(paths[1]).write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
                (folder / 'output' / 'dbsec_report.md').write_text(render_dbsec_markdown(report), encoding='utf-8')
                render_pdf(report, Path(paths[2]))

            if not Path(paths[2]).is_file():
                raise RuntimeError('PDF missing')

            rows = report['findings']
            xss_dec_j = str((report.get('report_metadata') or {}).get('xss_decision') or '').strip().lower()
            eval_rows = [r for r in rows if not (xss_dec_j == 'drop' and r.get('kind') == 'observation')]
            analyses = [r.get('ai_analysis', {}).get('status') for r in eval_rows]
            reviewed_ok = sum(s == 'ai_reviewed' for s in analyses) if not self.demo else len(eval_rows)
            skipped = sum(s != 'ai_reviewed' for s in analyses) if not self.demo else 0
            summary_status = report.get('ai_summary', {}).get('status')
            selection_failures = sum(r.get('generation_status') in {'api_error', 'rejected_output'} for r in eval_rows)
            partial = not self.demo and bool(eval_rows) and (skipped or summary_status != 'ai_reviewed' or selection_failures)

            from .pentest_polish import sanitize_raw_scan_text
            try:
                raw_scan_bytes = (folder / 'input.scan').read_bytes()
                (folder / 'output' / 'sanitized_input.txt').write_text(
                    sanitize_raw_scan_text(raw_scan_bytes, report), encoding='utf-8'
                )
            except Exception:
                pass

            dbsec = prepare_dbsec_report(report)
            counts = dbsec['counts']
            preview = [{
                'id': f['id'],
                'title': f['title'][:140],
                'component': f['component'][:110],
                'severity': f['severity_key'],
                'severity_label': f['severity_label'],
                'state': f['state'],
                'owasp': f['owasp_category'],
                'guidance_count': len(f['rem_refs']),
            } for f in dbsec['findings'][:25]]

            summary = {
                'findings': counts['total'],
                'confirmed_findings': counts['confirmed'],
                'tentative_findings': counts['tentative'],
                'insufficient_findings': counts['insufficient'],
                'with_guidance': counts['with_guidance'],
                'scope_blocked': sum(r.get('owasp_top10', {}).get('status') != 'in_scope' for r in rows),
                'ai_reviewed': reviewed_ok,
                'ai_unavailable': skipped,
                'selection_failures': selection_failures,
                'summary_status': summary_status,
                'duration_sec': round(max(0.1, _time.monotonic() - t0), 1),
                'findings_preview': preview,
            }
            done_stage = 'Đã tạo Báo cáo 10 mục; có phần AI chưa hoàn tất' if partial else 'Báo cáo Kiểm thử Bảo mật CSDL (10 mục) đã sẵn sàng'
            with self.lock:
                cur = self.jobs[id_]
                ev = (cur.get('events', []) + [{'at': now(), 'text': done_stage, 'step': 6, 'percent': 100}])[-80:]
                self.update(id_, status='partial' if partial else 'completed', step=6, percent=100, stage=done_stage, summary=summary, events=ev)
        except Exception as exc:
            err_msg = safe_error(exc)
            with self.lock:
                cur = self.jobs[id_]
                ev = (cur.get('events', []) + [{'at': now(), 'text': 'Dừng xử lý: ' + err_msg, 'step': int(cur.get('step') or 1), 'percent': int(cur.get('percent') or 5)}])[-80:]
                self.update(id_, status='failed', stage='Chưa tạo được báo cáo', error=err_msg, events=ev)

    def close(self):
        self.executor.shutdown(wait=True)


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, manager):
        super().__init__(address, Handler)
        self.manager = manager
        self.token = secrets.token_urlsafe(32)
        host_ip, port = self.server_address[0], self.server_address[1]
        self.allow_preview = (host_ip == '0.0.0.0')
        self.allowed_hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}


class Handler(BaseHTTPRequestHandler):
    server_version = 'DBSecOWASPLocal'

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def send_data(self, status, body, content_type='application/json; charset=utf-8', extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        obj_src = "'self'" if content_type == 'application/pdf' else "'none'"
        ancestors = '' if self.server.allow_preview else " frame-ancestors 'none';"
        self.send_header(
            'Content-Security-Policy',
            f"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src {obj_src};{ancestors} base-uri 'none'; form-action 'self'",
        )
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def trusted(self, *, auth=False, write=False):
        if not self.server.allow_preview:
            if self.headers.get('Host') not in self.server.allowed_hosts:
                self.send_data(403, {'error': 'Chỉ cho phép truy cập qua localhost.'})
                return False
            origin = self.headers.get('Origin')
            if origin and origin not in {'http://' + h for h in self.server.allowed_hosts}:
                self.send_data(403, {'error': 'Yêu cầu khác nguồn bị từ chối.'})
                return False
            if self.headers.get('Sec-Fetch-Site') == 'cross-site':
                self.send_data(403, {'error': 'Yêu cầu khác nguồn bị từ chối.'})
                return False
        if auth:
            hdr_tok = self.headers.get('X-App-Token', '')
            q_tok = parse_qs(urlsplit(self.path).query).get('token', [''])[0] if self.server.allow_preview else ''
            try:
                cookie = SimpleCookie(self.headers.get('Cookie', ''))
                value = cookie.get('rag_local')
                good = bool(value and secrets.compare_digest(value.value, self.server.token))
            except Exception:
                good = False
            if not good and self.server.allow_preview and (hdr_tok or q_tok):
                good = secrets.compare_digest(hdr_tok or q_tok, self.server.token)
            if not good:
                self.send_data(401, {'error': 'Phiên web đã đổi. Tải lại trang để tiếp tục.'})
                return False
        if write and not secrets.compare_digest(self.headers.get('X-App-Token', ''), self.server.token):
            self.send_data(403, {'error': 'Yêu cầu không hợp lệ. Tải lại trang.'})
            return False
        return True

    def do_GET(self):
        if not self.trusted():
            return
        parsed_url = urlsplit(self.path)
        path = parsed_url.path
        assets = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}
        if path in assets:
            ext = {'/': 'text/html; charset=utf-8', '/app.js': 'text/javascript; charset=utf-8', '/style.css': 'text/css; charset=utf-8'}
            raw_asset = (Path(__file__).parent / 'web' / assets[path]).read_bytes()
            if path == '/' and self.server.allow_preview:
                raw_asset = raw_asset.replace(b'</head>', f'<meta name="app-token" content="{self.server.token}"></head>'.encode('utf-8'), 1)
            cookie_flags = 'SameSite=None; Secure; Path=/' if self.server.allow_preview else 'HttpOnly; SameSite=Strict; Path=/'
            headers = {'Set-Cookie': f'rag_local={self.server.token}; {cookie_flags}'} if path == '/' else {}
            return self.send_data(200, raw_asset, ext[path], headers)
        if not self.trusted(auth=True):
            return
        if path == '/api/config':
            issues = []
            model = ''
            provider = 'demo'
            configured = False
            if not self.server.manager.demo:
                try:
                    settings = self.server.manager.settings_loader()
                    provider = settings.resolved_provider
                    model = settings.active_model
                    if provider == 'ollama':
                        status = check_ollama(settings)
                        configured = bool(status['ok'])
                        if status['error']:
                            issues.append(status['error'])
                    else:
                        configured = bool(settings.api_key and model)
                        if not configured:
                            issues.append('Đặt LLM_PROVIDER=ollama và OLLAMA_MODEL=qwen2.5:7b trong .env để chạy Ollama local (hoặc cấu hình GEMINI_API_KEY + GEMINI_CHAT_MODEL).')
                except Exception as exc:
                    issues.append('Không đọc được .env (' + str(exc) + '). Kiểm tra cấu hình trong .env.')
                if not self.server.manager.runner:
                    if not (ROOT / 'data/processed/owasp-official/vector_store.meta.json').is_file():
                        configured = False
                        issues.append('Chưa thấy kho vector OWASP: data/processed/owasp-official. Hãy chạy start-web.bat hoặc ingest_documents.py.')
                    if not (ROOT / 'data/raw/owasp/official/CheatSheetSeries-master/cheatsheets').is_dir():
                        configured = False
                        issues.append('Chưa thấy tài liệu Cheat Sheet Series trong data/raw/owasp/official.')
            return self.send_data(200, {
                'token': self.server.token,
                'demo': self.server.manager.demo,
                'provider': provider,
                'configured': configured or self.server.manager.demo,
                'model': model,
                'issues': issues,
                'formats': FORMATS,
                'max_bytes': MAX_UPLOAD,
            })
        if path == '/api/jobs':
            return self.send_data(200, self.server.manager.list())
        match = re.fullmatch(r'/api/jobs/([a-f0-9]{32})(?:/(pdf|json|md|log|trace|trace-txt))?', path)
        if match:
            try:
                job = self.server.manager.get(match[1])
            except KeyError:
                return self.send_data(404, {'error': 'Không tìm thấy phiên phân tích.'})
            if not match[2]:
                return self.send_data(200, job)
            kind = match[2]
            if kind in {'trace', 'trace-txt'}:
                out_folder = self.server.manager.directory / match[1] / 'output'
                if kind == 'trace':
                    tf_json = out_folder / 'ai_trace.json'
                    if tf_json.is_file():
                        try:
                            return self.send_data(200, json.loads(tf_json.read_text(encoding='utf-8')))
                        except Exception:
                            pass
                    return self.send_data(200, {'mode': 'demo' if job.get('demo') else 'live', 'model': '', 'from_cache': False, 'call_count': 0, 'entries': []})
                tf_txt = out_folder / 'ai_trace.txt'
                if tf_txt.is_file():
                    raw_txt = tf_txt.read_bytes()
                else:
                    from .llm import format_ai_trace_text
                    raw_txt = format_ai_trace_text({'mode': 'demo' if job.get('demo') else 'live', 'model': '', 'from_cache': False, 'entries': []}).encode('utf-8')
                return self.send_data(200, raw_txt, 'text/plain; charset=utf-8', {'Content-Disposition': f'attachment; filename="lenh-gui-ai-{match[1][:8]}.txt"'})
            if job['status'] not in {'completed', 'partial'}:
                return self.send_data(409, {'error': 'Báo cáo chưa sẵn sàng.'})
            fname = {'md': 'dbsec_report.md', 'log': 'sanitized_input.txt'}.get(kind, 'report.' + kind)
            file = self.server.manager.directory / match[1] / 'output' / fname
            if not file.is_file():
                return self.send_data(404, {'error': 'Không tìm thấy file báo cáo.'})
            inline = kind == 'pdf' and parse_qs(parsed_url.query).get('inline', ['0'])[0] == '1'
            disp = 'inline' if inline else 'attachment'
            ctype = {
                'pdf': 'application/pdf',
                'json': 'application/json; charset=utf-8',
                'md': 'text/markdown; charset=utf-8',
                'log': 'text/plain; charset=utf-8',
            }[kind]
            out_name_map = {
                'pdf': f'bao-cao-bao-mat-csdl-{match[1][:8]}.pdf',
                'md': f'bao-cao-bao-mat-csdl-{match[1][:8]}.md',
                'json': f'du-lieu-bao-cao-{match[1][:8]}.json',
                'log': f'du-lieu-da-lam-sach-{match[1][:8]}.txt',
            }
            return self.send_data(200, file.read_bytes(), ctype, {'Content-Disposition': f'{disp}; filename="{out_name_map[kind]}"'})
        self.send_data(404, {'error': 'Không tìm thấy đường dẫn.'})

    def do_POST(self):
        if not self.trusted(auth=True, write=True):
            return
        query = urlsplit(self.path)
        if query.path != '/api/jobs':
            return self.send_data(404, {'error': 'Không tìm thấy đường dẫn.'})
        if self.headers.get('Transfer-Encoding'):
            return self.send_data(400, {'error': 'Không hỗ trợ kiểu truyền dữ liệu này.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.send_data(400, {'error': 'Kích thước file không hợp lệ.'})
        params = parse_qs(query.query)
        is_bundle = params.get('bundle', ['0'])[0] == '1'
        limit = MAX_BUNDLE_BODY if is_bundle else MAX_UPLOAD
        if not 0 < length <= limit:
            return self.send_data(413, {'error': 'File phải có nội dung và không vượt quá 10 MB.'})
        filename = params.get('filename', ['kiem-thu'])[0]
        fmt = params.get('format', ['auto'])[0]
        note = params.get('note', [''])[0]
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                return self.send_data(400, {'error': 'Tải lên chưa đầy đủ. Hãy gửi lại file.'})
            meta = json.loads(params.get('metadata', ['{}'])[0])
            if is_bundle:
                job = self.server.manager.submit_bundle(json.loads(body.decode('utf-8')), note, meta)
            else:
                job = self.server.manager.submit(body, filename, fmt, note, meta)
        except ValueError as exc:
            return self.send_data(400, {'error': str(exc)})
        except Exception:
            return self.send_data(500, {'error': 'Không lưu được file. Kiểm tra quyền ghi hoặc dung lượng ổ đĩa.'})
        self.send_data(202, job)
