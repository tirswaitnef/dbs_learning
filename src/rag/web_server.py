"""Single-user loopback web UI. No shell execution, public hosting or external assets."""
import copy
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
from .parsers import SUPPORTED_FORMATS, load_findings

MAX_UPLOAD = 10 * 1024 * 1024
TERMINAL = {'completed', 'partial', 'failed'}
FORMATS = {'normalized':'JSON chuẩn hóa', 'zap':'OWASP ZAP · JSON', 'burp':'Burp Suite · XML',
           'nuclei':'Nuclei · JSONL', 'sqlmap-log':'sqlmap · log', 'nessus':'Nessus · XML', 'nmap':'Nmap · XML'}


def now(): return datetime.now(timezone.utc).isoformat()


def detect_format(path):
    raw=Path(path).read_bytes()
    if raw.startswith(b'%PDF'):
        raise ValueError('PDF đầu vào chưa được hỗ trợ. Hãy xuất JSON, XML, JSONL hoặc log từ công cụ; PDF là báo cáo đầu ra.')
    text=raw.decode('utf-8-sig',errors='replace').lstrip()
    try:
        data=json.loads(text)
        if isinstance(data,dict):
            if data.get('schema_version')==1:return 'normalized'
            if isinstance(data.get('site'),list):return 'zap'
            if 'template-id' in data and isinstance(data.get('info'),dict):return 'nuclei'
    except ValueError: pass
    # Detect only; strict safe XML parser runs immediately afterward.
    for root,fmt in [('issues','burp'),('NessusClientData_v2','nessus'),('nmaprun','nmap')]:
        if re.search(r'<'+root+r'(?:\s|>)',text[:4096]):return fmt
    try:
        first=json.loads(next(line for line in text.splitlines() if line.strip()))
        if isinstance(first,dict) and 'template-id' in first:return 'nuclei'
    except (ValueError,StopIteration):pass
    if re.search(r'(?m)^Parameter:\s*.+\(.+\)\s*$',text) or 'all tested parameters do not appear to be injectable' in text.lower():return 'sqlmap-log'
    raise ValueError('Chưa nhận diện được định dạng. Chọn đúng công cụ trong ô Định dạng hoặc dùng JSON chuẩn hóa của project.')


def safe_error(exc):
    if isinstance(exc,FileNotFoundError):return 'Thiếu file cấu hình, tài liệu OWASP hoặc vector store. Kiểm tra .env và kho đã ingest.'
    if isinstance(exc,ImportError):return 'Thiếu thư viện Python. Chạy .\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt rồi khởi động lại web.'
    text=str(exc).lower()
    if 'gemini' in text or 'api_key' in text or 'chat_model' in text:return 'Chưa gọi được Gemini. Kiểm tra API key, model và quota trong .env.'
    if any(x in text for x in ('store','corpus','chunk','embedding','model limit','revision')):return 'Kho vector, tài liệu hoặc cấu hình embedding chưa khớp. Giữ chunk/overlap đúng với lần ingest và kiểm tra kho OWASP.'
    return 'Không hoàn tất xử lý ('+type(exc).__name__+'). File đã được giữ cục bộ. Kiểm tra định dạng, cấu hình và thử lại bằng một lần gửi mới.'


class JobManager:
    def __init__(self,directory,*,demo=False,runner=None,settings_loader=load_settings):
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.demo=demo;self.runner=runner;self.settings_loader=settings_loader
        self.lock=threading.RLock();self.executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='report')
        self.jobs={}
        for path in self.directory.glob('*/job.json'):
            if not re.fullmatch(r'[a-f0-9]{32}',path.parent.name):continue
            try:
                job=json.loads(path.read_text(encoding='utf-8'))
                if job.get('id')!=path.parent.name:continue
                if job.get('status') not in TERMINAL:
                    job.update(status='failed',stage='Phiên xử lý bị gián đoạn',error='Ứng dụng đã dừng trước khi hoàn tất. Gửi lại file để tạo một lần xử lý mới.',updated_at=now())
                    self._save(job)
                self.jobs[job['id']]=job
            except (OSError,ValueError):continue

    def _save(self,job):
        folder=self.directory/job['id'];folder.mkdir(exist_ok=True)
        tmp=folder/'job.tmp';tmp.write_text(json.dumps(job,ensure_ascii=False,indent=2),encoding='utf-8')
        os.replace(tmp,folder/'job.json')

    def get(self,id_):
        with self.lock:
            if id_ not in self.jobs:raise KeyError(id_)
            return copy.deepcopy(self.jobs[id_])

    def list(self):
        with self.lock:return [copy.deepcopy(j) for j in sorted(self.jobs.values(),key=lambda j:j['created_at'],reverse=True)[:100]]

    def update(self,id_,**values):
        with self.lock:
            job=self.jobs[id_];job.update(values,updated_at=now());self._save(job)

    def progress(self,id_,message):
        label=message
        match=re.match(r'AI analysis (\d+)/(\d+)',message)
        if match:label=f"Đang phân tích phát hiện {match[1]}/{match[2]}"
        elif message.startswith('AI summary'):label='Đang viết và rà soát tổng quan'
        with self.lock:
            job=self.jobs[id_]
            events=(job.get('events',[])+[{'at':now(),'text':label}])[-60:]
            self.update(id_,stage=label,events=events)

    def submit(self,body,filename,format_,note='',metadata=None):
        from .report_view import clean_metadata
        metadata=clean_metadata(metadata)
        if not body or len(body)>MAX_UPLOAD:raise ValueError('File phải có nội dung và không vượt quá 10 MB.')
        if format_ not in ('auto',*SUPPORTED_FORMATS):raise ValueError('Định dạng không được hỗ trợ.')
        if len(note)>1000:raise ValueError('Ghi chú tối đa 1000 ký tự.')
        with self.lock:
            if sum(j['status'] not in TERMINAL for j in self.jobs.values())>=4:raise ValueError('Hàng đợi đã có 4 file. Chờ một báo cáo hoàn tất rồi gửi tiếp.')
            id_=secrets.token_hex(16);folder=self.directory/id_;folder.mkdir()
            path=folder/'input.scan';path.write_bytes(body)
            try:
                fmt=detect_format(path) if format_=='auto' else format_
                findings=load_findings(path,fmt)
                if len(findings)>100:raise ValueError('Mỗi báo cáo hỗ trợ tối đa 100 phát hiện. Hãy chia nhỏ file.')
            except Exception as exc:
                path.unlink(missing_ok=True);folder.rmdir()
                if isinstance(exc,ValueError) and (str(exc).startswith(('PDF đầu','Chưa nhận','Mỗi báo cáo'))):raise
                raise ValueError('File không đúng cấu trúc '+FORMATS.get(format_,'công cụ')+'. Hãy chọn đúng định dạng hoặc kiểm tra file export; chưa gọi AI.') from None
            # User filename is display-only; never a filesystem path.
            name=filename.replace('\\','/').split('/')[-1]
            name=re.sub(r'[\x00-\x1f\x7f]','',name)[:160] or 'kiem-thu'
            job={'id':id_,'filename':name,'report_metadata':metadata,'format':fmt,'note':note,'status':'queued','stage':'Đã nhận file, đang chờ xử lý',
                 'created_at':now(),'updated_at':now(),'count':len(findings),'size':len(body),
                 'input_sha256':hashlib.sha256(body).hexdigest(),'demo':self.demo,'events':[],'error':None,'summary':None}
            self.jobs[id_]=job;self._save(job)
            self.executor.submit(self._run,id_)
            return copy.deepcopy(job)

    def _run(self,id_):
        folder=self.directory/id_;job=self.get(id_)
        try:
            self.update(id_,status='running',stage='Đang chuẩn bị báo cáo' if self.demo else 'Đang nạp kho OWASP và tìm hướng dẫn phù hợp')
            if self.runner:
                paths=self.runner(folder/'input.scan',folder/'output',job,lambda m:self.progress(id_,m))
            elif self.demo:
                from .pipeline import run_report
                from .config import Settings
                paths=run_report(folder/'input.scan',ROOT/'data/raw/owasp/cards.json',folder/'output',Settings(),format_=job['format'],report_metadata=job.get('report_metadata'),display_filename=job['filename'])
            else:
                from .official_report import run_corpus_report
                settings=self.settings_loader()
                paths=run_corpus_report(folder/'input.scan',folder/'output',settings,format_=job['format'],
                    raw_directory=ROOT/'data/raw/owasp/official/CheatSheetSeries-master/cheatsheets',
                    store_directory=ROOT/'data/processed/owasp-official',offline=True,progress=lambda m:self.progress(id_,m),report_metadata=job.get('report_metadata'),display_filename=job['filename'])
            report=json.loads(Path(paths[1]).read_text(encoding='utf-8'))
            if not Path(paths[2]).is_file():raise RuntimeError('PDF missing')
            rows=report['findings']
            analyses=[r.get('ai_analysis',{}).get('status') for r in rows]
            skipped=sum(s!='ai_reviewed' for s in analyses) if not self.demo else 0
            summary_status=report.get('ai_summary',{}).get('status')
            selection_failures=sum(r.get('generation_status') in {'api_error','rejected_output'} for r in rows)
            partial=not self.demo and bool(rows) and (skipped or summary_status!='ai_reviewed' or selection_failures)
            summary={'findings':len(rows),'with_guidance':sum(bool(r.get('guidance')) for r in rows),
                     'scope_blocked':sum(r.get('owasp_top10',{}).get('status')!='in_scope' for r in rows),
                     'ai_unavailable':skipped,'selection_failures':selection_failures,'summary_status':summary_status}
            self.update(id_,status='partial' if partial else 'completed',stage='Đã tạo PDF; có phần AI chưa hoàn tất' if partial else 'Báo cáo PDF đã sẵn sàng',summary=summary)
        except Exception as exc:
            self.update(id_,status='failed',stage='Chưa tạo được báo cáo',error=safe_error(exc))

    def close(self):self.executor.shutdown(wait=True)


class LocalServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,manager):
        super().__init__(address,Handler)
        self.manager=manager;self.token=secrets.token_urlsafe(32)
        port=self.server_address[1]
        self.allowed_hosts={f'127.0.0.1:{port}',f'localhost:{port}'}


class Handler(BaseHTTPRequestHandler):
    server_version='PentestReportLocal'
    def log_message(self,*args):pass
    def setup(self):
        super().setup();self.connection.settimeout(30)

    def send_data(self,status,body,content_type='application/json; charset=utf-8',extra=None):
        if isinstance(body,(dict,list)):body=json.dumps(body,ensure_ascii=False).encode()
        elif isinstance(body,str):body=body.encode()
        self.send_response(status)
        self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for k,v in (extra or {}).items():self.send_header(k,v)
        self.end_headers()
        try:self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError):pass

    def trusted(self,*,auth=False,write=False):
        if self.headers.get('Host') not in self.server.allowed_hosts:
            self.send_data(403,{'error':'Chỉ cho phép truy cập qua localhost.'});return False
        origin=self.headers.get('Origin')
        if origin and origin not in {'http://'+h for h in self.server.allowed_hosts}:
            self.send_data(403,{'error':'Yêu cầu khác nguồn bị từ chối.'});return False
        if self.headers.get('Sec-Fetch-Site')=='cross-site':
            self.send_data(403,{'error':'Yêu cầu khác nguồn bị từ chối.'});return False
        if auth:
            try:
                cookie=SimpleCookie(self.headers.get('Cookie',''));value=cookie.get('rag_local')
                good=value and secrets.compare_digest(value.value,self.server.token)
            except Exception:good=False
            if not good:
                self.send_data(401,{'error':'Phiên web đã đổi. Tải lại trang để tiếp tục.'});return False
        if write and not secrets.compare_digest(self.headers.get('X-App-Token',''),self.server.token):
            self.send_data(403,{'error':'Yêu cầu không hợp lệ. Tải lại trang.'});return False
        return True

    def do_GET(self):
        if not self.trusted():return
        path=urlsplit(self.path).path
        assets={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
        if path in assets:
            ext={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}
            headers={'Set-Cookie':f'rag_local={self.server.token}; HttpOnly; SameSite=Strict; Path=/'} if path=='/' else {}
            return self.send_data(200,(Path(__file__).parent/'web'/assets[path]).read_bytes(),ext[path],headers)
        if not self.trusted(auth=True):return
        if path=='/api/config':
            issues=[];model='';configured=False
            if not self.server.manager.demo:
                try:
                    settings=self.server.manager.settings_loader();model=settings.chat_model
                    configured=bool(settings.api_key and model)
                    if not configured:issues.append('Thêm GEMINI_API_KEY và GEMINI_CHAT_MODEL vào .env, sau đó khởi động lại web.')
                except Exception:issues.append('Không đọc được .env. Kiểm tra cấu hình và thư viện Python.')
                if not (ROOT/'data/processed/owasp-official').is_dir():issues.append('Chưa thấy kho vector OWASP: data/processed/owasp-official.')
                if not (ROOT/'data/raw/owasp/official/CheatSheetSeries-master/cheatsheets').is_dir():issues.append('Chưa thấy tài liệu Cheat Sheet Series đã ingest.')
            return self.send_data(200,{'token':self.server.token,'demo':self.server.manager.demo,'configured':configured or self.server.manager.demo,'model':model,'issues':issues,'formats':FORMATS,'max_bytes':MAX_UPLOAD})
        if path=='/api/jobs':return self.send_data(200,self.server.manager.list())
        match=re.fullmatch(r'/api/jobs/([a-f0-9]{32})(?:/(pdf|json))?',path)
        if match:
            try:job=self.server.manager.get(match[1])
            except KeyError:return self.send_data(404,{'error':'Không tìm thấy cuộc trò chuyện.'})
            if not match[2]:return self.send_data(200,job)
            if job['status'] not in {'completed','partial'}:return self.send_data(409,{'error':'Báo cáo chưa sẵn sàng.'})
            kind=match[2];file=self.server.manager.directory/match[1]/'output'/('report.'+kind)
            if not file.is_file():return self.send_data(404,{'error':'Không tìm thấy file báo cáo.'})
            return self.send_data(200,file.read_bytes(),'application/pdf' if kind=='pdf' else 'application/json',{'Content-Disposition':f'attachment; filename="bao-cao-{match[1][:8]}.{kind}"'})
        self.send_data(404,{'error':'Không tìm thấy đường dẫn.'})

    def do_POST(self):
        if not self.trusted(auth=True,write=True):return
        query=urlsplit(self.path)
        if query.path!='/api/jobs':return self.send_data(404,{'error':'Không tìm thấy đường dẫn.'})
        if self.headers.get('Transfer-Encoding'):return self.send_data(400,{'error':'Không hỗ trợ kiểu truyền dữ liệu này.'})
        try:length=int(self.headers.get('Content-Length','0'))
        except ValueError:return self.send_data(400,{'error':'Kích thước file không hợp lệ.'})
        if not 0<length<=MAX_UPLOAD:return self.send_data(413,{'error':'File phải có nội dung và không vượt quá 10 MB.'})
        params=parse_qs(query.query)
        filename=params.get('filename',['kiem-thu'])[0];fmt=params.get('format',['auto'])[0]
        note=params.get('note',[''])[0]
        try:
            body=self.rfile.read(length)
            if len(body)!=length:return self.send_data(400,{'error':'Tải lên chưa đầy đủ. Hãy gửi lại file.'})
            job=self.server.manager.submit(body,filename,fmt,note,json.loads(params.get('metadata',['{}'])[0]))
        except ValueError as exc:return self.send_data(400,{'error':str(exc)})
        except Exception:return self.send_data(500,{'error':'Không lưu được file. Kiểm tra quyền ghi hoặc dung lượng ổ đĩa.'})
        self.send_data(202,job)
