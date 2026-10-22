"""Run the single-user local chat interface. Existing .env/corpus are reused."""
import argparse
import json
import threading
import urllib.request
import webbrowser
from _bootstrap import ROOT
from rag.config import load_settings
from rag.official_report import load_corpus_runtime
from rag.web_server import JobManager, LocalServer


def _background_warmup():
    """Pre-load the 25-sheet DB security vector store + E5 model + local Ollama weights in background."""
    try:
        settings = load_settings()
        raw = ROOT / 'data/raw/owasp/official/CheatSheetSeries-master/cheatsheets'
        store = ROOT / 'data/processed/owasp-official'
        if (store / 'vector_store.meta.json').is_file() and raw.is_dir():
            load_corpus_runtime(raw, store, settings, offline=False)
        if settings.resolved_provider == 'ollama' and settings.ollama_model:
            req = urllib.request.Request(
                f"{settings.ollama_base_url.rstrip('/')}/api/generate",
                data=json.dumps({
                    'model': settings.ollama_model,
                    'prompt': 'hi',
                    'stream': False,
                    'keep_alive': '30m',
                    'options': {'num_predict': 1},
                }).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
            )
            with urllib.request.urlopen(req, timeout=45):
                pass
    except Exception:
        pass


if __name__=='__main__':
    p=argparse.ArgumentParser(description='Local pentest report chatbot')
    p.add_argument('--host',default='127.0.0.1')
    p.add_argument('--port',type=int,default=8765)
    p.add_argument('--no-browser',action='store_true')
    p.add_argument('--demo',action='store_true',help='Explicit offline UI test with existing demo cards, no AI')
    args=p.parse_args()
    if not 1024<=args.port<=65535:p.error('Port must be between 1024 and 65535')
    manager=JobManager(ROOT/'data/web/jobs',demo=args.demo)
    try:server=LocalServer((args.host,args.port),manager)
    except OSError:
        manager.close();p.exit(1,'Port unavailable. Try: python scripts/web.py --port 8766\n')
    if not args.demo:
        threading.Thread(target=_background_warmup, daemon=True, name='rag-warmup').start()
    url=f'http://127.0.0.1:{args.port}'
    print(('DEMO ONLY - NO AI\n' if args.demo else '')+f'Open: {url}\nPress Ctrl+C to stop.',flush=True)
    if not args.no_browser:webbrowser.open(url)
    try:server.serve_forever()
    except KeyboardInterrupt:print('\nStopping web. Waiting for the current report to finish...',flush=True)
    finally:server.server_close();manager.close()
