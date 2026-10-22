"""Run the single-user local chat interface. Existing .env/corpus are reused."""
import argparse
import webbrowser
from _bootstrap import ROOT
from rag.web_server import JobManager, LocalServer

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
    url=f'http://127.0.0.1:{args.port}'
    print(('DEMO ONLY - NO AI\n' if args.demo else '')+f'Open: {url}\nPress Ctrl+C to stop.',flush=True)
    if not args.no_browser:webbrowser.open(url)
    try:server.serve_forever()
    except KeyboardInterrupt:print('\nStopping web. Waiting for the current report to finish...',flush=True)
    finally:server.server_close();manager.close()
