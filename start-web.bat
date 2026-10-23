@echo off
chcp 65001 >nul
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" goto have_venv

echo Dang tao moi truong Python .venv lan dau...
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 goto make_venv_python
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 goto make_venv_py
for %%V in (Python314 Python313 Python312 Python311) do (
  if exist "%LOCALAPPDATA%\Programs\Python\%%V\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\%%V\python.exe" -m venv .venv
    if exist ".venv\Scripts\python.exe" goto have_venv
  )
)
goto no_python

:make_venv_python
python -m venv .venv
if exist ".venv\Scripts\python.exe" goto have_venv
goto no_python

:make_venv_py
py -3 -m venv .venv
if exist ".venv\Scripts\python.exe" goto have_venv
goto no_python

:have_venv
if not exist ".env" copy /y ".env.example" ".env" >nul

echo %* | findstr /i /c:"--demo" >nul
if not errorlevel 1 goto check_demo_deps

".venv\Scripts\python.exe" -c "import urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:11434/api/tags', timeout=1.5).read()" >nul 2>&1
if not errorlevel 1 goto check_deps

if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" goto boot_local_ollama
where ollama >nul 2>&1
if errorlevel 1 goto check_deps
echo Dang bat Ollama chay nen...
start "" /b ollama serve >nul 2>&1
timeout /t 3 /nobreak >nul
goto check_deps

:boot_local_ollama
echo Dang bat Ollama chay nen...
start "" /b "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" serve >nul 2>&1
timeout /t 3 /nobreak >nul

:check_deps
".venv\Scripts\python.exe" -c "import sentence_transformers, dotenv, reportlab" >nul 2>&1
if errorlevel 1 goto install_deps

:check_store
if not exist "data\raw\owasp\official\CheatSheetSeries-master\cheatsheets" goto run_server
".venv\Scripts\python.exe" -c "import sys; sys.path.insert(0, 'src'); from pathlib import Path; from rag.config import load_settings; from rag.document_store import DocumentVectorStore; raw = Path('data/raw/owasp/official/CheatSheetSeries-master/cheatsheets'); store = DocumentVectorStore.load(Path('data/processed/owasp-official'), load_settings()); store.verify_corpus(raw)" >nul 2>&1
if not errorlevel 1 goto run_server
echo [1/2] Dang tao/cap nhat kho vector OWASP chuyen biet CSDL 25 tai lieu - khoang 20-40 giay...
".venv\Scripts\python.exe" scripts\ingest_documents.py --raw data\raw\owasp\official\CheatSheetSeries-master\cheatsheets --output data\processed\owasp-official
if errorlevel 1 goto ingest_failed
goto run_server

:check_demo_deps
".venv\Scripts\python.exe" -c "import reportlab" >nul 2>&1
if not errorlevel 1 goto run_server
echo Dang cai dat thu vien xuat PDF cho che do demo...
".venv\Scripts\python.exe" -m pip install -e .
if errorlevel 1 goto deps_failed

:run_server
echo Dang khoi dong Web UI tai http://127.0.0.1:8765 ...
".venv\Scripts\python.exe" scripts\web.py %*
pause
exit /b 0

:install_deps
echo Dang cai dat thu vien embedding E5 va PDF cho .venv lan dau - vui long cho vai phut...
".venv\Scripts\python.exe" -m pip install -e ".[retrieval,pdf]"
if errorlevel 1 goto deps_failed
goto check_store

:no_python
echo Khong tim thay Python 3.11 tro len. Hay cai Python 3.12 tu python.org.
pause
exit /b 1

:deps_failed
echo Khong cai duoc thu vien Python. Kiem tra ket noi internet roi thu lai.
pause
exit /b 1

:ingest_failed
echo Khong tao duoc kho vector OWASP. Kiem tra ket noi internet lan dau de tai model E5 roi thu lai.
pause
exit /b 1
