@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" goto no_venv

if not exist ".env" copy /y ".env.example" ".env" >nul

echo %* | findstr /i /c:"--demo" >nul
if not errorlevel 1 goto run_server

".venv\Scripts\python.exe" -c "import sentence_transformers, dotenv, reportlab" >nul 2>&1
if errorlevel 1 goto install_deps

:check_store
if exist "data\processed\owasp-official\vector_store.meta.json" goto run_server
if not exist "data\raw\owasp\official\CheatSheetSeries-master\cheatsheets" goto run_server
echo [1/2] Dang tao kho vector OWASP Cheat Sheet Series lan dau - vui long cho 1-3 phut...
".venv\Scripts\python.exe" scripts\ingest_documents.py --raw data\raw\owasp\official\CheatSheetSeries-master\cheatsheets --output data\processed\owasp-official
if errorlevel 1 goto ingest_failed

:run_server
echo Dang khoi dong Web UI tai http://127.0.0.1:8765 ...
".venv\Scripts\python.exe" scripts\web.py %*
pause
exit /b 0

:install_deps
echo Dang cai dat thu vien embedding va PDF cho .venv...
".venv\Scripts\python.exe" -m pip install -e ".[retrieval,pdf]"
if errorlevel 1 goto deps_failed
goto check_store

:no_venv
echo Chua co moi truong .venv. Chay: python -m venv .venv
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
