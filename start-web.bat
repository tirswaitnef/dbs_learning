@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment missing. See README.md, section "Cai dat day du".
  pause
  exit /b 1
)
".venv\Scripts\python.exe" scripts\web.py
pause
