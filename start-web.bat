@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment missing. See UPGRADE_V09.md for setup.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" scripts\web.py
pause
