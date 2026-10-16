@echo off
rem Update the project to the newest code on GitHub.
rem Local files (.env, data\, .venv) are never touched.
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================
echo   CAP NHAT CODE DU AN
echo ============================================
echo.

git rev-parse --git-dir >nul 2>&1
if errorlevel 1 (
  echo [LOI] Thu muc nay khong phai repo git, hoac chua cai Git.
  echo       Chua cai Git: https://git-scm.com/download/win
  echo       Dang dung ban ZIP: hay dung git clone, xem README.md.
  echo.
  pause
  exit /b 1
)

set "BEFORE="
for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set "BEFORE=%%i"
echo Ban dang o commit: !BEFORE!
echo Dang kiem tra ban moi tren GitHub...
echo.

git fetch origin
if errorlevel 1 (
  echo [LOI] Khong ket noi duoc GitHub. Kiem tra mang roi chay lai.
  echo.
  pause
  exit /b 1
)

rem Nhanh dich: neu nhanh lam viec con hon main thi dung nhanh do,
rem con khong (da gop vao main) thi dung main.
set "EXTRA=0"
for /f "delims=" %%c in ('git rev-list --count origin/main..origin/arena/e28181c3-dbs-learning 2^>nul') do set "EXTRA=%%c"
set "TARGET=main"
if not "!EXTRA!"=="0" set "TARGET=arena/e28181c3-dbs-learning"
if "!EXTRA!"=="" set "TARGET=main"

echo Nhanh se cap nhat: !TARGET!
echo.

rem File ma git quan ly dang bi sua doi thi canh bao, khong tu y xoa
git diff-index --quiet HEAD -- >nul 2>&1
if errorlevel 1 (
  echo [CANH BAO] Ban co thay doi trong file ma git quan ly:
  git status --short
  echo.
  echo   Chon 1 trong 2 lenh sau roi chay lai:
  echo     git stash          ^(tam cat, lay lai bang git stash pop^)
  echo     git checkout -- .  ^(bo het thay doi, khong lay lai duoc^)
  echo.
  pause
  exit /b 1
)

set "NOW="
for /f "delims=" %%i in ('git rev-parse --abbrev-ref HEAD 2^>nul') do set "NOW=%%i"
if not "!NOW!"=="!TARGET!" (
  echo Dang chuyen sang nhanh !TARGET! ...
  git switch "!TARGET!" >nul 2>&1
  if errorlevel 1 git checkout "!TARGET!"
  if errorlevel 1 (
    echo [LOI] Khong chuyen duoc nhanh. Chay tay: git switch !TARGET!
    echo.
    pause
    exit /b 1
  )
)

git pull --ff-only
if errorlevel 1 (
  echo.
  echo [LOI] Khong cap nhat duoc. Xem thong bao phia tren.
  echo       Thuong gap: mang chap chon, hoac lich su nhanh da doi tren GitHub.
  echo       Khi do chay: git fetch origin  roi  git reset --hard origin/!TARGET!
  echo.
  pause
  exit /b 1
)

set "AFTER="
for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set "AFTER=%%i"
echo.
echo ============================================
if "!BEFORE!"=="!AFTER!" (
  echo   BAN DANG O BAN MOI NHAT: !AFTER!
) else (
  echo   DA CAP NHAT: !BEFORE!  -^>  !AFTER!
  echo.
  git log --oneline "!BEFORE!..!AFTER!"
)
echo ============================================
echo.
echo .env, data\ va .venv KHONG bi thay doi.

set "DEPCHANGED="
if not "!BEFORE!"=="!AFTER!" (
  for /f "delims=" %%l in ('git diff "!BEFORE!" "!AFTER!" -- pyproject.toml requirements.txt 2^>nul ^| findstr /b /r "^[+-][^+-]" ^| findstr /v /c:"version ="') do set "DEPCHANGED=1"
  if defined DEPCHANGED (
    echo.
    echo   [CAN LAM] Danh sach thu vien da doi. Chay lenh sau:
    echo     .\.venv\Scripts\python.exe -m pip install -r requirements.txt
  ) else (
    echo   Khong can cai lai thu vien.
  )
)
echo.
pause
