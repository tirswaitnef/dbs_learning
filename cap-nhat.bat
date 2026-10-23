@echo off
rem Update the project to the newest code on GitHub.
rem Local files (.env, data\, .venv) are never touched.
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem DBS_AUTO=1 de chay tu dong, khong dung cho nguoi xem
set "PAUSE=pause"
if "%DBS_AUTO%"=="1" set "PAUSE=echo."

echo ============================================
echo   CAP NHAT CODE DU AN
echo ============================================
echo.

where git >nul 2>&1
if errorlevel 1 if exist "%ProgramFiles%\Git\cmd\git.exe" set "PATH=%PATH%;%ProgramFiles%\Git\cmd"
where git >nul 2>&1
if errorlevel 1 if exist "%LOCALAPPDATA%\Programs\Git\cmd\git.exe" set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Git\cmd"

git rev-parse --git-dir >nul 2>&1
if errorlevel 1 (
  echo [LOI] Thu muc nay khong phai repo git, hoac chua cai Git.
  echo       Chua cai Git: https://git-scm.com/download/win
  echo       Dang dung ban ZIP: hay dung git clone, xem README.md.
  echo.
  %PAUSE%
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
  %PAUSE%
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
rem Dung git status: git diff-index khong tu lam moi stat cache nen bao nham.
set "DIRTY="
for /f "delims=" %%i in ('git status --porcelain 2^>nul') do (
  set "LINE=%%i"
  if not "!LINE:~0,2!"=="??" set "DIRTY=1"
)
if defined DIRTY (
  echo [CANH BAO] Ban co thay doi trong file ma git quan ly:
  git status --short
  echo.
  echo   Chon 1 trong 2 lenh sau roi chay lai:
  echo     git stash          : tam cat thay doi, lay lai bang git stash pop
  echo     git checkout -- .  : bo het thay doi, khong lay lai duoc
  echo.
  %PAUSE%
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
    %PAUSE%
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
  %PAUSE%
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

if not "!BEFORE!"=="!AFTER!" (
  rem So danh sach thu vien, bo qua dong "version = " - doi so phien ban khong can cai lai
  set "D1=%TEMP%\dbs-dep-1.txt"
  set "D2=%TEMP%\dbs-dep-2.txt"
  set "DEPCHANGED="
  git show "!BEFORE!:pyproject.toml" 2>nul | findstr /v /c:"version =" > "!D1!"
  git show "!AFTER!:pyproject.toml" 2>nul | findstr /v /c:"version =" > "!D2!"
  fc /b "!D1!" "!D2!" >nul
  if errorlevel 1 set "DEPCHANGED=1"
  git show "!BEFORE!:requirements.txt" 2>nul > "!D1!"
  git show "!AFTER!:requirements.txt" 2>nul > "!D2!"
  fc /b "!D1!" "!D2!" >nul
  if errorlevel 1 set "DEPCHANGED=1"
  if defined DEPCHANGED (
    echo.
    echo   [CAN LAM] Danh sach thu vien da doi. Chay lenh sau:
    echo     .\.venv\Scripts\python.exe -m pip install -r requirements.txt
  ) else (
    echo   Khong can cai lai thu vien.
  )
)
echo.
%PAUSE%
