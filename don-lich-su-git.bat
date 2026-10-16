@echo off
rem Rewrite git history so the heavy files disappear from every commit:
rem   - data/raw/owasp/official/CheatSheetSeries.zip            (16 MB, unused)
rem   - data/raw/owasp/official/CheatSheetSeries-master/assets/ (19 MB of images)
rem   - tests/bao-cao-theo-mau-demo.pdf                        (orphan artefact)
rem Run it once. It changes every commit hash and force-pushes main and the
rem session branch. Escape hatch: it never touches your working clone.
rem Usage: don-lich-su-git.bat [repo-url]
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "URL=%~1"
if "%URL%"=="" set "URL=https://github.com/tirswaitnef/dbs_learning.git"
set "MAIN=main"
set "BRANCH=arena/e28181c3-dbs-learning"
set "PAUSE=pause"
if "%DBS_AUTO%"=="1" set "PAUSE=echo."

echo ==============================================
echo   DON LICH SU GIT (xoa file nang khoi moi commit)
echo ==============================================
echo.
echo Repo dich    : %URL%
echo Se force-push: %MAIN% va %BRANCH%
echo.
echo CANH BAO: buoc nay doi ma moi commit va ghi de lich su tren GitHub.
echo Sau khi xong, ban clone tren may ban can fetch va reset lai (script in lenh).
echo.

git rev-parse --git-dir >nul 2>&1
if errorlevel 1 (
  echo [LOI] Thu muc nay khong phai repo git. Hay chay script trong thu muc dbs_learning.
  echo.
  %PAUSE%
  exit /b 1
)

if not "%DBS_AUTO%"=="1" (
  set /p "ANS=Go dung chu XOA de tiep tuc: "
  if /i not "!ANS!"=="XOA" (
    echo Da huy, khong thay doi gi.
    exit /b 1
  )
)

rem Tim Python va dung duong dan TUYET DOI (script se cd sang thu muc tam).
set "PY="
if exist "%~dp0.venv\Scripts\python.exe" set "PY=%~dp0.venv\Scripts\python.exe"
if not defined PY (
  for /f "delims=" %%p in ('where python 2^>nul') do if not defined PY set "PY=%%p"
)
if not defined PY (
  for /f "delims=" %%p in ('where py 2^>nul') do if not defined PY set "PY=%%p"
)
if not defined PY (
  echo [LOI] Khong tim thay Python de chay git-filter-repo. Cai Python 3 roi chay lai.
  echo.
  %PAUSE%
  exit /b 1
)
echo Python dung de chay: %PY%

"%PY%" -c "import git_filter_repo" >nul 2>&1
if errorlevel 1 (
  echo Dang cai git-filter-repo (can mang)...
  "%PY%" -m pip install -q git-filter-repo
  if errorlevel 1 (
    "%PY%" -m pip install -q --user git-filter-repo
    if errorlevel 1 (
      echo [LOI] Khong cai duoc git-filter-repo. Chay tay:
      echo       "%PY%" -m pip install git-filter-repo
      echo.
      %PAUSE%
      exit /b 1
    )
  )
)
echo git-filter-repo: OK
echo.

set "TMP=%TEMP%\dbs-don-lich-su-%RANDOM%"
mkdir "%TMP%" >nul 2>&1
if not exist "%TMP%" (
  echo [LOI] Khong tao duoc thu muc tam: %TMP%
  echo.
  %PAUSE%
  exit /b 1
)
echo Thu muc tam: %TMP%
echo Dang tai toan bo lich su repo ve thu muc tam...
git clone -q --bare "%URL%" "%TMP%\work.git"
if errorlevel 1 (
  echo [LOI] Khong clone duoc repo. Kiem tra mang va URL.
  echo.
  %PAUSE%
  exit /b 1
)

pushd "%TMP%\work.git"
echo.
echo Dang viet lai lich su...
"%PY%" -m git_filter_repo --force --invert-paths ^
  --path data/raw/owasp/official/CheatSheetSeries.zip ^
  --path data/raw/owasp/official/CheatSheetSeries-master/assets/ ^
  --path tests/bao-cao-theo-mau-demo.pdf > "%TMP%\log.txt" 2>&1
if errorlevel 1 (
  echo [LOI] git-filter-repo that bai:
  type "%TMP%\log.txt"
  echo Khong co gi bi day len. Thu muc tam con nguyen: %TMP%
  popd
  echo.
  %PAUSE%
  exit /b 1
)

echo Kiem tra truoc khi day len:
git rev-list --all --objects > "%TMP%\objects.txt" 2>nul
findstr /c:"CheatSheetSeries-master/assets" "%TMP%\objects.txt" >nul
if not errorlevel 1 (
  echo [LOI] File assets VAN CON trong lich su. Dung lai, khong day len.
  echo       Thu muc tam con nguyen: %TMP%
  popd
  echo.
  %PAUSE%
  exit /b 1
)
git cat-file -e "%MAIN%:data/raw/owasp/official/CheatSheetSeries.zip" >nul 2>&1
if not errorlevel 1 (
  echo [LOI] Nhanh %MAIN% van con file zip. Dung lai, khong day len.
  popd
  echo.
  %PAUSE%
  exit /b 1
)
git cat-file -e "%BRANCH%:src/rag/db_scope.py" >nul 2>&1
if errorlevel 1 (
  echo [LOI] Nhanh %BRANCH% mat code quan trong sau khi viet lai. Dung lai, khong day len.
  popd
  echo.
  %PAUSE%
  exit /b 1
)
echo   assets da xoa khoi lich su: OK
echo   zip da xoa khoi %MAIN%: OK
echo   nhanh %BRANCH% con nguyen code: OK

git remote add origin "%URL%" >nul 2>&1
echo.
echo Dang force-push len GitHub...
git push --force origin "%MAIN%" "%BRANCH%"
if errorlevel 1 (
  echo [LOI] Push that bai. Repo tren GitHub chua bi doi.
  echo       Thu muc tam con nguyen: %TMP%
  popd
  echo.
  %PAUSE%
  exit /b 1
)

popd
rmdir /s /q "%TMP%" >nul 2>&1
echo.
echo ==============================================
echo   XONG. Lich su tren GitHub da sach.
echo ==============================================
echo.
echo Cap nhat ban clone tren may ban (bat buoc, vi ma commit da doi):
echo   git fetch origin --prune
echo   git reset --hard origin/%BRANCH%
echo.
echo Hoac don gian la xoa thu muc cu roi clone lai:
echo   git clone %URL%
echo.
%PAUSE%
