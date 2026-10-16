#!/usr/bin/env bash
# Viết lại lịch sử git để xoá VĨNH VIỄN các file nặng khỏi mọi commit:
#   - data/raw/owasp/official/CheatSheetSeries.zip              (16 MB, không ai dùng)
#   - data/raw/owasp/official/CheatSheetSeries-master/assets/   (19 MB ảnh/PDF)
#   - tests/bao-cao-theo-mau-demo.pdf                           (file mồ côi)
# Chạy một lần là xong. Thao tác này ĐỔI MÃ COMMIT và force-push cả main.
# Dùng: ./don-lich-su-git.sh [URL-repo]
set -u
set -o pipefail
cd "$(dirname "$0")" || exit 1

URL="${1:-${DBS_URL:-https://github.com/tirswaitnef/dbs_learning.git}}"
MAIN=main
BRANCH=arena/e28181c3-dbs-learning

echo "=============================================="
echo "  DỌN LỊCH SỬ GIT (xoá file nặng khỏi mọi commit)"
echo "=============================================="
echo
echo "Repo đích    : $URL"
echo "Sẽ force-push: $MAIN và $BRANCH"
echo
echo "CẢNH BÁO: bước này đổi mã mọi commit và ghi đè lịch sử trên GitHub."
echo "Sau khi xong, bản clone trên máy bạn cần fetch và reset lại (script in lệnh)."
echo

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "[LỖI] Thư mục này không phải repo git. Hãy chạy script trong thư mục dbs_learning."
  exit 1
fi

if [ "${DBS_AUTO:-0}" != "1" ]; then
  read -r -p "Gõ đúng chữ XOA để tiếp tục: " ANS
  if [ "$ANS" != "XOA" ]; then
    echo "Đã huỷ, không thay đổi gì."
    exit 1
  fi
fi

# Tìm Python và đổi thành đường dẫn TUYỆT ĐỐI (script sẽ cd sang thư mục tạm).
PY=""
for c in .venv/bin/python python3 python; do
  if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then
    ABS="$(cd "$(dirname "$c")" && pwd)/$(basename "$c")"
    if "$ABS" -c "import sys" >/dev/null 2>&1; then PY="$ABS"; break; fi
  fi
done
if [ -z "$PY" ]; then
  echo "[LỖI] Không tìm thấy Python để chạy git-filter-repo. Cài Python 3 rồi chạy lại."
  exit 1
fi
echo "Python dùng để chạy: $PY"

if ! "$PY" -c "import git_filter_repo" >/dev/null 2>&1; then
  echo "Đang cài git-filter-repo (cần mạng)..."
  if ! "$PY" -m pip install -q git-filter-repo; then
    "$PY" -m pip install -q --user git-filter-repo || {
      echo "[LỖI] Không cài được git-filter-repo. Chạy tay:"
      echo "      \"$PY\" -m pip install git-filter-repo"
      exit 1
    }
  fi
fi
echo "git-filter-repo: OK"
echo

TMP="$(mktemp -d)"
LOG="$TMP/filter-repo.log"
echo "Thư mục tạm: $TMP"
echo "Đang tải toàn bộ lịch sử repo về thư mục tạm..."
if ! git clone -q --bare "$URL" "$TMP/work.git"; then
  echo "[LỖI] Không clone được repo. Kiểm tra mạng và URL."
  exit 1
fi
echo "  trước khi dọn: $(du -sh "$TMP/work.git" | cut -f1)"

cd "$TMP/work.git" || exit 1
echo
echo "Đang viết lại lịch sử..."
if ! "$PY" -m git_filter_repo --force --invert-paths \
      --path data/raw/owasp/official/CheatSheetSeries.zip \
      --path data/raw/owasp/official/CheatSheetSeries-master/assets/ \
      --path tests/bao-cao-theo-mau-demo.pdf >"$LOG" 2>&1; then
  echo "[LỖI] git-filter-repo thất bại:"
  tail -10 "$LOG"
  echo "      Không có gì bị đẩy lên. Thư mục tạm còn nguyên: $TMP"
  exit 1
fi
tail -3 "$LOG"
echo "  sau khi dọn:  $(du -sh "$TMP/work.git" | cut -f1)"

echo
echo "Kiểm tra trước khi đẩy lên:"
LEFT="$(git rev-list --all --objects | grep -c 'CheatSheetSeries-master/assets' || true)"
echo "  file assets còn trong lịch sử: $LEFT (phải là 0)"
if [ "$LEFT" != "0" ]; then
  echo "[LỖI] Việc xoá KHÔNG thành công. Dừng lại, không đẩy lên."
  echo "      Thư mục tạm còn nguyên: $TMP"
  exit 1
fi
if git cat-file -e "$MAIN:data/raw/owasp/official/CheatSheetSeries.zip" 2>/dev/null; then
  echo "[LỖI] main vẫn còn file zip. Dừng lại, không đẩy lên."
  exit 1
fi
if ! git cat-file -e "$BRANCH:src/rag/db_scope.py" 2>/dev/null; then
  echo "[LỖI] Nhánh $BRANCH mất code quan trọng sau khi viết lại. Dừng lại, không đẩy lên."
  exit 1
fi
echo "  zip đã xoá khỏi main: OK"
echo "  nhánh $BRANCH còn nguyên code ($(git ls-tree -r "$BRANCH" --name-only | wc -l) file): OK"

git remote add origin "$URL" 2>/dev/null
echo
echo "Đang force-push lên GitHub..."
if ! git push --force origin "$MAIN" "$BRANCH"; then
  echo "[LỖI] Push thất bại. Repo trên GitHub chưa bị đổi."
  echo "      Thư mục tạm còn nguyên: $TMP"
  exit 1
fi

cd / && rm -rf "$TMP"
echo
echo "=============================================="
echo "  XONG. Lịch sử trên GitHub đã sạch."
echo "=============================================="
echo
echo "Cập nhật bản clone trên máy bạn (bắt buộc, vì mã commit đã đổi):"
echo "  git fetch origin --prune"
echo "  git reset --hard origin/$BRANCH"
echo
echo "Hoặc đơn giản là xoá thư mục cũ rồi git clone lại:"
echo "  git clone $URL"
