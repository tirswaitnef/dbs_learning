#!/usr/bin/env bash
# Cập nhật code mới nhất từ GitHub (bản Linux/macOS).
# Không đụng tới .env, data/ hay .venv.
set -u
cd "$(dirname "$0")" || exit 1

echo "============================================"
echo "  CẬP NHẬT CODE DỰ ÁN"
echo "============================================"
echo

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "[LỖI] Thư mục này không phải repo git, hoặc máy chưa cài Git."
  echo "      Đang dùng bản ZIP: hãy dùng git clone, xem README.md."
  exit 1
fi

BEFORE=$(git rev-parse --short HEAD)
echo "Bạn đang ở commit: $BEFORE"
echo "Đang kiểm tra bản mới trên GitHub..."
echo

if ! git fetch origin; then
  echo "[LỖI] Không kết nối được GitHub. Kiểm tra mạng rồi chạy lại."
  exit 1
fi

# Nhánh đích: nhánh làm việc còn hơn main thì dùng nó, đã gộp vào main thì dùng main.
EXTRA=$(git rev-list --count origin/main..origin/arena/e28181c3-dbs-learning 2>/dev/null || echo 0)
TARGET=main
[ "$EXTRA" != "0" ] && TARGET=arena/e28181c3-dbs-learning

echo "Nhánh sẽ cập nhật: $TARGET"
echo

if ! git diff-index --quiet HEAD --; then
  echo "[CẢNH BÁO] Bạn có thay đổi trong file mà git quản lý:"
  git status --short
  echo
  echo "  Chọn 1 trong 2 lệnh sau rồi chạy lại:"
  echo "    git stash          (tạm cất, lấy lại bằng git stash pop)"
  echo "    git checkout -- .  (bỏ hết thay đổi, không lấy lại được)"
  exit 1
fi

NOW=$(git rev-parse --abbrev-ref HEAD)
if [ "$NOW" != "$TARGET" ]; then
  echo "Đang chuyển sang nhánh $TARGET ..."
  git switch "$TARGET" || git checkout "$TARGET" || {
    echo "[LỖI] Không chuyển được nhánh. Chạy tay: git switch $TARGET"
    exit 1
  }
fi

if ! git pull --ff-only; then
  echo
  echo "[LỖI] Không cập nhật được. Xem thông báo phía trên."
  echo "      Khi lịch sử nhánh đã đổi trên GitHub, chạy:"
  echo "      git fetch origin && git reset --hard origin/$TARGET"
  exit 1
fi

AFTER=$(git rev-parse --short HEAD)
echo
echo "============================================"
if [ "$BEFORE" = "$AFTER" ]; then
  echo "  BẠN ĐANG Ở BẢN MỚI NHẤT: $AFTER"
else
  echo "  ĐÃ CẬP NHẬT: $BEFORE  ->  $AFTER"
  echo
  git log --oneline "$BEFORE..$AFTER"
fi
echo "============================================"
echo
echo ".env, data/ và .venv KHÔNG bị thay đổi."

dep_lines() {  # các dòng thay đổi trong khai báo thư viện, bỏ qua dòng version
  git diff "$1" "$2" -- pyproject.toml requirements.txt 2>/dev/null \
    | grep -E '^[+-][^+-]' | grep -v 'version =' || true
}
if [ "$BEFORE" != "$AFTER" ]; then
  if [ -n "$(dep_lines "$BEFORE" "$AFTER")" ]; then
    echo
    echo "  [CẦN LÀM] Danh sách thư viện đã đổi. Chạy lệnh sau:"
    echo "    .venv/bin/python -m pip install -r requirements.txt"
  else
    echo "  Không cần cài lại thư viện."
  fi
fi
