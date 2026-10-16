# Trạng thái kiểm tra

File này ghi lại những gì đã thực sự được chạy và những gì chưa. Test pass không
chứng minh chất lượng của AI.

## Cập nhật 2026-10-15 — bản 0.12.0 (suy luận theo đầu vào: khung CSDL và kiểm tra trùng lặp)

### Thay đổi

- `src/rag/db_scope.py`: khung CSDL cho từng bản ghi, tính bằng code từ cổng/dịch vụ,
  `details.scanner_rule`, `details.dbms` và CWE do công cụ/quy tắc cung cấp. Không suy
  đoán từ tên lỗi. Quy tắc thắng cổng; nhiều CWE chỉ cho một kiểm soát khi cùng nhóm.
- `src/rag/report_variety.py`: tách văn bản AI, câu do code sinh và bằng chứng;
  `prose_check` ghi vào `report.json`, `compare_reports` so hai lần chạy.
- `src/rag/analysis.py`: gửi khung cho AI dưới mã nguồn `K1`; lượt rà soát thêm cờ
  `database_specific` (thiếu hoặc sai thì diễn giải bị từ chối).
- `src/rag/pipeline.py`: nhánh thẻ (`--mode gemini`) nay cũng sinh diễn giải AI theo
  từng bản ghi, không chỉ chọn thẻ.
- `src/rag/parsers/native.py`: adapter sqlmap ghi `details.dbms` từ dòng `back-end DBMS`.
- Báo cáo: mục 2 có bảng phạm vi CSDL và dòng kết quả kiểm tra trùng lặp; mục 4 có dòng
  "Phạm vi CSDL" cho từng bản ghi; PDF in cùng nội dung.

### Đã chạy

- `python -m unittest discover -s tests`: **112 tests PASS** (82 test cũ, 30 test mới cho
  khung CSDL, phép đo trùng lặp và luồng diễn giải có model giả).
- Kiểm tra đột biến trên bản sao repo (baseline 112 OK): 6/6 đột biến bị phát hiện — bỏ
  điều kiện cùng nhóm CWE, cho cổng thắng quy tắc, so cả câu do code sinh, bỏ câu ràng
  buộc trong K1, bỏ cờ `database_specific`, bỏ nhánh tầng ứng dụng.
- Luồng thật không cần API: `scripts/demo.py`, `scripts/export_pdf.py`,
  `scripts/export_template_pdf.py` — chạy được với báo cáo demo.
- Khung CSDL chạy trên các fixture và trên file mô phỏng đúng dạng export của lab:
  Nmap + `mysql-empty-password` → máy chủ CSDL, MySQL/MariaDB, xác thực; Nessus 10481 →
  máy chủ CSDL, MySQL/MariaDB; sqlmap có dòng `back-end DBMS` → tầng ứng dụng, xử lý truy
  vấn, engine theo log; finding XSS → ngoài phạm vi CSDL.

### Chưa chạy

- **Chưa gọi Gemini thật** với khung mới và cờ `database_specific`; toàn bộ luồng diễn
  giải được kiểm tra bằng model giả. Cần `GEMINI_API_KEY` và một lần chạy thật để biết
  model có tuân thủ khung hay không, và tỉ lệ diễn giải bị từ chối là bao nhiêu.
- **Ngưỡng trùng lặp 0,7 chưa hiệu chỉnh** trên dữ liệu gán nhãn; chưa đo tỉ lệ dương
  tính giả trên báo cáo thật.
- Chưa có export thật từ lab (xem mục 0.11.1) nên khung chưa được đối chiếu với file do
  scanner thật sinh ra.

## Cập nhật 2026-10-15 — bản 0.11.1 (hướng dẫn lấy dữ liệu đầu vào thật)

### Thay đổi

- `docs/lab-quet-csdl.md`: quy trình dựng lab, chạy Nmap/sqlmap/ZAP/Nessus Essentials,
  lấy file export, đưa file vào project, biên bản quét và mẫu gán nhãn.
- `lab/docker-compose.yml`, `lab/README.md`: DVWA ở tầng ứng dụng, cộng hai CSDL cấu
  hình yếu ở tầng máy chủ (MariaDB root không mật khẩu cho phép từ xa, PostgreSQL
  `trust`). Không có thay đổi nào trong `src/`.

### Đã chạy

- File mô phỏng đúng dạng export của lab (do project tự tạo, **không phải** file quét
  từ máy người dùng) đi qua `scripts/normalize_scan.py`:
  - Nmap XML có `mysql-empty-password`: 4 bản ghi — 3 quan sát cổng/dịch vụ và finding
    `NMAP-0-1-S0` với CWE-1393; `details.scanner_rule` là `nmap-mysql-empty-password`;
    `import-summary.md` ghi "CWE gán theo quy tắc của dự án vì công cụ không ghi CWE: 1".
  - Nessus `.nessus` có plugin 10481 và 10483, mức 4, không có thẻ `<cwe>`: 2 bản ghi,
    cả hai nhận CWE-1393 từ quy tắc. Báo cáo `demo` xếp cả hai vào A07:2025 và để
    trạng thái `no_supported_guidance` vì chưa có thẻ CSDL.
- `python -m unittest discover -s tests`: 82 tests PASS (không đổi so với 0.11.0).

### Chưa chạy

- **Chưa có export thật từ lab.** Sandbox không có Docker, Nmap, sqlmap hay Nessus, và
  việc quét phải thực hiện trên máy của người dùng. Quy trình: `docs/lab-quet-csdl.md`.
- Chưa có file ZAP JSON thật từ ZAP Desktop để đối chiếu template report, và chưa xác
  nhận được `Nessus Essentials` có bật sẵn *thorough checks* cho plugin 10483 hay không.
- Chưa có bộ finding gán nhãn; mẫu CSV trong mục 9 của tài liệu lab mới chỉ là khung.

## Cập nhật 2026-10-15 — bản 0.11.0 (finding nhiều CWE, quy tắc CWE cho kiểm tra CSDL)

### Thay đổi

- Cổng Top 10 xét cả danh sách CWE do công cụ gắn: finding được gợi ý khi mọi CWE
  cùng thuộc một nhóm. Trước đây mọi finding nhiều CWE đều bị chặn.
- `src/rag/data/scanner-rules.json`: 12 quy tắc viết tay cho kiểm tra CSDL, gồm 10
  plugin Nessus và 2 script NSE của Nmap. Quy tắc chỉ áp dụng khi công cụ không ghi CWE.

### Nguồn đã đối chiếu khi viết quy tắc

- Trang plugin Tenable 10481, 10483, 10673, 81777, 100634, 57558, 63347, 55786, 64784,
  73756: tên, ID và họ plugin khớp với file quy tắc. Các trang 10481 và 10483 không ghi
  CWE nào.
- Mã nguồn `mysql-empty-password.nse` và `ms-sql-empty-password.nse` (repo
  nmap/nmap): mẫu output lấy từ dòng `string.format` của script. `mongodb-databases`
  và `redis-info` không được thêm vì có thể chạy kèm thông tin đăng nhập.
- MITRE: CWE-1393, CWE-306, CWE-1104 đều là mức Base và được phép dùng để ánh xạ
  (ALLOWED).
- OWASP Top 10:2025 (repo OWASP/Top10, commit `3a31f353`): A03 nêu phần mềm
  "unsupported, or out of date" gồm cả DBMS; A07 nêu việc cho phép mật khẩu mặc định.

### Đã chạy

- `python -m unittest discover -s tests`: **82 tests PASS** (56 test cũ, 10 test
  nhiều CWE và chế độ `owasp`, 16 test quy tắc). Test mới chạy chế độ `owasp` với
  retriever và model giả, không gọi E5 hay Gemini thật.
- Kiểm tra đột biến trên bản sao repo: 11/11 lỗi cố ý bị test phát hiện, gồm bỏ quy
  tắc nhiều CWE, dùng hợp thay vì "cùng một nhóm", để quy tắc ghi đè CWE của công cụ,
  bỏ finding NSE, bỏ ưu tiên Cheat Sheet, và cho validator nhận CWE ngoài Top 10.
- Kịch bản lab CSDL tự dựng (sqlmap, ZAP, Burp, Nmap, Nessus) qua parser và cổng Top 10:

  | Phát hiện | Trước | Sau |
  |---|---|---|
  | Burp SQL injection (CWE-89, 94, 116) | Bị chặn | A05, có thẻ SQLi |
  | Nmap `mysql-empty-password` báo root không mật khẩu | Chỉ là quan sát | Thêm finding CWE-1393, A07 |
  | Nessus 10481, 10483 (không kèm CWE) | Bị chặn | CWE-1393, A07 |
  | sqlmap, ZAP SQL injection | A05 | Không đổi |

- 10 file `.nessus` công khai (bộ test của DefectDojo và vài repo khác): vẫn chỉ 3/112
  finding mức từ low trở lên đủ điều kiện, vì các file này không có plugin CSDL nào.
  14 finding nhiều CWE đều thuộc nhiều nhóm, hoặc kèm mã View/Category như CWE-928,
  CWE-930 mà MITRE cấm dùng để ánh xạ.
- `demo.py`, `export_pdf.py`, `export_template_pdf.py`, và `normalize_scan.py` với
  file Nmap CSDL.

### Chưa kiểm tra

- Chưa có file export Nessus/Nmap thật từ một lab CSDL. Fixture trong test được dựng
  theo tài liệu và mã nguồn của công cụ.
- Chưa chạy E5 và Gemini thật với finding CSDL, nên chưa biết Database Security Cheat
  Sheet có lọt vào kết quả truy xuất hay không. Việc ưu tiên chỉ có tác dụng khi sheet
  đó được truy xuất.

## Cập nhật 2026-10-15 — bản 0.10.0 (dọn repo, CI, cập nhật tài liệu)

### Đã chạy

Môi trường: Linux, Python 3.11, `pip install -e ".[dev]"` (reportlab 4.5.1, numpy
2.4.6, pytest 9.1.1). Không cài sentence-transformers và google-genai.

- `python -m unittest discover -s tests -v`: **56 tests PASS**. Trước khi sửa: 55
  test, 1 lỗi import vì `template_report.py` nằm nhầm trong `tests/` (đã chuyển về
  `src/rag/`, và `export_template_pdf.py` về `scripts/`).
- `python -m pytest -q`: 56 passed.
- Thiếu numpy: 9 test vector store bị SKIP. Thiếu reportlab: các test sinh báo cáo
  lỗi, vì báo cáo luôn kèm PDF.
- `scripts/demo.py`, `scripts/export_pdf.py`, `scripts/export_template_pdf.py` và
  `generate_report.py --mode demo` với `zap-example.json`.
- `scripts/normalize_scan.py` và `scripts/preview_chunks.py` bằng Python không cài
  thư viện ngoài.
- `scripts/web.py --demo`: tạo báo cáo từ fixture ZAP qua API. Kiểm tra bằng curl:
  Host lạ → 403, thiếu `X-App-Token` → 403, Origin khác → 403, tên file
  `../../etc/passwd` chỉ còn `passwd`. Chế độ thường khi chưa có `.env` và vector
  store: `/api/config` báo đúng hai mục còn thiếu.
- File Burp dựng theo cấu trúc export thật (issue SQL injection có CWE-89, CWE-94,
  CWE-116): parser cho `cwe=unknown`, finding bị chặn phạm vi, không có hướng dẫn.
- `.github/workflows/tests.yml` hợp lệ theo schema (kiểm bằng action-validator).
- GitHub Actions, lần chạy đầu tiên
  ([run 38707407843](https://github.com/tirswaitnef/dbs_learning/actions/runs/38707407843)):
  cả 4 job PASS: Ubuntu và Windows, Python 3.11 và 3.14, gồm bộ unittest và bước
  chạy thử demo/xuất PDF.

### Quan sát từ các job web chạy thật ngày 2026-10-09 và 2026-10-10

Model `gemini-3.5-flash-lite`, E5 với store Cheat Sheet Series, đầu vào giả lập.
File job đã được gỡ khỏi repo nhưng vẫn còn trong lịch sử Git ở commit `6de0e7d`
(`data/web/jobs/`).

- 3 job: Burp (1 XSS), sqlmap (1 SQLi) và JSON chuẩn hóa (8 finding hỗn hợp). Job 8
  finding dùng 17 lượt gọi Gemini; phần tổng quan AI bị `api_error` nên job ở trạng
  thái `partial`.
- Điểm E5 của mọi ứng viên nằm trong khoảng 0,843–0,880, chênh nhau khoảng 0,01 trong
  cùng một truy vấn. Vì vậy `RAG_MIN_SCORE=0.75` không loại ứng viên nào. Ứng viên
  còn gồm cả sheet không liên quan, ví dụ Forgot Password và LLM Prompt Injection
  cho một ca XSS; WebSocket và GraphQL cho một ca SQLi.
- Diễn giải AI: một số ý sai ký tự hoặc mất dấu ("quản trỈ", "đěợc", "khợc phục",
  "phát hiền", "Cong cu kiem thu ghi nhan canh bao...") vẫn qua lượt AI rà soát và có
  trong PDF cuối. Nội dung chủ yếu nhắc lại tiêu đề, CWE, mức độ và vị trí.
- Hướng dẫn được chọn cho 5 ca SQLi/XSS có bằng chứng:
  - SQLi (JSON): "Defense Option 1: Prepared Statements" của Injection Prevention
    Cheat Sheet. Đúng biện pháp chính, nhưng đoạn trích nhắc "the safe example below"
    trong khi khối code đã bị bỏ.
  - SQLi bằng chứng yếu (JSON): chỉ có "Least Privilege", một biện pháp phụ.
  - SQLi (sqlmap): 2 đoạn của DotNet Security Cheat Sheet (ORM/stored procedures và
    parameterized queries), dù không biết công nghệ của mục tiêu.
  - XSS (Burp): "Framework Security" và "XSS Defense Philosophy", mang tính giới
    thiệu, không phải quy tắc encoding cụ thể.
  - XSS (JSON): không có hướng dẫn (`insufficient_context`).

### Chưa kiểm tra

- Test tự động cho luồng chính: chưa có test nào cho `official_report.py` (chế độ
  `owasp`), `analysis.py` (diễn giải AI, rà soát, che dữ liệu) và `web_server.py`.
  `top10.py` chỉ được kiểm gián tiếp qua luồng demo. 56 test hiện có phủ phần code
  của bản 0.1–0.5 và PDF theo mẫu.
- Chạy E5 và Gemini thật trong lần cập nhật này.
- File export thật từ các scanner.
- Đánh giá chất lượng có gán nhãn: độ đúng của hướng dẫn, của diễn giải, và khả năng
  từ chối.

## Cập nhật 2026-10-16 — bản 0.12.0 (gọn repo, script cập nhật, xác minh trên Windows)

### Đã chạy

- Dọn cây làm việc: 452 → **224 file**, 40 MB → **5,8 MB**. Bỏ file zip CheatSheetSeries
  (16 MB, không script/tài liệu/test nào tham chiếu), thư mục `assets/` của bản sao
  upstream (19 MB ảnh/PDF; ingest chỉ đọc `cheatsheets/*.md`), các file CI/package của
  upstream, bản nháp cheatsheet và `tests/bao-cao-theo-mau-demo.pdf` (file mồ côi).
  Giữ `cheatsheets/` (127 cheat sheet), `templates/`, `LICENSE.md`, `README.md`.
  `.gitignore` chặn lại các đường dẫn nặng nếu giải nén bản đầy đủ đè lên.
- `python -m pytest -q`: **112 passed, 70 subtests passed** (112 test của bản trước,
  không test nào phụ thuộc phần đã xoá).
- `cap-nhat.bat` / `cap-nhat.sh`: cập nhật code từ GitHub cho người dùng cuối, tự chọn
  nhánh (nhánh làm việc khi còn hơn `main`, `main` sau khi gộp), cảnh báo khi file được
  git quản lý bị sửa, `git pull --ff-only`, in commit mới và chỉ nhắc cài lại thư viện
  khi dòng khai báo thư viện thật sự đổi (đổi số `version` không tính).
- `don-lich-su-git.bat` / `.sh`: viết lại lịch sử để xoá vĩnh viễn zip, `assets/` và PDF
  mồ côi khỏi **mọi** commit, kiểm tra lại rồi mới force-push `main` và nhánh làm việc;
  không đụng bản clone đang dùng. Thử trên một origin giả trong sandbox: **32 MB → 2,3 MB**,
  16 commit giữ nguyên, cây nhánh không đổi (224 file), test vẫn PASS sau khi viết lại.
- Máy Windows thật (GitHub Actions, Windows Server 2022):
  [run 38887876130](https://github.com/tirswaitnef/dbs_learning/actions/runs/38887876130)
  chạy cả hai script `.bat` trên một origin giả rồi khẳng định: `assets` không còn trong
  lịch sử, `main` không còn zip, nhánh còn `lab/` và `db_scope.py`, cả hai script exit 0.
- Hai lỗi thật do lần chạy đó phát hiện: (1) `echo` chứa dấu ngoặc đơn đặt trong khối
  `if (...)` làm cmd vỡ cú pháp — script thoát 255 mà không báo gì; đã bỏ hết ngoặc đơn
  trong `echo`. (2) `git diff-index --quiet` không tự làm mới stat cache nên báo nhầm
  "có thay đổi" trên bản clone sạch — đã chuyển sang `git status --porcelain`, bỏ qua
  file chưa được theo dõi (`??`). Ngoài ra bản đầu tiên của script không dọn gì: đường
  dẫn Python là tương đối nên hỏng sau `cd`, và lỗi của `git-filter-repo` bị `| tail`
  che mất; nay script dừng hẳn nếu chưa xoá được `assets`.
- Workflow kiểm thử tạm (`test-don-lich-su.yml`) đã xoá sau khi xác minh; chỉ còn
  `tests.yml` trong CI.

### Chưa kiểm tra

- **Chưa áp dụng việc viết lại lịch sử lên repo thật.** Cho tới khi chạy
  `don-lich-su-git.bat`, bản clone đầy đủ vẫn mang các blob cũ (~72 MB); clone nông
  `--depth 1` thì chỉ ~6,8 MB. Đây là thao tác một lần, do người dùng chạy vì nó
  force-push cả `main`.
- Chưa chạy `cap-nhat.bat` trên máy người dùng với dữ liệu thật (.env, data/) — mới
  xác minh trên runner Windows với origin giả.

## Lịch sử kiểm tra bản 0.1–0.5

Phần dưới giữ nguyên từ các lần bàn giao trước; số liệu là của thời điểm đó.

### Bản nền 0.1 — bàn giao

Ngày: 2026-09-28. Đây là bản nền mới v0.1.

#### Đã chạy thực tế

- `python -m unittest discover -s tests -v`: **17 tests, tất cả PASS**.
- `python scripts/demo.py`: sinh report.md và report.json cho 3 finding giả lập.
- `python scripts/generate_report.py --input data/raw/scans/zap-example.json --format zap --mode demo --output data/reports/zap-demo`: sinh báo cáo XSS từ fixture ZAP.
- Đọc báo cáo demo để kiểm tra nguồn, bằng chứng, nhãn giả lập và hai tình huống từ chối đưa gợi ý.

Bộ test có kiểm tra ID nguồn bịa, ID sai CWE, field remediation tự do,
thiếu/duplicate finding, thiếu evidence, nguồn giả mạo domain, thẻ chưa duyệt,
ngưỡng truy xuất, bảo toàn evidence, escape Markdown/HTML, parser và luồng demo.
Test luồng Gemini dùng mock để kiểm tra chặn kế hoạch sai, không gọi API thật.

#### Chưa kiểm tra trực tiếp

- Cài toàn bộ requirements trong venv mới; `pip check` và `pytest` chưa chạy.
- Tải model E5 và chạy ingest với embedding thật (môi trường hiện tại chưa có sentence-transformers).
- Gọi Gemini thực tế (chưa có SDK/API key/model của người dùng).
- PowerShell trên Windows; lệnh được chuẩn bị nhưng thực thi hiện tại là Linux.
- Độ chính xác truy xuất/gợi ý trên dữ liệu kiểm thử thực tế; chưa có bộ đánh giá gán nhãn.
- ZAP export thực tế của người dùng; parser mới kiểm thử với fixture.

Không dùng kết quả test code làm bằng chứng rằng AI không bao giờ sai.
Không có cam kết rằng chỉ thêm key là chất lượng nghiên cứu đã được xác nhận.


### Cập nhật Tập 02 — phiên bản 0.2, ngày 2026-09-28

- `python -m unittest discover -s tests -v`: **24 tests, tất cả PASS**.
- `python scripts/preview_chunks.py`: chạy thực tế offline, không API/model.
- 2 tài liệu mẫu tự viết (1267 và 1679 ký tự) tạo ra 5 chunk: 800, 587, 800, 800, 319 ký tự.
- Kiểm thử bổ sung: quét thư mục con, tên file trùng khác thư mục, Markdown mở rộng,
  UTF-8 BOM, file rỗng/không hỗ trợ, metadata/hash, overlap/offset,
  kích thước tài liệu 1291+1530 tạo đúng 5 chunk, cấu hình lỗi và ranh giới kết thúc.
- Nhánh PDF không có text/file hỏng được kiểm thử bằng mock; chưa chạy pypdf trên PDF thật.
- Thay đổi này mới chuẩn bị corpus/chunks JSONL. Chưa nối corpus tài liệu mới vào embedding/report.
- Các giới hạn E5/Gemini/Windows và kiểm tra dependency đã nêu vẫn còn nguyên.


### Cập nhật Tập 03 — phiên bản 0.3, ngày 2026-09-28

- `python -m unittest discover -s tests -v`: **33 tests PASS**, không skip trong môi trường kiểm tra.
- 9 test mới chạy NumPy thật, encoder xác định trước để kiểm tra đại số/luồng ingest-query.
- Lưu/đọc NPZ float32, normalize, dot product/cosine, top-k, ngưỡng, nguồn và offsets.
- Test corpus/model/config thay đổi, vector/metadata hỏng, vector không hợp lệ và query khác số chiều.
- Test E5 wrapper dùng fake SentenceTransformer để kiểm tra CPU, local_files_only,
  prefix passage/query, kiểm tra độ dài và float32; KHÔNG phải chạy model E5 thật.
- Thử `pip install --dry-run --no-deps --timeout 8 --retries 0 sentence-transformers`
  không tìm thấy distribution khả dụng trong môi trường hiện tại. Không cài được model runtime.
- Chưa đo chất lượng semantic retrieval, chưa có score E5 thực tế, chưa chạy trên Windows.
- Không có store E5 tạo sẵn trong ZIP. Người dùng cần cài nhóm retrieval và chạy ingest_documents.py.
- Tập 03 không gọi Gemini; nhánh Gemini của bản nền vẫn chưa được kiểm tra bằng API thật.


### Cập nhật Tập 04 — phiên bản 0.4, ngày 2026-09-28

- `python -m unittest discover -s tests -v`: **44 tests PASS**.
- 11 test bổ sung: context/source, context budget, JSON prompt, context rỗng không
  gọi Gemini, chỉ trả nguồn được trích, thiếu thông tin dù score cao, ID bịa,
  quote sai nguồn, thiếu citation/URL tự viết, từ chối kèm claim, JSON lỗi/API lỗi,
  adapter Gemini dùng chung với nhánh kế hoạch báo cáo (một số test bao gồm nhiều case).
- Test QA dùng response giả lập có kiểm soát; không gọi Gemini thật.
- Bộ kiểm tra quote xác nhận sự tồn tại trong chunk, chưa kiểm chứng semantic entailment.
- Không tuyên bố prompt loại trừ hoàn toàn hallucination hoặc prompt injection.
- E5, Gemini và môi trường Windows vẫn chưa được kiểm tra trực tiếp.
- Nhánh hỏi đáp tài liệu đã nối trong code. Nhánh remediation chính thức vẫn dùng
  thẻ đã duyệt; chưa tự nối văn bản hỏi đáp tự do vào báo cáo kiểm thử.


### Nhập output công cụ — phiên bản 0.5, ngày 2026-09-28

- `python -m unittest discover -s tests -q`: **54 tests PASS**.
- Sáu fixture giả lập: ZAP JSON, Burp XML, Nuclei JSONL, sqlmap log, Nessus XML và Nmap XML.
- Chạy CLI normalize riêng cho từng fixture; mỗi fixture cho một bản ghi, riêng Nmap là observation.
- Kiểm tra roundtrip JSON chuẩn hóa, báo cáo demo, Base64, nhiều CWE, response/evidence,
  input sai định dạng, XML entity/external DTD, sqlmap thiếu bằng chứng kết luận.
- Chưa đối chiếu với export thật hoặc chạy trực tiếp các scanner; không bảo đảm mọi phiên bản/biến thể export.
- Nhập dữ liệu không gọi AI. Các giới hạn kiểm thử E5/Gemini của bản 0.4 vẫn áp dụng.
- Chưa bổ sung corpus OWASP đầy đủ theo yêu cầu tạm hoãn.
