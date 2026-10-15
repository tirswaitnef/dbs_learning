# Trạng thái kiểm tra

File này ghi lại những gì đã thực sự được chạy và những gì chưa. Test pass không
chứng minh chất lượng của AI.

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
