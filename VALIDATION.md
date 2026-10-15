# Trạng thái kiểm tra khi bàn giao

Ngày: 2026-09-28. Đây là bản nền mới v0.1.

## Đã chạy thực tế

- `python -m unittest discover -s tests -v`: **17 tests, tất cả PASS**.
- `python scripts/demo.py`: sinh report.md và report.json cho 3 finding giả lập.
- `python scripts/generate_report.py --input data/raw/scans/zap-example.json --format zap --mode demo --output data/reports/zap-demo`: sinh báo cáo XSS từ fixture ZAP.
- Đọc báo cáo demo để kiểm tra nguồn, bằng chứng, nhãn giả lập và hai tình huống từ chối đưa gợi ý.

Bộ test có kiểm tra ID nguồn bịa, ID sai CWE, field remediation tự do,
thiếu/duplicate finding, thiếu evidence, nguồn giả mạo domain, thẻ chưa duyệt,
ngưỡng truy xuất, bảo toàn evidence, escape Markdown/HTML, parser và luồng demo.
Test luồng Gemini dùng mock để kiểm tra chặn kế hoạch sai, không gọi API thật.

## Chưa kiểm tra trực tiếp

- Cài toàn bộ requirements trong venv mới; `pip check` và `pytest` chưa chạy.
- Tải model E5 và chạy ingest với embedding thật (môi trường hiện tại chưa có sentence-transformers).
- Gọi Gemini thực tế (chưa có SDK/API key/model của người dùng).
- PowerShell trên Windows; lệnh được chuẩn bị nhưng thực thi hiện tại là Linux.
- Độ chính xác truy xuất/gợi ý trên dữ liệu kiểm thử thực tế; chưa có bộ đánh giá gán nhãn.
- ZAP export thực tế của người dùng; parser mới kiểm thử với fixture.

Không dùng kết quả test code làm bằng chứng rằng AI không bao giờ sai.
Không có cam kết rằng chỉ thêm key là chất lượng nghiên cứu đã được xác nhận.


## Cập nhật Tập 02 — phiên bản 0.2, ngày 2026-09-28

- `python -m unittest discover -s tests -v`: **24 tests, tất cả PASS**.
- `python scripts/preview_chunks.py`: chạy thực tế offline, không API/model.
- 2 tài liệu mẫu tự viết (1267 và 1679 ký tự) tạo ra 5 chunk: 800, 587, 800, 800, 319 ký tự.
- Kiểm thử bổ sung: quét thư mục con, tên file trùng khác thư mục, Markdown mở rộng,
  UTF-8 BOM, file rỗng/không hỗ trợ, metadata/hash, overlap/offset,
  kích thước tài liệu 1291+1530 tạo đúng 5 chunk, cấu hình lỗi và ranh giới kết thúc.
- Nhánh PDF không có text/file hỏng được kiểm thử bằng mock; chưa chạy pypdf trên PDF thật.
- Thay đổi này mới chuẩn bị corpus/chunks JSONL. Chưa nối corpus tài liệu mới vào embedding/report.
- Các giới hạn E5/Gemini/Windows và kiểm tra dependency đã nêu vẫn còn nguyên.


## Cập nhật Tập 03 — phiên bản 0.3, ngày 2026-09-28

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


## Cập nhật Tập 04 — phiên bản 0.4, ngày 2026-09-28

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


## Nhập output công cụ — phiên bản 0.5, ngày 2026-09-28

- `python -m unittest discover -s tests -q`: **54 tests PASS**.
- Sáu fixture giả lập: ZAP JSON, Burp XML, Nuclei JSONL, sqlmap log, Nessus XML và Nmap XML.
- Chạy CLI normalize riêng cho từng fixture; mỗi fixture cho một bản ghi, riêng Nmap là observation.
- Kiểm tra roundtrip JSON chuẩn hóa, báo cáo demo, Base64, nhiều CWE, response/evidence,
  input sai định dạng, XML entity/external DTD, sqlmap thiếu bằng chứng kết luận.
- Chưa đối chiếu với export thật hoặc chạy trực tiếp các scanner; không bảo đảm mọi phiên bản/biến thể export.
- Nhập dữ liệu không gọi AI. Các giới hạn kiểm thử E5/Gemini của bản 0.4 vẫn áp dụng.
- Chưa bổ sung corpus OWASP đầy đủ theo yêu cầu tạm hoãn.
