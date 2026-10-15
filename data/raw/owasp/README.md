# Kho hướng dẫn OWASP khởi đầu

`cards.json` chứa 2 thẻ: SQL Injection (CWE-89) và XSS (CWE-79).
Đây là trích mục ngắn và diễn giải tiếng Việt đã đối chiếu trang OWASP ngày 2026-09-28,
không phải toàn bộ tài liệu OWASP, không phải nội dung OWASP chứng nhận cho project.

Trường `approved` nghĩa là thẻ được cho phép dùng trong project. Hai thẻ có sẵn
đã được kiểm tra nguồn khi tạo starter; người làm nghiên cứu cần duyệt lại trước
khi dùng làm bộ dữ liệu đánh giá chính thức. `reviewed_by` ghi rõ nguồn gốc lần duyệt này.

Mỗi thẻ bắt buộc có ID, CWE, tên tài liệu, mục, URL chính thức, ngày đối chiếu,
người đối chiếu, trích mục gốc, hướng dẫn tiếng Việt và điều kiện áp dụng.
Không tự động đánh dấu approved cho tài liệu tải mới.

Mở rộng: đọc mục nguồn đầy đủ, viết hướng dẫn đúng phạm vi, ghi điều kiện áp dụng,
đối chiếu với nguồn, sau đó mới approved và chạy ingest lại.
Chương trình kiểm tra cấu trúc/nguồn/ID/CWE; nó không thể tự chứng minh việc
diễn giải của người viết thẻ là đúng. Việc cùng CWE cũng không đảm bảo phù hợp mọi trường hợp.

Nguồn:
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html#defense-option-1-prepared-statements-with-parameterized-queries
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#output-encoding

`loader.load_document()` hỗ trợ đọc .md/.txt và PDF có text (cần pypdf), nhưng
chưa tự biến các file đó thành hướng dẫn đã duyệt. CLI ingest bản này nhận cards.json.
PDF dạng ảnh chưa có OCR.
