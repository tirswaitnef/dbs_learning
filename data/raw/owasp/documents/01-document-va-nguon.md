# Document và nguồn tài liệu

Đây là tài liệu mẫu do project viết để kiểm tra loader và chunker, không phải tài liệu OWASP và không được dùng làm căn cứ khắc phục lỗ hổng.

Một Document biểu diễn một file đã đọc vào bộ nhớ. Thuộc tính source giữ đường dẫn tương đối từ thư mục corpus, còn text giữ nội dung đã giải mã hoặc trích xuất. Ví dụ hai file nằm ở hai thư mục khác nhau nhưng cùng tên vẫn cần có source khác nhau. Nếu chỉ giữ tên file cuối cùng, báo cáo có thể trích nhầm nguồn.

Loader đi qua các thư mục con theo thứ tự ổn định. File Markdown và text được đọc bằng UTF-8; BOM được loại bỏ khi đọc. File PDF cần thư viện pypdf để trích xuất lớp văn bản. PDF chỉ có ảnh có thể không trả về text; project ghi rõ trường hợp đó, chưa có bước OCR.

Các file rỗng và định dạng không hỗ trợ được liệt kê trong kết quả bỏ qua. Lỗi đọc, PDF hỏng hoặc metadata sai cần được báo rõ để người dùng biết corpus chưa được chuẩn bị đúng. Không âm thầm coi file lỗi là tài liệu hợp lệ.

Đường dẫn nguồn giúp tìm lại file, nhưng không tự chứng minh nội dung có xuất xứ OWASP. Với tài liệu thực tế, cần giữ thêm URL chính thức, tên tài liệu, mục liên quan và ngày thu thập. Metadata chỉ mô tả xuất xứ; đọc được tài liệu không có nghĩa tài liệu đã được duyệt làm hướng dẫn sửa.
