# Chunk và overlap

Đây là tài liệu mẫu kỹ thuật của project, không phải nguồn hướng dẫn bảo mật OWASP.

Chunking chia văn bản thành các đoạn nhỏ để chuẩn bị cho embedding và retrieval. Trong bản Tập 02, cách chia dùng số ký tự của chuỗi Python. Nó không dùng số byte của file và không tương đương số token mà model embedding xử lý.

Với chunk_size bằng 800 và overlap bằng 120, chunk đầu lấy lát cắt text[0:800]. Chunk thứ hai bắt đầu từ vị trí 680 và lấy text[680:1480]. Phần giao nhau có 120 ký tự. Khi đoạn cuối đã tới hết văn bản, vòng lặp phải dừng ngay để không sinh thêm đoạn trùng lặp.

Điều kiện hợp lệ là chunk_size lớn hơn không và overlap nằm trong khoảng từ không tới nhỏ hơn chunk_size. Nếu overlap bằng hoặc lớn hơn kích thước chunk, bước di chuyển có thể không tiến lên. Kiểm tra cấu hình phải thực hiện kể cả khi chưa có tài liệu nào.

Overlap giúp giữ lại một phần ngữ cảnh gần ranh giới nhưng không bảo đảm một ý dài sẽ luôn nằm trọn trong một chunk. Khi áp dụng cho tài liệu kỹ thuật, các bước sau có thể bổ sung cách chia theo tiêu đề hoặc mục. Không nối phần cuối của tài liệu này với phần đầu tài liệu khác.

Mỗi chunk giữ source, index, start, end, text, hash file gốc và metadata. Giá trị start bao gồm ký tự đầu, còn end là vị trí ngay sau ký tự cuối. Có thể kiểm tra tính đúng bằng phép so sánh chunk.text với document.text[start:end]. Với PDF, các vị trí này tính trên văn bản đã trích xuất, không phải số trang.

Kết quả được lưu thành JSONL trong data/processed để kiểm tra trước khi sang bước tạo vector. Bước này không gọi API và không tự tải model embedding. Số chunk phụ thuộc độ dài tài liệu thực tế, không nhất thiết giống ví dụ trong video.
