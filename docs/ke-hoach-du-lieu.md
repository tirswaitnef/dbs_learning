# Kế hoạch dữ liệu đầu vào: bao nhiêu file thì đủ

Tài liệu này trả lời "cần bao nhiêu kiểu đầu vào thì đủ để bảo vệ đồ án". Cách dựng lab
và lệnh quét từng công cụ nằm ở [lab-quet-csdl.md](lab-quet-csdl.md).

Nguyên tắc: **đếm theo loại tình huống mà đầu vào chứng minh được, không đếm theo số
file**. 20 file cùng một loại không mạnh bằng 6 file trải đủ 6 tình huống. Mỗi tình
huống phải có một câu trong luận văn mà nó làm bằng chứng.

## 1. Bảy tình huống cần có

| # | Tình huống | Bằng chứng cho luận văn | Cách tạo | File sinh ra | Kỳ vọng sau chuẩn hóa | Bắt buộc |
|---|---|---|---|---|---|---|
| 1 | CSDL ở tầng máy chủ thiếu xác thực (root không mật khẩu) | Quy tắc `nmap-mysql-empty-password` và Nessus 10481 hoạt động trên file thật | `weak-mysql` trong `lab/` | `nmap-lab.xml`, `nessus-lab.nessus` | Nmap 1 finding `NMAP-...-S0` CWE-1393; Nessus 1 finding CWE-1393 | **Có** |
| 2 | CSDL ở tầng máy chủ xác thực sai cấu hình (`trust`) | Quy tắc Nessus 10483 | `weak-postgres` | `nessus-lab.nessus` | Nessus 1 finding CWE-1393 | **Có** |
| 3 | SQL injection ở tầng ứng dụng | Adapter sqlmap, CWE-89, A05; phần "tầng app" của phạm vi | DVWA + sqlmap | `sqlmap-dvwa.log` | 1 finding `SQLMAP-0`, có payload và kỹ thuật | **Có** |
| 4 | Engine CSDL được xác định từ log | Khung suy luận đọc `back-end DBMS` | như #3 (dòng `back-end DBMS` có trong log thật) | như trên | `engine` trong khung khác "chưa xác định" | Nên có |
| 5 | Finding nhiều CWE (cổng Top 10 xét cả danh sách) | Quy tắc nhiều CWE trên file thật | Burp Pro (nếu có) hoặc alert ZAP SQLi nhiều mã CWE | `burp-lab.xml` / `zap-lab.json` | Vào A05 nếu mọi CWE cùng nhóm | Nên có |
| 6 | Quan sát cổng/dịch vụ, không phải lỗ hổng | Hệ thống không tự biến quan sát thành lỗ hổng | Nmap chỉ `-sV`, không script | `nmap-ports.xml` | Các bản ghi `observation`, không có CWE | Nên có |
| 7 | Quét không tìm thấy gì (đối chứng âm) | "0 bản ghi ≠ hệ thống an toàn" — câu này phải có bằng chứng | Quét lại sau khi đặt mật khẩu (mục 3) | `nmap-hardened.xml`, `nessus-hardened.nessus` | Không có finding CSDL | **Có** |
| 8 | File sai định dạng/bị cắt | Hệ thống báo lỗi chứ không trả kết quả giả | Chọn sai `--format`, hoặc cắt đuôi file | không cần lưu | `Import failed (...)` và exit code 1 | Nên có |

Số file thật cần lưu: **6–8 file**. Đó là con số "đủ", không phải 20.

## 2. Ba mức ngân sách

| Mức | Thời gian | Làm gì | Chứng minh được |
|---|---|---|---|
| **Tối thiểu** | ~1 giờ | XAMPP/Docker + Nmap (#1, #6) + sqlmap (#3) | Đủ cho mục "kiểm thử CSDL ở hai tầng" và câu chuyện SQLi; quy tắc NSE có bằng chứng thật |
| **Đủ (khuyến nghị)** | ~3–4 giờ | Tối thiểu + Nessus (#1, #2, #4) + quét lại sau khi siết cấu hình (#7) | 10 quy tắc Nessus có bằng chứng thật; có đối chứng âm; có cặp trước/sau để so báo cáo |
| **Đầy đủ** | ~6–8 giờ | Đủ + ZAP hoặc Burp (#5) + MySQL 5.7 hết hỗ trợ (CWE-1104) + MongoDB/Redis nếu thêm service | Phủ 12/12 quy tắc; có finding nhiều CWE; so sánh công cụ miễn phí với Nessus |

Với đồ án, **mức "Đủ" là điểm dừng hợp lý**. ZAP/Burp chỉ làm dày thêm phần tầng ứng
dụng, không mở thêm quy tắc CSDL nào.

## 3. Cặp trước/sau — thứ đáng làm nhất mà ít người làm

Quét lab ở trạng thái yếu, rồi **siết cấu hình và quét lại**, cùng công cụ:

```bash
# Trước: root không mật khẩu / trust
docker compose up -d
nmap -Pn -sV -p 3306,5432 --script mysql-empty-password -oX data/raw/scans/lab-db/truoc/nmap.xml 127.0.0.1

# Sau: đặt mật khẩu, chuyển sang xác thực mật khẩu
docker compose exec weak-mysql mariadb -uroot -e "ALTER USER 'root'@'%' IDENTIFIED BY 'MatKhauManh!2026'; FLUSH PRIVILEGES;"
nmap -Pn -sV -p 3306,5432 --script mysql-empty-password -oX data/raw/scans/lab-db/sau/nmap.xml 127.0.0.1
```

Hai file này dùng cho đúng ba việc:

1. **Chứng minh báo cáo khác nhau theo đầu vào.** Cùng một lab, cùng lệnh, chỉ khác trạng
   thái cấu hình: báo cáo trước có finding CSDL, báo cáo sau không có. Đối chiếu bằng
   `compare_reports` (xem README, mục "Suy luận theo đầu vào") sẽ ra tỉ lệ trùng khác nhau
   ở phần bằng chứng, trong khi phần khung báo cáo vẫn giống — đúng như thiết kế.
2. **Đối chứng âm (#7).** Không có bản ghi không đồng nghĩa an toàn; hệ thống phải nói
   đúng như vậy chứ không suy ra "đã sửa xong".
3. **Kiểm tra quy tắc không bắn nhầm.** Nếu sau khi đặt mật khẩu mà hệ thống vẫn gán
   CWE-1393 thì quy tắc sai — đây là phép thử mà đọc code không thay được.

Nhớ ghi cả hai lần vào biên bản quét (mục 9 của [lab-quet-csdl.md](lab-quet-csdl.md)).

## 4. Bộ gán nhãn để đo chất lượng AI

Mục tiêu **30–50 finding có nhãn**, con số đủ để nói "chất lượng gợi ý là bao nhiêu
phần trăm" mà không cần thống kê cao siêu. Phân bổ thực tế:

| Nguồn | Số finding | Ghi chú |
|---|---|---|
| Lab: Nmap + sqlmap + Nessus (mức "Đủ") | ~10–20 | Một phần là quan sát cổng, không phải lỗ hổng — vẫn gán nhãn để kiểm tra hệ thống có xếp đúng loại |
| Cặp trước/sau (#7) | +1–5 | Chủ yếu để kiểm tra đối chứng âm |
| 10 file `.nessus` công khai (bộ test của dự án khác) | ~25–35 | Dùng cho độ tương thích định dạng và thống kê CWE; **không** phải bằng chứng về lab |
| Fixture trong `tests/fixtures/scanners/` | 6 | Chỉ để kiểm tra code, dán nhãn chỉ để đối chiếu |

Khung CSV gán nhãn ở mục 9 của [lab-quet-csdl.md](lab-quet-csdl.md). Nguyên tắc: tự đọc
bằng chứng rồi kết luận, không để AI điền hộ; nhãn "không kết luận" cũng là nhãn hợp lệ
và đáng ghi.

Nếu thời gian eo hẹp: gán nhãn **tất cả** finding từ lab (10–20 dòng) và **20 dòng đầu**
trong 10 file Nessus công khai. Đủ để nói về tỉ lệ, và trung thực về cỡ mẫu nhỏ.

## 5. Tổ chức file và lưu trữ

```
data/raw/scans/lab-db/          # đã ignore, không vào Git
├── truoc/                      # lần quét trạng thái yếu
│   ├── nmap.xml  nmap.txt  sqlmap-out/log  zap.json  nessus.nessus
├── sau/                        # lần quét sau khi siết cấu hình
│   ├── nmap.xml  nmap.txt  nessus.nessus
└── BIEN-BAN.md                 # biên bản quét (mục 9 của lab-quet-csdl.md)
data/processed/lab-db/          # kết quả chuẩn hóa, mỗi lần một thư mục riêng
data/reports/lab-db/            # báo cáo sinh ra cho từng lần
```

Ba việc không được quên:

- Giữ **file gốc** cạnh bản chuẩn hóa; báo cáo ghi SHA-256 của file gốc, sửa file gốc sau
  đó sẽ lệch hash và lộ ngay.
- **Không commit** dữ liệu quét (đã chặn bởi `.gitignore`). Nếu luận văn cần nộp kèm thì
  lược IP/hostname/cookie rồi mới thêm ngoại lệ, và ghi hash bản đã lược vào
  `VALIDATION.md`.
- Biên bản ghi **lệnh nguyên văn**, phiên bản công cụ, thời điểm; người chấm thường hỏi
  câu này trước khi xem bảng kết quả.

## 6. Checklist trước khi coi là xong

- [ ] Có ít nhất 6 file thật: 2 Nmap, 1 sqlmap, 1–2 Nessus, 1 bản trước/sau.
- [ ] `import-summary.md` của Nmap có dòng `CWE gán theo quy tắc của dự án ...: 1`.
- [ ] `findings.json` của Nessus có `details.scanner_rule` là `nessus-10481`/`nessus-10483`.
- [ ] sqlmap có `Parameter:`/`Type:`/`Payload:` và `details.dbms` khác rỗng.
- [ ] Cặp trước/sau cho ra: trước có finding CSDL, sau không có.
- [ ] Có 1 lần chạy sai định dạng để chụp lại thông báo lỗi.
- [ ] Biên bản quét đầy đủ, có SHA-256 lấy từ `import_metadata.input_sha256`.
- [ ] Bảng nhãn có ≥30 dòng, gồm cả nhãn "không kết luận".
- [ ] Không file dữ liệu quét nào bị commit.
