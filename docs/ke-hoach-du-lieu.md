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

Nếu là đồ án phải bảo vệ và cần đầu vào "thực tế" đúng nghĩa (IP công khai, quét qua
mạng) thì thêm **#1 trong mục 6.2** vào mức "Đủ": thuê VPS miễn phí, dựng lại đúng lab
đó trên VPS, quét qua Internet. Chi phí 0 đồng, thời gian thêm khoảng 1 giờ.

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
data/raw/scans/lab-db/          # đã ignore, không vào Git (thêm thư mục vps/ nếu quét VPS)
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

## 6. Một đầu vào "thực tế" mà không vi phạm pháp luật

Đề tài hay được hiểu là "đi pentest một web bất kỳ để có file kết quả". Làm vậy là vi
phạm pháp luật, và cũng không cần thiết — xem mục 6.6. Phần này là các đường hợp pháp,
xếp theo độ "thực tế".

### 6.1 "Thực tế" nghĩa là gì

Không phải "của người khác". Ba thứ làm nên tính thực tế mà người chấm quan tâm:

1. **Hệ thống thật** — ứng dụng đang dùng được, CSDL có dữ liệu, cấu hình như triển khai
   thật; không phải app cố ý trồng lỗi.
2. **Đường mạng thật** — quét qua mạng chứ không chỉ `localhost`. Nhiều plugin "Remote"
   của Nessus và bước nhận diện hệ điều hành chỉ có dữ liệu khi có đường mạng thật; bản
   ghi cũng có IP, TLS, banner thật để viết phụ lục.
3. **Có quyền quét** — bạn là chủ sở hữu, hoặc có xác nhận bằng văn bản của người có
   thẩm quyền.

Tự dựng rồi quét chính nó vẫn là pentest thật. Không có chỗ nào trong luận văn cần chứng
minh "nạn nhân là người khác".

### 6.2 Bảy phương án

| # | Phương án | Độ thực tế | Chi phí | Hợp pháp | File lấy được | Ghi chú |
|---|---|---|---|---|---|---|
| 1 | **VPS của chính bạn** + ứng dụng mã nguồn mở (WordPress, Nextcloud, DVWA) + CSDL cấu hình yếu | Cao: IP công khai, mạng thật, Nessus quét qua Internet | 0 đồng (Oracle Cloud Always Free) đến ~150k/tháng | ✅ | `.nessus`, `nmap.xml`, `zap.json`, sqlmap log | **Khuyên dùng** — xem công thức ở 6.3 |
| 2 | **Ứng dụng của chính bạn** (đồ án môn khác, web của CLB) đưa lên VPS/VM | Cao nhất: app thật, không phải app trồng lỗi | như #1 | ✅ | tất cả | Có thêm finding "sạch" làm đối chứng âm rất thuyết phục |
| 3 | **VM nội bộ của khoa** + giấy phép viết tay của bộ môn/IT | Cao | 0 | ✅ khi có giấy | tất cả | Tờ giấy phép in vào phụ lục là điểm cộng hồ sơ |
| 4 | **Máy của bạn + Docker** (tài liệu [lab-quet-csdl.md](lab-quet-csdl.md)) | Trung bình: thiếu đường mạng thật | 0 | ✅ | tất cả | Nhanh nhất, nên làm trước để quen tay |
| 5 | **Phòng lab web được phép tấn công**: PortSwigger Web Security Academy, TryHackMe, HackTheBox, PentesterLab | Trung bình–cao (app thật, hạ tầng của họ nhưng họ cho phép) | 0 đến vài trăm k | ✅ theo điều khoản của họ | `zap.json`, sqlmap log | **Đọc điều khoản trước**: phần lớn cấm Nessus/quét cổng ồ ạt trên hạ tầng dùng chung → chỉ dùng cho tầng web |
| 6 | **`scanme.nmap.org`** — máy chủ của chính dự án Nmap, họ tuyên bố cho phép quét ("You are authorized to scan this machine with Nmap or other port scanners", vài lần mỗi ngày) | Thấp: không phải hệ thống của bạn | 0 | ✅ | `nmap.xml` của một host Internet thật | Dùng để so "host Internet thật" với lab của bạn trong phần nhận xét |
| 7 | **File export công khai** (bộ test của DefectDojo và dự án khác) | Thấp | 0 | ✅ | `.nessus` | Chỉ để kiểm tra tương thích định dạng; **không** dùng làm bằng chứng về lab |

Không cần làm hết. Với đồ án, **#4 (làm quen) → #1 (đầu vào chính) → #5 (tầng web cho
phong phú)** là đủ và kín về pháp lý.

### 6.3 Công thức VPS, 8 bước

1. **Chọn nơi thuê**: Oracle Cloud Always Free (VM ARM miễn phí 24/7), DigitalOcean /
   Vultr / Linode (~5 USD/tháng), hoặc trong nước: Vietnix, InterData, AZDIGI.
2. **Tạo 1 VM** Ubuntu 24.04, dùng SSH key, chỉ mở cổng 22 và các cổng sẽ quét.
3. **Cài Docker + compose** rồi copy `lab/docker-compose.yml` lên; đổi phần cổng từ
   `127.0.0.1:3306:3306` thành `3306:3306` cho những cổng cần thấy từ ngoài, và thay
   DVWA bằng ứng dụng bạn muốn (WordPress/Nextcloud cũng được, miễn là môi trường của bạn).
4. **Siết firewall** để chỉ máy bạn vào được cổng CSDL — đây là điểm quan trọng nhất:

   ```bash
   sudo ufw default deny incoming
   sudo ufw allow 22/tcp
   sudo ufw allow from <IP-nhà-bạn> to any port 3306 proto tcp
   sudo ufw allow from <IP-nhà-bạn> to any port 5432 proto tcp
   sudo ufw enable
   ```

   Cách an toàn hơn nữa: dựng WireGuard/Tailscale giữa máy bạn và VM, rồi để Nessus quét
   qua địa chỉ VPN — không cổng CSDL nào lộ ra Internet.
5. **Quét từ máy bạn** đúng như mục 4–7 của [lab-quet-csdl.md](lab-quet-csdl.md), chỉ đổi
   mục tiêu thành IP của VM.
6. **Lấy file export** và ghi biên bản: lệnh nguyên văn, phiên bản công cụ, thời điểm,
   IP đã lược.
7. Lưu ảnh chụp `docker compose config` và cấu hình firewall vào biên bản để người chấm
   đối chiếu được môi trường.
8. **Xoá VM** khi xong (`destroy`, không chỉ stop). Không để tồn tại một CSDL root rỗng
   có địa chỉ công khai.

**Cảnh báo bắt buộc đọc:** một MySQL root không mật khẩu lộ ra Internet sẽ bị quét trong
vài giờ và bị chiếm (cài mã đào tiền, tống tiền dữ liệu) trong vài ngày. Vì vậy: chỉ cho
đúng IP của bạn vào, hoặc dùng VPN; VM không chứa dữ liệu gì có giá trị; xong là xoá.
Nếu bạn *muốn* số liệu "cổng CSDL mở thì bị nhòm ngó trong bao lâu" để đưa vào luận văn
thì đó là số liệu thật và hợp pháp — nhưng chỉ làm trên VM mới, rỗng, bật log, để mở tối
đa vài giờ, chụp log rồi xoá ngay.

### 6.4 Một đoạn email xin phép, dùng được ngay

Nếu chọn phương án #3 (VM của khoa), gửi email — bản thân thư trả lời là "written
authorization" mà tài liệu pháp lý của Nmap khuyến nghị, in được vào phụ lục:

> Kính gửi thầy/cô … và bộ phận IT của Khoa,
>
> Em là … , MSSV … , đang làm đồ án về trợ lý AI sinh báo cáo kiểm thử bảo mật CSDL. Em
> xin phép được quét kiểm thử bảo mật đối với máy ảo … (địa chỉ …) trong khoảng thời gian
> … đến … .
>
> Công cụ dự kiến: Nmap, Nessus Essentials, sqlmap, OWASP ZAP, Burp (nếu có). Phạm vi: chỉ
> dò tìm và khai thác ở mức kiểm chứng (không phá hoại, không lấy dữ liệu thật, không cài
> mã), chạy từ máy cá nhân của em tại IP … , ngoài giờ học.
>
> Em xin phép được ghi lại kết quả (đã lược thông tin nhạy cảm) trong luận văn và phụ lục.
> Rất mong nhận được xác nhận của thầy/cô để em bắt đầu.

### 6.5 Nếu không cài được Nessus: OpenVAS/Greenbone

Greenbone Community Edition (OpenVAS) là mã nguồn mở, tự host, miễn phí, có họ kiểm tra
CSDL và xuất XML/CSV. Nhưng project **chưa có adapter cho định dạng GVM**, nên cần một
trong hai việc: tự chuyển tay file GVM sang JSON chuẩn hóa của project (khả thi khi số
bản ghi ít), hoặc tôi viết adapter GVM (khoảng 1–2 giờ, kèm quy tắc CWE tương ứng cho các
NVT tìm thấy).

### 6.6 Đừng làm

Pentest một website bất kỳ trên Internet, kể cả chỉ quét cổng, là chạm vào
[Điều 289 Bộ luật Hình sự](https://tuoitre.vn/giai-thich-quy-dinh-cua-bo-luat-hinh-su-ve-hanh-vi-xam-nhap-trai-phep-mang-may-tinh-20211123120351827.htm)
(Tội xâm nhập trái phép vào mạng máy tính, mạng viễn thông hoặc phương tiện điện tử của
người khác): khung cơ bản phạt tiền 50–300 triệu đồng **hoặc** tù 1–5 năm; có tổ chức,
lợi dụng chức vụ hoặc gây thiệt hại theo mức thì tù 3–7 năm, khung cao nhất tới 12 năm.
Nghị quyết của Ủy ban Thường vụ Quốc hội năm 2022
([giải thích khoản 1 Điều 289](https://pbgdpl.hanoi.gov.vn/quy-dinh-moi/-/asset_publisher/sxBNLsQSLyY8/content/ubtvqh-giai-thich-quy-inh-khoan-1-ieu-289-bo-luat-hinh-su))
nêu rõ hành vi "cố ý vượt qua cảnh báo, mã truy cập, tường lửa" cũng nằm trong phạm vi
điều luật — nghĩa là khi trang web đã ghi cảnh báo cấm mà vẫn vượt qua thì càng nặng, chứ
không phải nhẹ hơn.

Ngoài hình sự còn hai rủi ro thực tế khác: nhà mạng có thể cắt dịch vụ theo điều khoản sử
dụng (AUP) khi nhận khiếu nại, và nhà trường có thể kỷ luật. Đổi lại được gì? Một VM miễn
phí cho ra đúng loại file như vậy, hợp pháp, và tuyên bố trong luận văn còn mạnh hơn vì
tái lập được. Xem thêm
[Legal Issues](https://nmap.org/book/legal-issues.html) của Nmap về việc luôn có
authorization bằng văn bản.

## 7. Checklist trước khi coi là xong

- [ ] Có ít nhất 6 file thật: 2 Nmap, 1 sqlmap, 1–2 Nessus, 1 bản trước/sau.
- [ ] `import-summary.md` của Nmap có dòng `CWE gán theo quy tắc của dự án ...: 1`.
- [ ] `findings.json` của Nessus có `details.scanner_rule` là `nessus-10481`/`nessus-10483`.
- [ ] sqlmap có `Parameter:`/`Type:`/`Payload:` và `details.dbms` khác rỗng.
- [ ] Cặp trước/sau cho ra: trước có finding CSDL, sau không có.
- [ ] Có 1 lần chạy sai định dạng để chụp lại thông báo lỗi.
- [ ] Biên bản quét đầy đủ, có SHA-256 lấy từ `import_metadata.input_sha256`.
- [ ] Bảng nhãn có ≥30 dòng, gồm cả nhãn "không kết luận".
- [ ] Không file dữ liệu quét nào bị commit.
- [ ] Mục tiêu quét là máy của bạn, VM của khoa có xác nhận, hoặc phòng lab được phép —
      không có IP nào của người khác trong biên bản (xem mục 6.6).
- [ ] Nếu dùng VPS: cổng CSDL chỉ mở cho IP của bạn hoặc qua VPN, và VM đã được xoá sau khi lấy file.
