# Lấy dữ liệu đầu vào thật: dựng lab và quét

Tài liệu này trả lời câu hỏi "lấy file test đầu vào ở đâu". Đầu vào của project là
**file kết quả do scanner xuất ra**, không phải dữ liệu tự viết và cũng không phải kết
quả project tự tạo. Danh sách định dạng đọc được nằm ở
[SCANNER_INPUTS.md](../SCANNER_INPUTS.md); ở đây là phần còn thiếu: dựng mục tiêu, chạy
công cụ, lấy file, và kiểm tra file đã vào đúng đường.

Có ba đường lấy đầu vào, dùng phối hợp:

1. **Lab tự dựng (khuyên dùng cho đồ án):** [lab/docker-compose.yml](../lab/docker-compose.yml)
   dựng DVWA (tầng ứng dụng) và hai CSDL cấu hình yếu (tầng máy chủ), rồi quét bằng
   Nmap, sqlmap, ZAP, Nessus Essentials. Đây là đường duy nhất tạo ra finding CSDL thật
   khớp với 12 quy tắc trong `src/rag/data/scanner-rules.json`.
2. **File export công khai:** một số repo test của dự án khác có sẵn file `.nessus`,
   `-oX` XML, log sqlmap thật để thử độ tương thích của adapter mà không cần quét.
3. **Fixture giả lập có sẵn trong repo:** `tests/fixtures/scanners/`, chỉ để biết lệnh
   chạy, không phải bằng chứng quét.

Đầu vào này dùng cho ba việc, nên lấy file gốc chứ đừng chỉ lấy báo cáo: chạy demo
trong luận văn, kiểm chứng quy tắc CWE trên file thật, và gán nhãn để đo chất lượng
(theo mục 9).

## 1. Bốn file cần lấy

| # | File (đề xuất) | Công cụ | `--format` | Nội dung chứng minh | Sau khi chuẩn hóa |
|---|---|---|---|---|---|
| 1 | `nmap-lab.xml` | Nmap `-oX` | `nmap` | Cổng/dịch vụ thật của mục tiêu; NSE xác nhận tài khoản CSDL không mật khẩu | 1 quan sát mỗi cổng + 1 finding `NMAP-<h>-<p>-S<k>`, CWE-1393, A07 |
| 2 | `sqlmap-dvwa.log` | sqlmap | `sqlmap-log` | SQL injection tầng ứng dụng kèm payload và kỹ thuật thật | `SQLMAP-0`, CWE-89, A05 |
| 3 | `zap-dvwa.json` | ZAP (report JSON) | `zap` | Bằng chứng request/response ở tầng web | alert theo `pluginid`, giữ `evidence` |
| 4 | `nessus-lab.nessus` | Nessus Essentials | `nessus` | Kết quả của scanner thương mại, plugin họ Databases | `NESSUS-<h>-<i>`, CWE-1393, A07 |

File 1 và 2 là phần lõi: chúng cho cả lỗi tầng ứng dụng (SQLi) lẫn lỗi cấu hình máy chủ
CSDL (xác thực, tài khoản mặc định) — đúng hai nửa phạm vi mà đề tài cần. File 3 và 4
làm dày bằng chứng và cho phép so sánh công cụ miễn phí với công cụ thương mại.

Đường dẫn lưu, tạo một lần:

```powershell
mkdir data\raw\scans\lab-db
```

Thư mục này đã bị `.gitignore` chặn (`data/raw/scans/*`), nên file thật không vào Git.
Nếu cần nộp kèm luận văn thì xem ghi chú ở cuối mục 8.

## 2. Chuẩn bị

| Phần mềm | Vì sao cần | Ghi chú |
|---|---|---|
| Docker Desktop (Windows/macOS) hoặc Docker Engine + compose v2 (Linux) | dựng lab | Kiểm tra: `docker compose version` phải in ra `v2.x` |
| Nmap | file 1 | Trên Windows: cài kèm Npcap và chạy PowerShell bằng quyền Administrator |
| sqlmap | file 2 | Chạy được bằng Python 3; trên Windows nên dùng `sqlmap` từ bản release |
| ZAP | file 3 | Có hai cách: ZAP Desktop (khuyên dùng) hoặc container, xem mục 5.3 |
| Nessus Essentials | file 4 | Miễn phí cho 16 IP, cần đăng ký email lấy mã kích hoạt; cài nặng (~2 GB) và lần đầu tải plugin rất lâu |

Không cần cài tất cả trong một lần. Thứ tự ít tốn công nhất: Nmap (5 phút) → sqlmap
(15 phút) → Nessus (30–90 phút, phần lớn là chờ tải plugin) → ZAP (20 phút).

**Phạm vi hợp pháp:** chỉ quét máy của mình. Cả lab này lẫn các IP công cộng đều không
phải mục tiêu hợp pháp. Truy cập trái phép hệ thống thông tin của người khác là tội
danh riêng trong Bộ luật Hình sự (Điều 289), không phải lỗi hành chính.

## 3. Dựng lab

### 3.1 Mở terminal đúng chỗ

Ba lệnh dưới đây gõ trong terminal, **mỗi dòng một lần Enter**; phần dấu nhắc
(`PS C:\Users\...>` trên PowerShell, `$` trên Linux/macOS) là của terminal, không gõ theo.

- **Windows:** mở thư mục project bằng File Explorer, bấm vào thanh địa chỉ, gõ
  `powershell` rồi Enter — terminal mở ra ngay tại thư mục đó. Hoặc trong VS Code:
  **Terminal → New Terminal**.
- **Linux/macOS:** mở terminal rồi `cd` tới thư mục project.

Thư mục project là nơi có `README.md` và thư mục `lab`; kiểm tra bằng `ls` (PowerShell
cũng hiểu `ls`). Nếu chưa thấy thư mục `lab`, thường là đang ở nhánh `main`: chạy
`git fetch origin` rồi `git switch arena/e28181c3-dbs-learning`, hoặc tải bản zip của
nhánh tại <https://github.com/tirswaitnef/dbs_learning/archive/refs/heads/arena%2Fe28181c3-dbs-learning.zip>.

Điều kiện trước khi chạy: Docker Desktop (hoặc Docker Engine) đã cài và **đang chạy**.
Kiểm tra bằng hai lệnh:

```bash
docker version          # phải in ra cả Client và Server
docker compose version  # phải là v2.x
```

Nếu terminal báo không nhận lệnh `docker`, hoặc báo không kết nối được daemon, thì Docker
chưa cài / chưa chạy / terminal được mở từ trước khi cài — mở Docker Desktop rồi mở một
terminal mới.

### 3.2 Chạy lab

```bash
cd lab
docker compose up -d
docker compose ps
```

Không muốn `cd` thì chạy từ thư mục gốc project:

```bash
docker compose -f lab/docker-compose.yml up -d
```

Lần đầu chạy, `up -d` sẽ tải 4 image (DVWA, MariaDB 10, MariaDB 11.4, PostgreSQL 16) —
vài trăm MB, mất vài phút. Kết quả mong đợi: 4 container `dvwa`, `db`, `weak-mysql`,
`weak-postgres` ở trạng thái `Up`; trong đó ba dòng có cổng `127.0.0.1:4280->80/tcp`,
`127.0.0.1:3306->3306/tcp`, `127.0.0.1:5432->5432/tcp`, còn `db` không có cổng nào (đúng
thiết kế). Sau đó mở `http://127.0.0.1:4280`:
nếu DVWA hiện trang setup thì bấm **Create / Reset Database**, nếu hiện trang đăng nhập
thì vào bằng `admin` / `password`, rồi vào **DVWA Security** chọn **Low** (mức thấp có
lỗi SQLi rõ nhất để làm demo).

Kiểm tra hai mục tiêu CSDL trước khi quét — bước này chỉ xem cấu hình, chưa phải quét:

```bash
docker compose exec weak-mysql mariadb -uroot -e "select user, host, plugin from mysql.user"
docker compose exec weak-postgres psql -U postgres -c "show hba_file"
docker compose exec weak-postgres sh -c 'grep -v "^#" "$PGDATA/pg_hba.conf" | grep -v "^$"'
```

Điều cần thấy:

- MySQL: dòng `root | % | ...` — tài khoản `root` cho phép từ mọi host, và vào được
  bằng `mariadb -uroot` không mật khẩu. Đây chính là tiền đề của plugin Nessus 10481.
- PostgreSQL: `pg_hba.conf` có các dòng `host all all all trust` — mọi kết nối TCP được
  chấp nhận không cần mật khẩu, tiền đề của plugin Nessus 10483.

Hai điều dễ quên:

- Cổng chỉ mở trên `127.0.0.1` của máy bạn. Nếu quét từ máy ảo Kali thì đổi
  `127.0.0.1` trong `docker-compose.yml` thành IP host-only (ví dụ `192.168.56.1`) và
  chạy lại `docker compose up -d`; chỉ trong mạng host-only đó.
- Xong việc: `docker compose down -v`. `weak-mysql`/`weak-postgres` cố ý không có volume,
  nên mỗi lần dựng lại là CSDL mới đúng trạng thái không mật khẩu.

## 4. Quét bằng Nmap (file 1)

Từ thư mục gốc project:

```powershell
nmap -Pn -sV -p 80,4280,3306,5432 --script mysql-empty-password -oX data/raw/scans/lab-db/nmap-lab.xml -oN data/raw/scans/lab-db/nmap-lab.txt 127.0.0.1
```

- `-oX` là file cho project đọc; `-oN` là bản chữ dễ đọc để dán vào phụ lục luận văn.
- `--script mysql-empty-password` phải gọi đúng tên vì script thuộc nhóm `intrusive`,
  không nằm trong bộ `default`. Script chỉ thử hai tài khoản mặc định là `root` và
  tài khoản ẩn danh, và chỉ in dòng khi đăng nhập thành công.
- Không cần `-p 5432` cho quy tắc (chưa có script NSE nào được ghi nhận cho
  PostgreSQL), nhưng để lại cũng tốt vì nó cho một bản ghi quan sát cổng.

Dòng mong đợi trong output:

```
3306/tcp open  mysql   MariaDB 11.4.x
| mysql-empty-password:
|_  root account has empty password
```

Không thấy dòng này nghĩa là quy tắc sẽ không bắn — kiểm tra lại `mysql.user` ở mục 3.
Nếu Nmap báo thiếu quyền trên Windows, thêm `-sT` (connect scan) hoặc chạy lại với
quyền Administrator.

## 5. Quét bằng sqlmap (file 2)

### 5.1 Lấy cookie phiên DVWA

DVWA yêu cầu đăng nhập, nên sqlmap phải mang cookie phiên:

1. Đăng nhập `http://127.0.0.1:4280` bằng `admin` / `password`.
2. Vào **DVWA Security**, chọn **Low** (DVWA ghi mức này vào cookie `security`).
3. Mở DevTools (F12) → **Application** → **Cookies** → `http://127.0.0.1:4280` → sao
   chép giá trị `PHPSESSID`.

### 5.2 Chạy sqlmap và lấy log

```powershell
sqlmap -u "http://127.0.0.1:4280/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=<dán giá trị vừa sao chép>; security=low" --batch --disable-coloring --level=3 --risk=2 --dbms=MySQL --flush-session --output-dir=data/raw/scans/lab-db/sqlmap-out
```

- `--disable-coloring` để log sạch mã màu (parser cũng tự xóa ANSI, nhưng log sạch vẫn
  dễ đối chiếu hơn).
- `--flush-session` để không dùng lại session cũ; nếu không, sqlmap có thể in "resumed
  from stored session" và kết quả là của lần chạy trước.
- `--dbms=MySQL` để bỏ qua bước dò DBMS khác, chạy nhanh hơn.

File cần lấy là `data/raw/scans/lab-db/sqlmap-out/log`. sqlmap ghi khối kết quả vào file
này ở dạng chữ thường (không kèm tiền tố thời gian), đúng dạng adapter đọc được:

```
sqlmap identified the following injection point(s) with a total of N HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1415=1415
---
back-end DBMS: MySQL
```

Nếu bạn chỉ chuyển hướng màn hình (`... > data/raw/scans/lab-db/sqlmap-dvwa.log`) thì
cũng dùng được: khối kết quả in ra qua dumper nên không bị gắn tiền tố log.

Hai lỗi hay gặp:

- "all tested parameters do not appear to be injectable": sai hoặc thiếu cookie, chưa
  chọn mức Low, hoặc chưa bấm **Create / Reset Database** trong DVWA.
- Parser báo `No recognized final sqlmap finding/negative result` hoặc `Incomplete
  sqlmap injection block`: file đang đưa vào không phải log kết quả cuối (bị cắt, bị
  sửa tay, hoặc chỉ có dòng heuristic "might be injectable"). Lấy lại nguyên file `log`.

## 6. Quét bằng ZAP (file 3)

### 6.1 ZAP Desktop — cách lấy được alert SQLi

Trình duyệt của ZAP phải đi qua proxy của nó để ZAP thấy được phiên đăng nhập:

1. Mở ZAP → **Manual Explore** (hoặc cấu hình proxy `127.0.0.1:8080` cho Firefox/Chrome
   của bạn) → mở `http://127.0.0.1:4280`.
2. Đăng nhập DVWA, chọn mức **Low**, rồi tự tay mở các trang có lỗ hổng, tối thiểu:
   `/vulnerabilities/sqli/?id=1&Submit=Submit` và
   `/vulnerabilities/sqli_blind/?id=1&Submit=Submit`. Mở bằng trình duyệt đúng cách này
   để URL và cookie nằm trong cây Sites của ZAP; nếu chỉ dán URL vào hộp thoại quét thì
   ZAP không có phiên đăng nhập và sẽ chỉ thấy trang login.
3. Trong cây **Sites**, bấm phải `http://127.0.0.1:4280` → **Attack** → **Active Scan**
   → **Start Scan**. Chờ đến khi tiến trình đạt 100%.
4. **Report** → **Generate Report** → chọn template JSON (bản traditional; nếu có template
   kèm request/response thì chọn bản đó để `evidence` dày hơn) → **Generate** → lưu vào
   `data/raw/scans/lab-db/zap-dvwa.json`.

Alert đáng quan tâm: **SQL Injection** (CWE-89) và **SQL Injection - MySQL**; bản blind
cũng cho "Blind SQL Injection". Đó là các finding đi vào A05 và khớp thẻ SQLi có sẵn.

### 6.2 Chạy ZAP bằng container (không cần cài ZAP)

```bash
cd data/raw/scans/lab-db
docker run --rm --network dbs-learning-lab_default -v "${PWD}:/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t http://dvwa/ -J zap-dvwa.json
```

- `--network dbs-learning-lab_default` là mạng của lab, nên ZAP gọi thẳng container
  `dvwa` bằng tên service; không cần biết IP.
- Cách này **không có phiên đăng nhập**, nên nó chỉ quét được trang login và các trang
  công khai (cookie thiếu HttpOnly/Secure, thiếu header, CSRF token...). Muốn có alert
  SQLi trên DVWA thì dùng 6.1, hoặc truyền context file có form-based auth qua `-n`.
- Mã thoát của script: 0 thành công, 1 có FAIL, 2 có WARN, 3 lỗi khác. Mã 2 vẫn là
  chạy xong bình thường (mặc định mọi alert là WARN).

## 7. Quét bằng Nessus Essentials (file 4)

1. Đăng ký Nessus Essentials tại
   <https://www.tenable.com/products/nessus/nessus-essentials> bằng email, nhận mã kích
   hoạt; tải bản cài cho hệ điều hành của bạn.
2. Cài, rồi mở `https://localhost:8834/`. Trình duyệt sẽ cảnh báo chứng chỉ tự ký —
   chấp nhận và tiếp tục. Chọn **Nessus Essentials**, dán mã kích hoạt, tạo tài khoản
   quản trị, rồi **chờ tải và biên dịch plugin** (lần đầu rất lâu; đừng tắt máy giữa
   chừng, có thể mất 30–60 phút).
3. **New Scan** → **Basic Network Scan** → đặt tên `lab-db` → **Targets**: `127.0.0.1`.
4. Trong phần cài đặt của scan, mở **Discovery → Port Scanning**, chuyển sang **Custom**
   và ghi `80,4280,3306,5432` (danh sách cổng chung có thể không bao gồm cổng lab).
5. **Launch** và chờ. Mở tab **Vulnerabilities** của scan, lọc theo họ **Databases**.
   Hai plugin cần thấy:

   | Plugin ID | Tên | Mức độ |
   |---|---|---|
   | 10481 | MySQL Unpassworded Account Check | High |
   | 10483 | PostgreSQL Default Unpassworded Account | High |

6. **Export** (trong trang kết quả scan) → chọn định dạng **Nessus** → lưu thành
   `data/raw/scans/lab-db/nessus-lab.nessus`. Export CSV/HTML/PDF không dùng được:
   adapter chỉ đọc `.nessus` (XML v2).

Ghi lại vào biên bản: phiên bản Nessus, ngày quét, phiên bản plugin set (Settings →
About), và mục **Thorough checks** đang bật hay tắt.

Nếu không thấy 10481/10483: template **Basic Network Scan** không bật *thorough checks*,
mà trang plugin 10483 của Tenable có ghi mục này là tùy chọn. Thử lại bằng template
**Advanced Scan** (template này bật thorough checks) rồi so sánh. Nếu vẫn không có,
ghi lại sự việc đó trong luận văn — nó là một nhận xét thật về công cụ, không phải lỗi
của bạn.

Nessus là bước nặng nhất. Nếu không cài được, ba file kia đã đủ để chạy demo và kiểm
chứng quy tắc; khi đó phần "so sánh với scanner thương mại" trong luận văn nên viết là
chưa thực hiện, đừng thay bằng dữ liệu tự tạo.

**Burp Suite:** bản Community không có scanner, nên không xuất được *issues XML* có
nghĩa. Nếu có Burp Pro thì quét cùng mục tiêu và Export → **Issues** → XML; adapter
`burp` đọc được file đó, và các issue SQLi của Burp thường gắn nhiều CWE (89, 94, 116)
— tất cả đều thuộc A05 nên vẫn được gợi ý.

## 8. Đưa file vào project

Chuẩn hóa từng file (không gọi AI, không cần mạng):

```powershell
python scripts/normalize_scan.py --input data/raw/scans/lab-db/nmap-lab.xml --format nmap --output data/processed/lab-db/nmap
python scripts/normalize_scan.py --input data/raw/scans/lab-db/sqlmap-out/log --format sqlmap-log --output data/processed/lab-db/sqlmap
python scripts/normalize_scan.py --input data/raw/scans/lab-db/zap-dvwa.json --format zap --output data/processed/lab-db/zap
python scripts/normalize_scan.py --input data/raw/scans/lab-db/nessus-lab.nessus --format nessus --output data/processed/lab-db/nessus
```

Mỗi lệnh in ra số bản ghi và hai đường dẫn `findings.json`, `import-summary.md`. Kiểm tra
theo bảng sau — cột phải là thứ phải thấy trong `import-summary.md`:

| File | Kỳ vọng | Căn cứ |
|---|---|---|
| Nmap | Dòng `CWE gán theo quy tắc của dự án vì công cụ không ghi CWE: 1`, và một bản ghi `NMAP-0-1-S0` với `CWE-1393 (gán theo quy tắc ánh xạ của dự án...)` | Quy tắc `nmap-mysql-empty-password` |
| sqlmap | Một bản ghi `SQLMAP-0`, `CWE-89` | Quy tắc adapter SQLi cổ điển |
| ZAP | Alert theo `pluginid`, có `evidence`; alert nhiều CWE bị chặn đúng như thiết kế | Cổng Top 10 xét cả danh sách CWE |
| Nessus | `CWE gán theo quy tắc...: 2` nếu có cả 10481 và 10483 | Quy tắc `nessus-10481`, `nessus-10483` |

Kiểm tra chi tiết một bản ghi, ví dụ với Nmap:

```powershell
python -c "import json;d=json.load(open('data/processed/lab-db/nmap/findings.json'));f=[x for x in d['findings'] if x['cwe']=='CWE-1393'];print(json.dumps(f,ensure_ascii=False,indent=2)[:1500])"
```

Trong đó `details.scanner_rule` và `details.cwe_mapping` là bằng chứng cho thấy CWE đến
từ quy tắc viết tay chứ không phải từ công cụ; `import_metadata.input_sha256` là SHA-256
của file gốc (khỏi tính tay bằng `Get-FileHash`).

Ra báo cáo thử ngay, không cần AI:

```powershell
python scripts/generate_report.py --input data/processed/lab-db/nessus/findings.json --format normalized --mode demo --output data/reports/lab-db-nessus
```

Với finding CSDL, kết quả mong đợi ở chế độ `demo` là: finding vào đúng nhóm
**A07:2025 Authentication Failures** trong mục 3 của `report.md`, nhưng mục 6 để trống và
trạng thái là `no_supported_guidance`, vì `cards.json` hiện chỉ có thẻ SQLi và XSS. Muốn
có phần hướng dẫn cho lỗi CSDL thì phải chạy `--mode owasp` (cần `GEMINI_API_KEY` và
model E5 tải về máy) — và đọc kỹ mục "Dữ liệu gửi lên Gemini" trong README trước khi gửi
dữ liệu thật. Đây là giới hạn đã biết, không phải lỗi khi bạn chạy lệnh.

Nếu luận văn cần nộp kèm chính file export: đổi tên miền/IP riêng tư, xóa cookie và
token phiên trong file, rồi thêm một dòng ngoại lệ vào `.gitignore`, và ghi SHA-256 của
bản đã sửa vào `VALIDATION.md` để người đọc phân biệt được bản gốc với bản đã lược. Mặc
định của repo là giữ các file này ngoài Git.

## 9. Biên bản quét và nhãn đánh giá

Mỗi lần quét, ghi một dòng vào biên bản. Phần này vào phụ lục luận văn, và là thứ người
chấm hỏi trước tiên khi thấy bảng kết quả:

| STT | Ngày giờ | Mục tiêu | Công cụ + phiên bản | Lệnh đã chạy | File kết quả | SHA-256 | Ghi chú |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-15 20:10 (+07) | 127.0.0.1 | Nmap 7.94 | `nmap -Pn -sV -p 80,4280,3306,5432 --script mysql-empty-password -oX ... 127.0.0.1` | `nmap-lab.xml` | `a28ae996...` | Script bắn đúng 1 dòng |

SHA-256 lấy từ `import_metadata.input_sha256` trong `findings.json` sau khi chuẩn hóa,
nên không cần tính riêng.

Muốn đo chất lượng thì cần nhãn. Mỗi finding một dòng, tự đọc bằng chứng rồi kết luận,
không để AI điền hộ:

```csv
file,finding_id,tool,title,cwe_tool,cwe_rule,top10,label_cwe,label_top10,label_guidance,label_evidence,note
nmap-lab.xml,NMAP-0-1-S0,Nmap,MySQL account with empty password,,nmap-mysql-empty-password,A07,đúng,đúng,chưa có,đủ,root@% vào được bằng mật khẩu rỗng
```

- `label_cwe`: `đúng` / `sai` / `không kết luận` cho CWE mà project gán.
- `label_top10`: nhóm A07 có đúng là nhóm mà OWASP xếp cho lỗi này không.
- `label_guidance`: phần khắc phục có đúng và đủ không (`đúng` / `một phần` / `sai` /
  `chưa có`).
- `label_evidence`: bằng chứng trong file có đủ để khẳng định lỗi không.

Nhãn này dùng cho cả hai việc: đếm số finding được gợi ý đúng, và hiệu chỉnh ngưỡng
truy xuất (xem giới hạn #3 trong README).

## 10. Lỗi thường gặp

| Hiện tượng | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| `'docker' is not recognized` / `command not found` | Chưa cài Docker, hoặc terminal mở từ trước khi cài | Cài Docker Desktop; mở terminal mới |
| `error during connect ... daemon is not running` | Docker Desktop chưa chạy | Mở Docker Desktop, chờ engine báo running |
| `no configuration file provided: not found` | Đang đứng sai thư mục, không phải chỗ có `docker-compose.yml` | `cd lab` từ thư mục gốc project, hoặc `docker compose -f lab/docker-compose.yml up -d` |
| `permission denied ... docker.sock` (Linux) | Tài khoản chưa thuộc nhóm `docker` | `sudo usermod -aG docker $USER` rồi đăng nhập lại, hoặc tạm dùng `sudo docker compose up -d` |
| `docker compose` không tìm thấy, chỉ có `docker-compose` | Máy còn compose v1 | Dùng `docker-compose up -d`, hoặc cài plugin compose v2 |
| Báo cổng đã bị dùng | Máy đã có MySQL/PostgreSQL/Apache | Đổi cổng bên trái trong `docker-compose.yml` (ví dụ `"127.0.0.1:3307:3306"`) rồi `up -d` lại, nhớ đổi cả lệnh quét |
| MariaDB vẫn đòi mật khẩu | Volume cũ đã khởi tạo trước đó — biến môi trường chỉ có tác dụng ở lần khởi tạo đầu | `docker compose down -v` rồi `up -d` |
| PostgreSQL vẫn đòi mật khẩu | Như trên, `pg_hba.conf` đã sinh từ trước | `docker compose down -v` rồi `up -d` |
| DVWA hiện trang setup | Lần chạy đầu, chưa có bảng | Bấm **Create / Reset Database** |
| ZAP chỉ thấy trang login | Chưa có phiên đăng nhập trong cây Sites | Làm lại mục 6.1: tự duyệt web qua proxy trước khi Active Scan |
| Report ZAP không có `evidence` | Chọn template JSON không kèm request/response | Chọn lại template có đầy đủ message, hoặc chấp nhận ít bằng chứng hơn |
| `Failed to connect to mysql server` | Container chưa lên, hoặc quét sai cổng | `docker compose ps`; xem lại `-p 3306` |
| Nmap không bắn gì trên 3306 | `root@'%'` không tồn tại hoặc tài khoản đã có mật khẩu | Kiểm tra `mysql.user` như mục 3, dựng lại lab bằng `down -v` |
| Nessus không thấy plugin CSDL | Template chưa bật thorough checks, hoặc plugin chưa tải xong | Thử template **Advanced Scan**; kiểm tra plugin set đã biên dịch xong |
| `Import failed: Input exceeds ...` | File lớn quá giới hạn 10 MiB hoặc quá 10.000 bản ghi | Chỉ quét một host lab, không export cả mạng |
| `Imported 0 records` | Sai `--format`, hoặc file export không phải định dạng đó (CSV/HTML) | Chọn đúng định dạng; Nessus phải là `.nessus`, ZAP phải là JSON |

Danh sách giới hạn của từng adapter (đọc gì, bỏ qua gì) nằm ở
[SCANNER_INPUTS.md](../SCANNER_INPUTS.md), mục "Giới hạn cụ thể".

## 11. Chưa nằm trong tài liệu này

- **Quét có xác thực (credentialed scan):** plugin local của Nessus cần tài khoản CSDL
  và đọc được cấu hình sâu hơn (quyền, mã hóa, log, `mysql_audit`). Đây là bước mở rộng
  tự nhiên để phủ đủ "quyền, mã hoá, logging" trong phạm vi đề tài.
- **MongoDB/Redis:** muốn thử quy tắc 81777/100634 thì thêm service `mongo`/`redis`
  không xác thực vào `docker-compose.yml`; chưa có trong file hiện tại.
- **Script NSE dò mật khẩu (`mysql-brute`, `pgsql-brute`):** cố ý không dùng, vì output
  chứa mật khẩu dạng rõ, sẽ đi vào báo cáo và có thể bị gửi lên Gemini.
- **Định dạng khác:** PDF/HTML/CSV chưa được nhận; `.db` của Nessus cũng không.

## 12. Nguồn tham khảo

- DVWA và cách chạy bằng compose: <https://github.com/digininja/DVWA>
- Nmap: <https://nmap.org/book/output-formats-xml-output.html>,
  <https://nmap.org/nsedoc/scripts/mysql-empty-password.html>
- sqlmap: <https://github.com/sqlmapproject/sqlmap/wiki/Usage>
- ZAP container: <https://www.zaproxy.org/docs/docker/full-scan/>
- Nessus Essentials: <https://www.tenable.com/products/nessus/nessus-essentials>
- Plugin 10481, 10483: <https://www.tenable.com/plugins/nessus/10481>,
  <https://www.tenable.com/plugins/nessus/10483>
- Định dạng file export của Nessus: <https://developer.tenable.com/docs/export-file-formats>
