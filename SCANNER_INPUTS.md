# Đọc output của công cụ kiểm thử

Các adapter được thêm từ bản 0.5 (`findings.json` ghi `parser_version` 0.5.0) và vẫn
được dùng ở bản 0.10 cho mọi chế độ báo cáo lẫn web UI.

Mục tiêu: đọc file kết quả đã xuất, lấy đúng từng bản ghi và bằng chứng, chuẩn hóa
để kiểm tra trước khi dùng AI. Bước chuẩn hóa không cần API, model embedding hay kho
OWASP. Project không chạy scanner, không truy cập mục tiêu và không sửa hệ thống được
quét.

## Các định dạng đã có adapter

| Tool | File nhận vào | `--format` | Phạm vi đọc |
|---|---|---|---|
| ZAP | Traditional JSON / JSON with Requests and Responses | `zap` | site → alerts → instances; evidence và HTTP response |
| Burp Suite | Export issues XML, root issues | `burp` | issue, severity/confidence, vị trí, issueDetail, HTTP response; giải mã Base64 |
| Nuclei | JSONL, một finding trên mỗi dòng | `nuclei` | template-id, info, matched-at/host, response, extracted-results |
| sqlmap | Log text có khối kết quả injection point hoàn chỉnh | `sqlmap-log` | Parameter, Type, Title, Payload; từng tham số |
| Nessus | .nessus XML, root NessusClientData_v2 | `nessus` | ReportHost/ReportItem, mức độ, plugin_output, CVE/CVSS nếu có |
| Nmap | XML -oX, root nmaprun | `nmap` | Cổng open/open-filtered, service, port scripts và host scripts |

Các adapter hiện đã được kiểm tra bằng fixture tự tạo dựa trên cấu trúc tài liệu;
**chưa xác nhận tương thích bằng file export thật của người dùng**. Không tuyên bố
hỗ trợ mọi phiên bản, template, biến thể định dạng hoặc extension của các tool.

## Chạy ngay với file mẫu

Từ thư mục project:

```powershell
python scripts/normalize_scan.py --input tests/fixtures/scanners/zap.json --format zap --output data/processed/demo-imports/zap
python scripts/normalize_scan.py --input tests/fixtures/scanners/burp.xml --format burp --output data/processed/demo-imports/burp
python scripts/normalize_scan.py --input tests/fixtures/scanners/nuclei.jsonl --format nuclei --output data/processed/demo-imports/nuclei
python scripts/normalize_scan.py --input tests/fixtures/scanners/sqlmap.log --format sqlmap-log --output data/processed/demo-imports/sqlmap
python scripts/normalize_scan.py --input tests/fixtures/scanners/nessus.nessus --format nessus --output data/processed/demo-imports/nessus
python scripts/normalize_scan.py --input tests/fixtures/scanners/nmap.xml --format nmap --output data/processed/demo-imports/nmap
```

Các file trong tests/fixtures/scanners là giả lập, không phải bằng chứng quét thật.
Các địa chỉ example.test và 192.0.2.10 chỉ nằm trong dữ liệu mẫu.
Mỗi lệnh sinh `findings.json` và `import-summary.md`, hoàn toàn local, không gọi AI.

Muốn **file thật** thay vì file mẫu: dựng lab trong `lab/` rồi quét bằng Nmap, sqlmap,
ZAP và Nessus Essentials theo [docs/lab-quet-csdl.md](docs/lab-quet-csdl.md). Tài liệu đó
cũng ghi cách kiểm tra file đã vào đúng đường và mẫu biên bản quét.

Với file thật, thay đường dẫn `--input`, chọn đúng `--format` và thư mục output riêng.
Giữ file gốc bên cạnh bản chuẩn hóa để kiểm tra lại. Mỗi lần nhập ghi đè output
trong thư mục được chọn; không ghi đè input. Không nạp output scanner vào corpus
OWASP hoặc chia nó theo 800 ký tự.

## Đầu ra chung

Một finding có các trường:

| Trường | Ý nghĩa |
|---|---|
| id | ID nội bộ trong file import |
| title | Tên lỗi/quan sát từ tool |
| kind | scanner_alert hoặc observation |
| tool | Công cụ nguồn |
| severity | Mức độ do tool cung cấp; không có thì unknown |
| cwe | CWE rõ ràng, duy nhất; thiếu hoặc nhiều mã thì unknown (danh sách nằm ở details.cwes) |
| location | URL hoặc host/port; không tự đoán vị trí chưa biết |
| evidence | Các mẩu thông tin được tool báo làm căn cứ hoặc phản hồi quan sát được |
| source_ref | Đường dẫn logic hoặc số dòng trong file gốc, không phải XPath chạy trực tiếp |
| details | Confidence, rule/plugin ID, CWE/CVE, request/payload, solution của tool và dữ liệu gốc tùy adapter |

`import_metadata` ghi SHA-256 file đầu vào, định dạng và phiên bản parser.
Việc đọc lại findings.json giữ nguyên tool/source_ref/details của từng finding.
`import-summary.md` cho biết bản ghi nào thiếu evidence/CWE; số mục evidence
không phải điểm độ tin cậy. Chuẩn hóa không xác nhận true positive/false positive.

### Không đánh đồng các loại dữ liệu

- Payload/request là dữ liệu gửi đi, giữ ở details; không tự coi là bằng chứng phản hồi.
- ZAP response và Burp issueDetail/response có thể cung cấp thông tin dù evidence riêng không có.
- Nuclei response/extracted-results được giữ; matcher-status=false bị bỏ qua.
- Lời khuyên của tool nằm ở details.scanner_solution, không trở thành nguồn OWASP.
- Cổng/dịch vụ Nmap được đánh dấu observation. Chỉ output NSE khớp một quy tắc trong
  `src/rag/data/scanner-rules.json` mới sinh thêm finding riêng (xem dưới).
- Nessus severity=0 được đánh dấu observation. Severity là mức tool báo, không phải project tính lại.
- Không suy luận CWE theo tên finding. CWE không có sẵn trong output chỉ đến từ quy
  tắc ghi rõ: khối classic SQLi của sqlmap → CWE-89 (quy tắc adapter), và các quy
  tắc cho kiểm tra CSDL của Nessus/Nmap trong `src/rag/data/scanner-rules.json`. Quy
  tắc chỉ áp dụng khi tool không ghi CWE, và được ghi ở details.scanner_rule và
  details.cwe_mapping.
- Có nhiều CWE thì giữ toàn bộ ở details.cwes và để trường cwe là unknown. Cổng Top 10
  xét cả danh sách: finding chỉ được gợi ý khi mọi CWE cùng thuộc một nhóm.
- Không gộp trùng giữa các tool hoặc các lần quét trong bản này; ID nội bộ chỉ duy nhất trong một import.

## Giới hạn cụ thể

- ZAP: chưa đọc SARIF, HTML, PDF hoặc JSON API khác cấu trúc traditional.
  Diagnostics/automation sections không được chuyển thành finding.
- Burp: đọc issue XML, không đọc project .burp hoặc XML HTTP history có root items.
  Hỗ trợ CWE dạng thẻ cwe hoặc mã CWE trong HTML classification. Issue Burp thật
  thường liệt kê nhiều CWE (ví dụ SQL injection: CWE-89, CWE-94, CWE-116). Cả ba
  thuộc A05:2025 nên finding vẫn được gợi ý; danh sách trải trên nhiều nhóm thì bị
  chặn. Event OAST/infiltrator
  và trường phụ vẫn có thể được giữ trong raw_xml, chưa diễn giải thành evidence riêng.
  Base64 lỗi bị từ chối; byte HTTP không phải UTF-8 được hiển thị bằng replacement
  character, bản Base64 gốc vẫn nằm trong raw_xml để khôi phục khi cần.
- Nuclei: JSONL findings, chưa đọc JSON array, SARIF, console màu hoặc statistics JSONL.
  Chưa tự đánh giá matcher/template có chính xác hay không.
- sqlmap: dòng `back-end DBMS` được ghi vào `details.dbms` và dùng làm engine trong khung
  suy luận CSDL; không sinh CWE, mức độ hay vị trí từ dòng này. Adapter đọc classic SQLi
  log, chưa đọc --report-json/API JSON, HAR, session.sqlite,
  database dump CSV hoặc chế độ LDAP/XPath/NoSQL/GraphQL. Dòng heuristic/might be
  injectable không được chấp nhận là kết quả cuối. Log phải riêng một target/lần
  chạy, không nối nhiều log. Không tự đoán URL từ log; trường location ghi tham số
  và trạng thái chưa xác định URL. Có thể bổ sung URL đã biết trong JSON chuẩn hóa
  và ghi nguồn bổ sung trong details trước khi viết báo cáo.
- Nessus: .nessus v2, chưa đọc .db, CSV, HTML/PDF hoặc cấu trúc scanner khác. CWE lấy
  từ thẻ `<cwe>`. Phần lớn plugin không có thẻ này; 10 plugin CSDL được gán CWE theo
  quy tắc của dự án, khóa theo pluginID (danh sách trong README, mục "Quy tắc CWE cho
  kiểm tra CSDL").
- Nmap: chỉ XML, không đọc normal text/grepable. Cổng closed/filtered không tạo
  finding; port/host scripts được giữ. Không suy luận mức độ. CWE chỉ được gán khi
  script và output khớp quy tắc: `mysql-empty-password` (dòng `... account has empty
  password`) và `ms-sql-empty-password` (dòng `sa:<empty> => ...`), mức độ `unknown`.
- Giới hạn import: 10 MiB và 10000 bản ghi/file. Chế độ `gemini`, `owasp` và web UI
  nhận tối đa 100 bản ghi mỗi báo cáo.
- XML cho phép internal DTD khai báo element như Burp, nhưng chặn entity/external DTD.
- File malformed/sai định dạng báo lỗi, không trả giả một kết quả sạch. Không có
  findings chỉ có nghĩa adapter không nhận bản ghi phù hợp từ input đó, không kết
  luận an toàn hoặc scan đã hoàn thành thành công.

## Dùng với báo cáo khi cần

Hiện có thể đưa findings.json vào nhánh báo cáo đã có:

```powershell
python scripts/generate_report.py --input data/processed/demo-imports/zap/findings.json --format normalized --mode demo --output data/reports/import-demo
```

Hoặc truyền file native cùng --format tương ứng. Chế độ demo dùng thẻ đã duyệt
theo luật, không có AI. Chế độ `owasp` và web UI dùng kho OWASP Cheat Sheet Series
và gửi một phần dữ liệu lên Gemini; xem README, mục "Dữ liệu gửi lên Gemini". Web UI
tự nhận diện định dạng; CLI cần `--format`.

## Nguồn cấu trúc tham khảo

- ZAP: https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/
- Burp: https://portswigger.net/burp/documentation/desktop/running-scans/reporting/report-settings
- Nuclei: https://docs.projectdiscovery.io/opensource/nuclei/running
- Nuclei output model: https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/pkg/output
- sqlmap: https://github.com/sqlmapproject/sqlmap/wiki/Usage
- Nessus: https://developer.tenable.com/docs/export-file-formats
- Nmap: https://nmap.org/book/output-formats-xml-output.html
