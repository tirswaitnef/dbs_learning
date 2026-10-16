# AI sinh báo cáo kiểm thử và gợi ý sửa theo OWASP

Package `owasp-report-rag` · phiên bản **0.12.0** · giao diện web: **AuditNote**.
Project học RAG viết tay từng bước, không dùng LangChain.

Project đọc **file kết quả đã xuất** từ công cụ kiểm thử (OWASP ZAP, Burp Suite,
Nuclei, sqlmap, Nessus, Nmap hoặc JSON chuẩn hóa của project), giữ nguyên bằng
chứng, phân loại theo **OWASP Top 10:2025** bằng bảng ánh xạ CWE, rồi sinh báo cáo
**Markdown, JSON và PDF tiếng Việt**.

- Gợi ý khắc phục chỉ lấy từ nguồn OWASP: 2 thẻ đã duyệt trong `cards.json`, hoặc
  đoạn **trích nguyên văn** từ OWASP Cheat Sheet Series. AI chỉ được **chọn ID**
  nguồn, không được tự viết cách sửa.
- Ở chế độ đầy đủ, Gemini viết thêm phần diễn giải tiếng Việt. Mỗi ý phải trích
  nguyên văn từ dữ liệu đầu vào và qua một lượt AI rà soát.

> Project không chạy scanner, không truy cập hệ thống mục tiêu và không xác minh lỗ
> hổng. Báo cáo sinh ra là bản nháp, cần người có chuyên môn kiểm tra trước khi dùng.

## Ba chế độ tạo báo cáo

| Chế độ | Chạy bằng | Cần thêm | Gọi Gemini | Nguồn khắc phục |
|---|---|---|---|---|
| `demo` | `scripts/demo.py`, `generate_report.py --mode demo`, `web.py --demo` | Chỉ `reportlab` | Không | 2 thẻ trong `data/raw/owasp/cards.json` (SQLi, XSS), ghép theo CWE |
| `gemini` (nhánh thẻ) | `generate_report.py --mode gemini` | Index E5 của thẻ (`ingest.py`), API key | 1 lần chọn thẻ mỗi báo cáo, cộng 2 lần diễn giải mỗi bản ghi | Thẻ đã duyệt; Gemini chọn ID thẻ |
| `owasp` (luồng chính) | `web.py`, `generate_report.py --mode owasp` | Vector store E5 của Cheat Sheet Series, API key | Nhiều lần, xem [Dữ liệu gửi lên Gemini](#dữ-liệu-gửi-lên-gemini) | Trích nguyên văn Cheat Sheet Series; Gemini chọn đoạn và viết diễn giải |

Cả ba chế độ dùng chung parser, cổng phạm vi Top 10:2025, khung suy luận CSDL và bộ
dựng báo cáo, và luôn sinh đủ `report.json`, `report.md`, `report.pdf`. Hai chế độ
`gemini` và `owasp` đều sinh diễn giải AI theo từng bản ghi; chế độ `demo` thì không
gọi AI nên phần văn bản đặc thù do code sinh.

## Chạy thử nhanh, không cần AI

Yêu cầu Python 3.11 trở lên (khuyến nghị 3.12). Mở PowerShell tại thư mục gốc của
repo (thư mục có `pyproject.toml`):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe scripts/demo.py
```

Linux/macOS: `python3 -m venv .venv`, rồi dùng `.venv/bin/python` thay cho
`.\.venv\Scripts\python.exe`.

`pip install -e .` chỉ cài `reportlab` (cần để xuất PDF). Demo không gọi mạng, không
đọc `.env`, không dùng AI hay embedding: code chỉ ghép CWE với 2 thẻ có sẵn. Kết quả
nằm ở `data/reports/demo/`. File mẫu `data/raw/scans/example.json` có 3 finding giả lập:

| Finding | Kết quả dự kiến |
|---|---|
| SQL Injection có bằng chứng giả lập | Có hướng dẫn OWASP kèm mục và link |
| XSS không có bằng chứng | Không đưa gợi ý sửa |
| Finding chưa phân loại (CWE `unknown`) | Không phân loại Top 10, không gợi ý |

Chỉ chuẩn hóa output scanner (không sinh báo cáo, chỉ cần thư viện chuẩn Python):

```powershell
python scripts/normalize_scan.py --input tests/fixtures/scanners/zap.json --format zap
```

Kết quả: `data/processed/scan-import/findings.json` và `import-summary.md`.
Chi tiết từng định dạng: [SCANNER_INPUTS.md](SCANNER_INPUTS.md).

Mở giao diện web để thử ngay, không cần API key: `pip install -e .` ở trên là đủ.

```powershell
.\.venv\Scripts\python.exe scripts\web.py --demo
```

Trình duyệt tự mở `http://127.0.0.1:8765`; kéo thả một file trong
`tests/fixtures/scanners/` để xem luồng upload → báo cáo → tải PDF. Chế độ `--demo`
ghép 2 thẻ có sẵn nên finding SQLi/XSS có gợi ý, còn finding CSDL sẽ ghi "chưa có
hướng dẫn". Muốn bản đầy đủ (AI + Cheat Sheet Series) thì xem
[Web UI (luồng chính)](#web-ui-luồng-chính).

## Cài đặt đầy đủ

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
Copy-Item .env.example .env
```

`requirements.txt` cài project kèm nhóm `ai,pdf,dev` trong `pyproject.toml`
(sentence-transformers, numpy, google-genai, python-dotenv, pypdf, pytest).
sentence-transformers kéo theo PyTorch nên dung lượng lớn. Nếu chỉ cần retrieval E5,
không cần Gemini: `pip install -e ".[retrieval]"`.

Nếu PowerShell chặn `Activate.ps1`, cứ gọi thẳng `.\.venv\Scripts\python.exe` như
trên. Các lệnh `python ...` bên dưới đều hiểu là Python trong venv.

Project chưa có lockfile. Sau khi cài và chạy ổn, nên lưu
`python -m pip freeze > requirements-lock.txt` để tái lập thí nghiệm.

Điền `.env`:

1. `GEMINI_API_KEY`: lấy tại https://aistudio.google.com/apikey.
2. `GEMINI_CHAT_MODEL`: mã model khả dụng trong tài khoản, có hỗ trợ structured
   output (xem https://ai.google.dev/gemini-api/docs/models). Biến này cố ý để trống
   để không phụ thuộc vào một alias có thể đổi giữa các lần thí nghiệm.
3. Giữ `EMBED_MODEL=intfloat/multilingual-e5-small`; nên điền `EMBED_REVISION` bằng
   commit model đã dùng.

Không commit `.env`, cache model, vector store, file scan thật hay báo cáo thật.
Các thư mục tương ứng đã có trong `.gitignore`.

## Web UI (luồng chính)

### Chuẩn bị một lần

1. Cài đầy đủ và điền `.env` như trên.
2. Tạo vector store cho OWASP Cheat Sheet Series. Repo đã có sẵn bản sao trong
   `data/raw/owasp/official/CheatSheetSeries-master/`. Lần đầu cần internet để tải
   model E5 từ Hugging Face:

```powershell
python scripts/ingest_documents.py --raw data/raw/owasp/official/CheatSheetSeries-master/cheatsheets --output data/processed/owasp-official
```

Web UI chạy E5 ở chế độ offline (`local_files_only`), nên phải chạy bước này trước
để model có sẵn trong cache. Khi đổi `EMBED_MODEL`, `EMBED_REVISION`,
`RAG_CHUNK_SIZE` hoặc `RAG_CHUNK_OVERLAP`, hoặc khi sửa file trong corpus, phải
ingest lại; store cũ sẽ bị từ chối. Nếu gặp lỗi `Embedding input exceeds model
limit`, giảm `RAG_CHUNK_SIZE` rồi ingest lại.

### Khởi động

```powershell
python scripts/web.py          # mở http://127.0.0.1:8765
python scripts/web.py --demo   # thử giao diện, không AI, dùng 2 thẻ demo
```

Trên Windows có thể bấm đúp `start-web.bat` (cần `.venv` đã cài). Tùy chọn:
`--port 8766`, `--no-browser`. Trang web báo ngay nếu thiếu API key, model, vector
store hoặc corpus.

### Cách dùng

- Kéo thả hoặc đính kèm file kết quả (tối đa 10 MB và 100 phát hiện). Chọn định
  dạng hoặc để tự nhận diện. Có thể điền ứng dụng, khách hàng, người lập, thời gian
  kiểm thử và phân loại tài liệu cho trang bìa.
- Mỗi file là một mục trong lịch sử. Server xử lý tuần tự từng file, hàng đợi tối đa
  4 file. Khi xong, tải PDF hoặc JSON.
- Trạng thái `partial`: PDF đã có nhưng một phần AI (chọn nguồn, diễn giải hoặc tổng
  quan) bị lỗi hay bị từ chối; lý do ghi trong báo cáo.
- Dữ liệu lưu ở `data/web/jobs/<id>/` (`input.scan`, `job.json`,
  `output/report.{json,md,pdf}`). **Thư mục này có thể chứa dữ liệu khách hàng.**
  Nó đã được `.gitignore`; hãy tự xóa khi không cần nữa. Ghi chú gõ trong ô chat chỉ
  lưu trong `job.json`, không vào báo cáo và không gửi lên Gemini.

Server chỉ nghe trên `127.0.0.1` và chỉ nhận Host `127.0.0.1:<port>` hoặc
`localhost:<port>` (chống DNS rebinding). Server kiểm tra `Origin` và
`Sec-Fetch-Site`, dùng cookie phiên HttpOnly + SameSite=Strict, token chống CSRF cho
request ghi, CSP chặt và không tải tài nguyên ngoài. Server không được thiết kế để
chạy công khai hay cho nhiều người dùng.

### Luồng xử lý của chế độ `owasp`

1. Parser đọc file thành danh sách finding, giữ nguyên mức độ, CWE và bằng chứng.
2. Code tra bảng CWE để xếp nhóm Top 10:2025. Chỉ finding có **CWE nằm trong bảng**
   (nếu có nhiều CWE thì tất cả phải cùng một nhóm), **có bằng chứng** và **không
   phải quan sát** mới được tìm hướng dẫn.
3. E5 truy xuất các chunk Cheat Sheet (lấy ít nhất 12, lọc theo `RAG_MIN_SCORE`),
   rồi mở rộng thành nguyên đoạn Markdown kèm tiêu đề mục. Code bỏ khối code, danh
   sách tham khảo, mục ví dụ và kịch bản tấn công. Với CWE-89/CWE-79, các sheet về
   SQLi/XSS được xếp trước; với finding nhận CWE từ
   [quy tắc CSDL](#quy-tắc-cwe-cho-kiểm-tra-csdl), sheet của quy tắc được xếp trước.
4. Gemini chọn tối đa 3 ID đoạn. Code kiểm tra ID rồi chép nguyên văn đoạn đó (tiếng
   Anh), gắn nhãn "chưa duyệt thủ công".
5. Với **mọi** finding, Gemini viết diễn giải (tối đa 3 ý mỗi phần). Mỗi ý phải kèm
   trích dẫn nguyên văn từ nguồn đầu vào. Một lượt gọi Gemini thứ hai (cùng model)
   rà soát; ý nào không qua thì không được in.
6. Gemini viết tổng quan báo cáo theo cùng cơ chế. Sau đó code dựng JSON, Markdown
   và PDF.

## Dữ liệu gửi lên Gemini

Đọc kỹ phần này trước khi dùng với dữ liệu thật.

| Lệnh | Số lần gọi | Nội dung gửi | Không gửi |
|---|---|---|---|
| `generate_report.py --mode gemini` | 1 mỗi báo cáo | ID, tiêu đề, CWE và cờ có/không có bằng chứng của từng finding; nội dung thẻ ứng viên | Vị trí/URL, mức độ, bằng chứng, request/response, `details` |
| `--mode owasp` và web UI | Tối đa 1 + 2 cho mỗi finding, cộng 2 cho tổng quan | Xem danh sách bên dưới | File gốc, các trường raw (`raw_xml`, `raw_result`, `raw_instance`...), bằng chứng từ mục thứ 9 trở đi, request thứ 2 trở đi, ghi chú web |
| `answer.py` | 1 mỗi câu hỏi | Câu hỏi và các chunk context (text, đường dẫn nguồn, metadata), tối đa 12.000 ký tự JSON | Phần còn lại của corpus |

Chi tiết với `--mode owasp` và web UI:

- **Chọn nguồn** (chỉ finding đủ điều kiện): tiêu đề, CWE, nhóm Top 10 và các đoạn
  OWASP ứng viên.
- **Diễn giải và rà soát** (mọi finding, 2 lần gọi): tiêu đề, CWE, mức độ, loại bản
  ghi, **vị trí/URL**, số mục bằng chứng, mô tả của công cụ (tối đa 2.400 ký tự), tên
  công cụ, phương thức HTTP, tham số, confidence, **request HTTP đầu tiên** (tối đa
  2.400 ký tự) và **tối đa 8 mục bằng chứng, mỗi mục tối đa 2.400 ký tự**. Bằng chứng
  có thể là HTTP response (ZAP, Burp, Nuclei), plugin output (Nessus), NSE output
  (Nmap) hoặc khối kết quả của sqlmap.
- **Tổng quan** (2 lần gọi): mỗi finding gồm ID, tiêu đề (tối đa 200 ký tự), CWE,
  mức độ, vị trí (tối đa 240 ký tự) và 2 mục bằng chứng đầu (tối đa 800 ký tự), kèm
  bảng thống kê.

Trước khi gửi, `analysis.redact()` dùng regex để che: các dòng header
`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`; giá trị
của các khóa `password`, `passwd`, `pwd`, `api_key`, `access_token`,
`refresh_token`, `secret`, `token`; thông tin đăng nhập dạng `https://user:pass@`.
Regex **không** che session ID mang tên khác, JWT không gắn tên khóa, dữ liệu cá
nhân, hostname/IP nội bộ hay dữ liệu nghiệp vụ trong response body.

Với gói Gemini API miễn phí, điều khoản của Google cho phép dùng nội dung gửi lên để
cải thiện sản phẩm và cho người duyệt đọc. Google cũng khuyến cáo không gửi dữ liệu
nhạy cảm hoặc bảo mật lên gói này. Gói trả phí thì không dùng prompt để cải thiện sản
phẩm. Xem [Gemini API Additional Terms](https://ai.google.dev/gemini-api/terms).

**Với kết quả pentest của khách hàng:** chỉ dùng `--mode owasp` hoặc web UI khi hợp
đồng/NDA cho phép, và với gói dịch vụ phù hợp. Nếu không, dùng chế độ `demo`,
`--mode gemini` (không gửi bằng chứng) hoặc làm sạch dữ liệu trước.

Embedding E5 chạy hoàn toàn trên máy; mạng chỉ dùng để tải model lần đầu.

## Dùng bằng dòng lệnh

```powershell
# Báo cáo không AI từ file ZAP mẫu
python scripts/generate_report.py --input data/raw/scans/zap-example.json --format zap --mode demo --output data/reports/zap-demo

# Luồng chính (cần store data/processed/owasp-official và .env)
python scripts/generate_report.py --input <file> --format <định dạng> --mode owasp --output data/reports/<tên>

# Nhánh thẻ + Gemini
python scripts/ingest.py
python scripts/ask.py "Cách phòng SQL Injection" --cwe CWE-89
python scripts/generate_report.py --input data/raw/scans/example.json --mode gemini --output data/reports/ai-example

# Xuất lại PDF từ report.json có sẵn, không gọi AI
python scripts/export_pdf.py --input data/reports/demo/report.json --output data/reports/demo/report-copy.pdf
python scripts/export_template_pdf.py --input data/reports/demo/report.json --client "Tên khách hàng" --tester "Người thực hiện"
```

- `--format`: `normalized` (mặc định), `zap`, `burp`, `nuclei`, `sqlmap-log`,
  `nessus`, `nmap`. CLI không tự nhận diện định dạng; web UI thì có.
- `--mode owasp --offline-embeddings`: chỉ dùng model E5 đã có trong cache.
  `--raw`/`--store` để đổi vị trí corpus và vector store.
- Nếu `--mode gemini` gặp lỗi API hoặc AI trả ID không hợp lệ, lệnh dừng, không ghi
  báo cáo và không tự chuyển sang demo. Với `--mode owasp`, báo cáo vẫn được ghi; phần
  AI lỗi được đánh dấu trong `generation_status` và `ai_analysis.status`, mục 7 của
  PDF liệt kê trạng thái AI của từng bản ghi.
- Giới hạn nhập: 10 MiB và 10.000 bản ghi mỗi file. Chế độ `gemini` và `owasp` nhận
  tối đa 100 finding mỗi báo cáo.
- `export_template_pdf.py` dựng PDF theo mẫu 7 phần, gắn nhãn nguồn cho từng nội
  dung (`[Đầu vào]`, `[Quy tắc]`, `[AI đã rà soát]`, `[OWASP]`) và ẩn các ý AI không
  qua bộ lọc chính tả tiếng Việt.

## Đầu vào

Phạm vi đọc và giới hạn của từng adapter nằm trong [SCANNER_INPUTS.md](SCANNER_INPUTS.md).
Các adapter mới được kiểm thử bằng fixture giả lập, chưa xác nhận với file export thật.
Muốn có file export thật để chạy demo, kiểm chứng quy tắc CWE và gán nhãn: dựng lab
trong `lab/` rồi quét theo [docs/lab-quet-csdl.md](docs/lab-quet-csdl.md); số file và
kiểu tình huống cần có, và cách có một đầu vào "thực tế" mà vẫn hợp pháp (VPS của chính
bạn, VM của khoa có giấy phép, phòng lab được phép tấn công), nằm ở
[docs/ke-hoach-du-lieu.md](docs/ke-hoach-du-lieu.md).

JSON chuẩn hóa của project:

```json
{
  "schema_version": 1,
  "tool": "Tên công cụ và phiên bản",
  "report_metadata": {
    "application": "Ứng dụng được kiểm thử",
    "client": "Khách hàng",
    "prepared_by": "Người lập báo cáo",
    "assessment_period": "Thời gian kiểm thử",
    "classification": "Nội bộ",
    "roles": "Vai trò / tài khoản đã kiểm thử",
    "excluded_areas": "Ngoài phạm vi"
  },
  "findings": [
    {
      "id": "F-001",
      "title": "SQL Injection",
      "cwe": "CWE-89",
      "severity": "high",
      "location": "https://example.test/search?q=...",
      "evidence": ["Bằng chứng thực sự có trong kết quả công cụ"],
      "kind": "scanner_alert",
      "details": {}
    }
  ]
}
```

- Bắt buộc: `schema_version`, `tool`, và `id`, `title` của từng finding; `id` phải
  duy nhất. `severity` và `location` mặc định là `unknown`. `kind` là
  `scanner_alert` hoặc `observation`.
- `report_metadata` là tùy chọn và chỉ nhận các khóa trên (tối đa 180 ký tự;
  `classification` tối đa 80; `roles`, `excluded_areas` tối đa 1.000). Web UI cho
  nhập 5 khóa đầu; giá trị không rỗng nhập trên web sẽ ghi đè giá trị trong file.
- Không tự đặt bằng chứng hoặc CWE khi công cụ không có căn cứ. Khi không biết CWE,
  để `unknown` hoặc bỏ trường này; hệ thống không đoán CWE theo tên lỗi.
- Công cụ ghi nhiều CWE: để `cwe` là `unknown` và đặt cả danh sách vào
  `details.cwes`, ví dụ `["CWE-89", "CWE-94"]`. `normalize_scan.py` xuất đúng dạng này.

## Phạm vi OWASP Top 10:2025 và các rào chắn

Bảng `src/rag/data/top10-2025.json` lấy từ danh sách CWE được ánh xạ (List of Mapped
CWEs) trong repo [OWASP/Top10](https://github.com/OWASP/Top10), commit `3a31f353`,
lấy ngày 2026-10-02, giấy phép CC BY 3.0. Code tra bảng chính xác theo mã CWE; không
dùng AI, tên lỗi hay độ tương đồng để phân loại.

Một finding chỉ được gắn hướng dẫn khắc phục khi thỏa cả ba điều kiện:

- **CWE nằm trong bảng.** Nếu công cụ gắn nhiều CWE cho một finding (Burp gắn
  CWE-89, CWE-94, CWE-116 cho SQL injection), thì mọi CWE phải cùng thuộc một nhóm Top
  10; code không chọn hay bỏ bớt CWE nào. Có CWE ngoài bảng, hoặc các CWE thuộc nhiều
  nhóm khác nhau, thì finding bị chặn.
- **Có bằng chứng** đính kèm.
- **Không phải quan sát** (cổng/dịch vụ của Nmap, Nessus severity 0).

Các finding khác vẫn có trong báo cáo, kèm lý do (`scope_blocked`,
`missing_evidence`, `no_supported_guidance`...).

Các rào chắn khác:

- Parser không đoán CWE theo tên lỗi. Khi công cụ không ghi CWE, CWE chỉ có thể đến
  từ quy tắc viết tay, khóa theo định danh ổn định của công cụ: khối SQLi của sqlmap
  được gán CWE-89, và [bảng quy tắc cho kiểm tra CSDL](#quy-tắc-cwe-cho-kiểm-tra-csdl).
  Báo cáo ghi rõ CWE nào do quy tắc gán. Payload/request không được tính là bằng
  chứng. Mức độ giữ nguyên như công cụ báo. *(có test)*
- AI chỉ được trả ID nằm trong danh sách ứng viên của đúng finding đó. ID lạ, ID
  trùng, thiếu finding hoặc có trường văn bản tự do đều bị từ chối. *(có test cho cả
  nhánh thẻ, `validators.py`, và bước chọn đoạn của chế độ `owasp`,
  `official_report.py`, với model giả)*
- Văn bản khắc phục và URL do code lấy từ nguồn, không do AI viết. Thẻ phải dùng URL
  HTTPS thuộc `owasp.org`. *(có test)*
- Diễn giải AI phải trích dẫn nguyên văn nguồn đầu vào có ID, không được chứa khuyến
  nghị, và phải qua lượt rà soát riêng. Đầu ra bị từ chối không bao giờ được in.
  *(chưa có test, `analysis.py`)*
- Báo cáo ghi SHA-256 của file đầu vào và kho hướng dẫn, tên model và thời điểm.
  Vector store ghi hash corpus/chunk/vector và cấu hình; nếu lệch thì bắt ingest lại.
  *(có test cho vector store)*

Các rào chắn này giảm việc bịa nội dung nhưng không bảo đảm chọn đúng hướng dẫn. Xem
[Giới hạn đã biết](#giới-hạn-đã-biết).

## Quy tắc CWE cho kiểm tra CSDL

Nessus và Nmap thường báo lỗi cấu hình CSDL mà không kèm CWE. Ví dụ, trang plugin
10481 (MySQL có tài khoản không mật khẩu) của Tenable không ghi CWE nào. Không có CWE
thì finding bị chặn ở cổng Top 10, nên báo cáo kiểm thử CSDL sẽ không có gợi ý cho
chính các lỗi CSDL phổ biến nhất.

`src/rag/data/scanner-rules.json` bổ sung CWE cho các kiểm tra này, theo đúng kiểu quy
tắc sqlmap → CWE-89:

- Khóa bằng định danh ổn định của công cụ: `pluginID` của Nessus, hoặc tên script NSE
  của Nmap cộng một mẫu output lấy từ mã nguồn script. Không so khớp theo tên hay mô
  tả.
- Chỉ áp dụng khi công cụ không ghi CWE. CWE do công cụ ghi luôn được giữ.
- Finding ghi `details.scanner_rule` và `details.cwe_mapping`. Báo cáo hiển thị "gán
  theo quy tắc ánh xạ của dự án"; PDF theo mẫu gắn nhãn `[Quy tắc]` thay cho
  `[Đầu vào]`.
- Với Nmap, bản ghi cổng/dịch vụ vẫn là quan sát. Mỗi script có output khớp quy tắc
  sinh thêm một finding riêng, mức độ `unknown` vì Nmap không chấm mức độ.
- Ở chế độ `owasp`, Cheat Sheet của quy tắc được xếp trước trong các kết quả truy xuất
  (giống cách sheet SQLi được ưu tiên cho CWE-89). Việc ưu tiên chỉ sắp xếp lại, không
  thêm sheet không được truy xuất. Ở chế độ thẻ, 2 thẻ có sẵn chỉ dành cho SQLi và XSS,
  nên các finding này nằm trong phạm vi nhưng ghi "chưa có hướng dẫn".

| Công cụ | Định danh | Kiểm tra | CWE | Nhóm |
|---|---|---|---|---|
| Nessus | 10481 | MySQL: tài khoản không mật khẩu | CWE-1393 | A07 |
| Nessus | 10483 | PostgreSQL: tài khoản mặc định không mật khẩu | CWE-1393 | A07 |
| Nessus | 10673 | SQL Server: tài khoản `sa` mặc định để trống mật khẩu | CWE-1393 | A07 |
| Nessus | 81777 | MongoDB không yêu cầu xác thực | CWE-306 | A07 |
| Nessus | 100634 | Redis không có mật khẩu | CWE-306 | A07 |
| Nessus | 57558, 63347, 55786, 64784, 73756 | MySQL, PostgreSQL, Oracle, SQL Server (2 plugin) hết hỗ trợ | CWE-1104 | A03 |
| Nmap | `mysql-empty-password` | Dòng `<tài khoản> account has empty password` | CWE-1393 | A07 |
| Nmap | `ms-sql-empty-password` | Dòng `sa:<empty> => ...` | CWE-1393 | A07 |

Mỗi dòng trong file JSON ghi lý do và nguồn: trang plugin của Tenable hoặc tài liệu và
mã nguồn NSE (ghim theo commit), định nghĩa CWE của MITRE, và trang Top 10:2025.
A03:2025 ghi rõ phần mềm "unsupported, or out of date" gồm cả DBMS; A07:2025 nêu việc
cho phép mật khẩu mặc định. Với MongoDB 5.0 trở lên, Tenable khuyên tự xác nhận lại kết
quả của plugin 81777.

Chưa có quy tắc, có chủ ý:

- Script NSE dò mật khẩu (`mysql-brute`, `pgsql-brute`...): output chứa mật khẩu dạng
  rõ, sẽ đi vào báo cáo và có thể bị gửi lên Gemini.
- `mongodb-databases`, `redis-info`: script có thể chạy kèm thông tin đăng nhập, nên
  output thành công không chứng minh dịch vụ thiếu xác thực.
- Các plugin khác trong họ Databases của Nessus (khoảng 680 plugin): chỉ thêm sau khi
  kiểm chứng từng plugin.

Thêm quy tắc: sửa file JSON rồi chạy test. `scanner_rules.validate` từ chối file khi
thiếu hoặc thừa trường, trùng ID hoặc plugin, CWE không nằm trong bảng Top 10, nguồn
không phải HTTPS, tên Cheat Sheet sai dạng, hoặc biểu thức output không hợp lệ. Test
còn kiểm tra mỗi quy tắc có nguồn từ công cụ, MITRE và OWASP, và Cheat Sheet có trong
kho đi kèm.

## Suy luận theo đầu vào

Mục tiêu: báo cáo phải bám dữ liệu của lần kiểm thử đó, không phải một bản mẫu điền
tên vào. Có hai cơ chế, cả hai đều chạy bằng code nên kiểm tra lại được.

### Khung suy luận CSDL (K1)

Trước khi gọi AI, `src/rag/db_scope.py` đọc chính bản ghi và trả về một khung: mức liên
quan CSDL, tầng, engine và kiểm soát đang có vấn đề. Nguồn dữ liệu của khung chỉ gồm
những thứ có trong đầu vào:

| Căn cứ | Ví dụ | Cho ra |
|---|---|---|
| Cổng/dịch vụ trong trường `location` | `...:3306/tcp` | engine MySQL/MariaDB, tầng máy chủ CSDL |
| `details.scanner_rule` (quy tắc trong `scanner-rules.json`) | `nessus-10481` | engine do quy tắc nêu; tầng máy chủ CSDL |
| `details.dbms` (dòng `back-end DBMS` của sqlmap) | `MySQL >= 5.0.12` | engine theo log |
| CWE do công cụ hoặc quy tắc cung cấp | `CWE-1393` | kiểm soát: xác thực / mật khẩu mặc định |

Không suy đoán từ tên lỗi hay mô tả. CWE không có trong bảng kiểm soát thì khung ghi
"chưa xác định", và quy tắc luôn thắng cổng khi hai thứ mâu thuẫn (plugin PostgreSQL
báo trên cổng 3306 vẫn là PostgreSQL, và cổng đó không được in ra như thể xác nhận).
Nhiều CWE chỉ cho ra một kiểm soát khi mọi CWE cùng một nhóm.

Khung này đi vào báo cáo ở hai chỗ: mục 2 (bảng đếm theo tầng, engine, kiểm soát) và
mục 4 của từng bản ghi. Nó cũng được gửi cho AI dưới mã nguồn `K1`, kèm câu "không do
AI suy đoán", và lượt rà soát thứ hai phải trả thêm cờ `database_specific`: chỉ đúng khi
mọi câu có nhắc tầng, engine hay kiểm soát CSDL đều khớp K1 và không tự thêm tầng hay
engine khác. Cờ này sai thì diễn giải bị từ chối, không in ra. *(có test cho cả hai
nhánh: khớp thì hiện, sai thì `rejected_output`)*

### Kiểm tra trùng lặp văn bản (`prose_check`)

`src/rag/report_variety.py` tách ba loại văn bản, vì chỉ một loại phải khác nhau giữa
các bản ghi:

- **văn bản AI** (`ai_analysis`): phải khác nhau → đây là thứ được đo;
- **câu do code sinh** (`analysis_vi` ở nhánh corpus): giống nhau là đúng thiết kế → chỉ
  đếm, không coi là lỗi;
- **bằng chứng và trích OWASP**: sao từ đầu vào/nguồn, giống nhau nghĩa là dữ liệu giống.

Kết quả nằm trong `report.json` ở khóa `prose_check` và in ra mục 2 của báo cáo: nhóm
bản ghi nào có diễn giải AI gần giống nhau (Jaccard theo tập từ, ngưỡng 0,7), hay lần
chạy này không có diễn giải AI để so. Khi cần so hai lần chạy, `compare_reports` trả về
bốn tỉ lệ riêng: văn bản AI, câu do code sinh, bằng chứng, để thấy phần nào giống nhau
và vì sao.

Đây là phép đo từ vựng, không phải đánh giá đúng/sai: nó chứng minh hai báo cáo không
phải bản sao của nhau, không chứng minh nội dung chính xác. Ngưỡng 0,7 chưa được hiệu
chỉnh trên dữ liệu gán nhãn.

## Kết quả đầu ra

- `report.json`: dữ liệu đầy đủ, gồm finding, phân loại Top 10, kết quả truy xuất,
  hướng dẫn, diễn giải AI kèm trích dẫn, trạng thái từng bước, hash và giới hạn.
- `report.md` và `report.pdf` gồm 7 phần: Tổng quan điều hành, Phạm vi và phương
  pháp, Tổng hợp theo OWASP, Chi tiết phát hiện, Xếp hạng rủi ro, Hướng dẫn khắc
  phục, Phụ lục. PDF nhúng font DejaVu để hiển thị tiếng Việt.
- Báo cáo được gắn nhãn "kiểm thử giả lập" khi trường `tool` của đầu vào chứa
  `synthetic` hoặc `demo only`.

## Cấu hình `.env`

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `GEMINI_API_KEY` | trống | Bắt buộc cho `gemini`, `owasp`, web UI và `answer.py` |
| `GEMINI_CHAT_MODEL` | trống | Mã model Gemini hỗ trợ structured output |
| `EMBED_MODEL` | `intfloat/multilingual-e5-small` | Model embedding; wrapper hiện viết riêng cho prefix `query:`/`passage:` của E5 |
| `EMBED_REVISION` | trống | Commit của model trên Hugging Face, để tái lập kết quả |
| `RAG_CHUNK_SIZE` / `RAG_CHUNK_OVERLAP` | 800 / 120 | Tính theo ký tự, không phải token; đổi thì phải ingest lại |
| `RAG_TOP_K` | 4 | Số kết quả truy xuất; chế độ `owasp` lấy ít nhất 12 |
| `RAG_MIN_SCORE` | 0.75 | Ngưỡng cosine thử nghiệm, không phải xác suất; áp cho nhánh thẻ và chế độ `owasp`, không áp cho `retrieve.py`/`answer.py` |

`.env` chỉ được đọc khi file tồn tại (cần `python-dotenv`). Chế độ `demo` và
`preview_chunks.py` không đọc `.env`.

## Cấu trúc thư mục

| Đường dẫn | Nội dung |
|---|---|
| `src/rag/parsers/` | Adapter: JSON chuẩn hóa và ZAP (`__init__.py`); Burp, Nuclei, sqlmap, Nessus, Nmap (`native.py`) |
| `src/rag/top10.py`, `src/rag/data/top10-2025.json` | Cổng phạm vi OWASP Top 10:2025 |
| `src/rag/scanner_rules.py`, `src/rag/data/scanner-rules.json` | Quy tắc CWE viết tay cho kiểm tra CSDL của Nessus/Nmap |
| `src/rag/db_scope.py`, `report_variety.py` | Khung suy luận CSDL (K1) và phép đo trùng lặp văn bản |
| `src/rag/retriever.py`, `vector_store.py`, `validators.py`, `llm.py` | Nhánh thẻ: truy xuất theo CWE + E5, Gemini chọn ID, kiểm tra kế hoạch |
| `src/rag/official_report.py` | Chế độ `owasp`: tách đoạn Cheat Sheet, chọn nguồn, dựng báo cáo |
| `src/rag/analysis.py` | Diễn giải AI, lượt rà soát, che dữ liệu nhạy cảm |
| `src/rag/report_builder.py`, `report_view.py` | Dựng báo cáo JSON/Markdown, phần trình bày dùng chung |
| `src/rag/pdf_report.py`, `template_report.py`, `fonts/` | PDF 7 phần, PDF theo mẫu, font tiếng Việt |
| `src/rag/web_server.py`, `src/rag/web/` | Web UI local |
| `src/rag/loader.py`, `chunker.py`, `embeddings.py`, `document_store.py`, `context.py`, `prompts.py`, `qa.py` | Corpus tài liệu, E5, vector store NumPy, hỏi đáp có trích dẫn (Tập 02–04) |
| `src/rag/config.py`, `schemas.py`, `pipeline.py` | Cấu hình, kiểu dữ liệu, điều phối chế độ `demo`/`gemini` |
| `scripts/` | Các lệnh CLI |
| `tests/`, `tests/fixtures/scanners/` | Unittest và 6 fixture scanner giả lập |
| `lab/` | Compose dựng lab quét: DVWA + hai CSDL cấu hình yếu |
| `data/raw/owasp/cards.json` | 2 thẻ hướng dẫn (SQLi, XSS) |
| `data/raw/owasp/official/CheatSheetSeries-master/` | Bản sao OWASP Cheat Sheet Series (CC BY-SA 4.0) |
| `data/raw/owasp/documents/` | 2 tài liệu minh họa tự viết cho Tập 02–04, không phải tài liệu OWASP |
| `data/raw/scans/` | 2 file scan mẫu; các file khác bị ignore |
| `data/processed/`, `data/reports/`, `data/web/` | Sinh tự động khi chạy, đã ignore |
| `docs/lo-trinh-hoc-rag.md` | Các bài học Tập 01–04 |
| `docs/lab-quet-csdl.md` | Dựng lab và quét để lấy dữ liệu đầu vào thật |
| `docs/ke-hoach-du-lieu.md` | Bao nhiêu file/kiểu đầu vào là đủ, cặp trước–sau, kế hoạch gán nhãn |

## Kiểm thử và CI

```powershell
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
# hoặc: python -m pytest -q
```

Nhóm `dev` gồm pytest và numpy. Thiếu numpy thì 9 test vector store bị SKIP; thiếu
`reportlab` thì các test sinh báo cáo lỗi, vì báo cáo luôn kèm PDF. Test không cần
sentence-transformers hay google-genai: E5 và Gemini đều được mock, không gọi mạng.

GitHub Actions (`.github/workflows/tests.yml`) chạy bộ test trên Ubuntu và Windows
với Python 3.11 và 3.14, sau đó chạy thử `demo.py` và hai lệnh xuất PDF.

Bộ test hiện có 112 test, phủ parser và quy tắc CWE, cổng Top 10 (kể cả finding nhiều
CWE), nhánh `demo`/`gemini` (có diễn giải AI với model giả), bước truy xuất và chọn
nguồn của chế độ `owasp` (retriever và model giả), khung suy luận CSDL, phép đo trùng
lặp văn bản, corpus và vector store, hỏi đáp có trích dẫn, và PDF theo mẫu. Quy trình
diễn giải AI được kiểm tra thêm bằng 6 đột biến cố ý: bỏ điều kiện cùng nhóm CWE, cho
cổng thắng quy tắc, so cả câu do code sinh, bỏ câu ràng buộc trong K1, bỏ cờ
`database_specific`, và bỏ nhánh tầng ứng dụng — cả 6 đều bị test phát hiện. **Chưa có
test tự động:** bước che dữ liệu trong `analysis.py` (phần regex), web server
(`web_server.py`), và bước ingest/E5 thật của chế độ `owasp`.

Test pass chỉ cho biết code chạy đúng với các trường hợp đã viết, không chứng minh
chất lượng gợi ý hay diễn giải của AI. Xem [VALIDATION.md](VALIDATION.md).

## Giới hạn đã biết

1. **Nhiều finding vẫn không có CWE dùng được.** Finding nhiều CWE giờ được xét nếu
   mọi CWE cùng một nhóm, đủ cho các issue Burp như SQLi, XSS, XPath injection. Nhưng
   trên 10 file Nessus công khai đã thử, chỉ 3/112 finding mức từ low trở lên đủ điều
   kiện: 95 finding không có CWE; các finding nhiều CWE thì gộp lỗi của nhiều nhóm
   (như "PHP Multiple Vulnerabilities"), hoặc kèm mã View/Category của MITRE như
   CWE-928, CWE-930, vốn bị MITRE cấm dùng để ánh xạ lỗ hổng. Quy tắc CSDL chỉ phủ
   12 kiểm tra (xem [mục trên](#quy-tắc-cwe-cho-kiểm-tra-csdl)).
2. **Chất lượng AI chưa được đánh giá.** Chưa có bộ finding gán nhãn để đo. Các lần
   chạy thật ghi trong [VALIDATION.md](VALIDATION.md) cho thấy: có diễn giải sai chính
   tả hoặc mất dấu vẫn qua lượt AI rà soát; hướng dẫn được chọn có lúc thuộc một
   framework cụ thể (.NET) hoặc chỉ mang tính giới thiệu; có một XSS điển hình không
   được gợi ý.
3. **`RAG_MIN_SCORE` gần như không lọc được với E5**, vì điểm cosine của E5 vốn tập
   trung trong khoảng 0,7–1,0 ([model card](https://huggingface.co/intfloat/multilingual-e5-small)).
   Trong các lần chạy thật, mọi ứng viên đều có điểm từ 0,843 đến 0,880, kể cả các
   sheet không liên quan. Cần hiệu chỉnh ngưỡng trên dữ liệu gán nhãn.
4. **Che dữ liệu bằng regex có giới hạn**, xem [Dữ liệu gửi lên Gemini](#dữ-liệu-gửi-lên-gemini).
5. **Khung CSDL phụ thuộc thứ có trong đầu vào.** Không có cổng, quy tắc hay CWE thì
   khung ghi "unrelated"/"chưa xác định" thay vì suy đoán, nên tin nhắn NSE bị đổi định
   dạng hoặc plugin không có trong bảng quy tắc sẽ không được gán tầng CSDL. Kiểm tra
   trùng lặp cũng chỉ so từ ngữ, chưa hiệu chỉnh ngưỡng trên dữ liệu gán nhãn.
6. **Gọi API tuần tự, không thử lại khi lỗi.** Mỗi finding tốn khoảng 2–3 lần gọi;
   lỗi quota làm báo cáo thành `partial`.
7. Code chỉ xét **có hay không có bằng chứng**: không đánh giá độ mạnh của bằng
   chứng, không phân biệt true/false positive, không tự tính CVSS, không retest.
8. Bản sao Cheat Sheet Series chưa ghi lại commit nguồn; hash chỉ bảo đảm corpus không
   đổi so với lúc ingest. `cards.json` chỉ có 2 thẻ.
9. Bộ lọc chính tả của `export_template_pdf.py` có thể ẩn nhầm câu đúng có chứa tên
   kiểu CamelCase (JavaScript, PostgreSQL...).
10. Chưa nhận PDF/HTML/CSV làm đầu vào. Với corpus tài liệu, PDF dạng ảnh chưa có OCR.

## Lộ trình học RAG

Các bài Tập 01–04 (báo cáo từ thẻ, load và chunk, embedding và retrieval cục bộ,
context + generate + trích nguồn) nằm ở [docs/lo-trinh-hoc-rag.md](docs/lo-trinh-hoc-rag.md).

## Nguồn và giấy phép

- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org, CC BY-SA 4.0 (xem
  `data/raw/owasp/official/CheatSheetSeries-master/LICENSE.md`).
- OWASP Top 10:2025: https://github.com/OWASP/Top10, CC BY 3.0.
- Font DejaVu: `src/rag/fonts/LICENSE.txt`.
- E5: https://huggingface.co/intfloat/multilingual-e5-small
- Google Gen AI Python SDK: https://github.com/googleapis/python-genai
- Structured output: https://ai.google.dev/gemini-api/docs/structured-output
- Tài liệu định dạng của từng scanner: xem [SCANNER_INPUTS.md](SCANNER_INPUTS.md).
