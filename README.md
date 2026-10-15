# AI sinh báo cáo kiểm thử và gợi ý sửa theo OWASP

Project mới từ đầu, phiên bản 0.5 (bổ sung nhập output từ sáu công cụ). Không kế thừa code/cấu hình/dữ liệu của dự án trước.
Không dùng LangChain. Phù hợp học cơ chế RAG và phát triển đề tài theo từng bước.

## Bắt đầu với output công cụ — bản 0.5

Đọc chi tiết trong [SCANNER_INPUTS.md](SCANNER_INPUTS.md). Có bộ đọc cho ZAP,
Burp, Nuclei, sqlmap, Nessus và Nmap; mẫu đều là dữ liệu giả lập.

```powershell
python scripts/normalize_scan.py --input tests/fixtures/scanners/zap.json --format zap
```

Lệnh này chỉ cần Python standard library, không gọi AI và không cần kho OWASP.
Kết quả: `data/processed/scan-import/findings.json` và `import-summary.md`.
Nmap được giữ dưới dạng quan sát; lời khuyên từ scanner được giữ riêng với nguồn OWASP.
Chưa xác nhận parser bằng file export thật của người dùng.

## Chạy ngay trên Windows — chưa cần API

Giải nén, mở PowerShell trong thư mục `owasp-report-rag` rồi chạy:

```powershell
python --version
python scripts/demo.py
```

Yêu cầu Python 3.11 trở lên; khuyến nghị dùng 3.12 cho môi trường ban đầu.
Demo dùng thư viện chuẩn Python, không cần cài requirements, không gọi mạng và
không đọc `.env`. Đây là demo pipeline theo luật ghép CWE, **không phải kết quả do AI tạo**.

Mở `data/reports/demo/report.md` trong VS Code (Ctrl+Shift+V) để xem báo cáo.
`report.json` là bản dữ liệu có cấu trúc. Bộ mẫu có 3 finding giả lập:

| Finding | Kết quả dự kiến |
|---|---|
| SQL Injection có bằng chứng giả lập | Có hướng dẫn OWASP kèm mục và link |
| XSS không có bằng chứng | Chưa đưa gợi ý sửa |
| Finding chưa phân loại | Chưa có hướng dẫn phù hợp |

Mọi địa chỉ `example.test` và nội dung trong file mẫu là dữ liệu giả lập.
Project không truy cập hoặc kiểm thử các địa chỉ đó.

## Cài môi trường RAG/AI đầy đủ

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip check
Copy-Item .env.example .env
```

Nếu PowerShell chặn activate, dùng thẳng Python của môi trường ảo; không cần sửa execution policy:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts/demo.py
```

Các lệnh `python ...` phía dưới cũng có thể thay bằng `.\.venv\Scripts\python.exe ...`.
Trên Linux/macOS: tạo venv tương tự rồi `source .venv/bin/activate`.

`requirements.txt` cài project với nhóm thư viện `ai,pdf,dev` từ `pyproject.toml`:
sentence-transformers, numpy, google-genai, python-dotenv, pypdf, pytest.
Các khoảng phiên bản hiện chưa phải lockfile đã xác nhận trên máy bạn.
Sau khi cài và kiểm tra thành công, lưu môi trường phục vụ thí nghiệm:

```powershell
python -m pip freeze > requirements-lock.txt
```

Không commit `.env`, cache model, vector store hay kết quả quét thật.
`pip check` chỉ kiểm tra dependency, không kiểm chứng AI hoặc chất lượng RAG.

## Chạy RAG + Gemini

1. Lấy key tại https://aistudio.google.com/apikey và điền `GEMINI_API_KEY` trong `.env`.
2. Điền `GEMINI_CHAT_MODEL` bằng mã model khả dụng trong tài khoản, có hỗ trợ structured output.
   Không ghi cứng một mã có thể đã hết hỗ trợ. Xem https://ai.google.dev/gemini-api/docs/models.
   Quota/chi phí phụ thuộc tài khoản và model; project không hứa API miễn phí vô hạn.
3. Giữ `EMBED_MODEL=intfloat/multilingual-e5-small` để bắt đầu. Lần đầu cần tải model.
4. Chạy:

```powershell
python scripts/ingest.py
python scripts/ask.py "Cách phòng SQL Injection" --cwe CWE-89
python scripts/generate_report.py --input data/raw/scans/example.json --mode gemini --output data/reports/ai-example
```

Trong chế độ này: tài liệu đã duyệt → chunk → E5 embeddings → NumPy cosine retrieval
→ lọc CWE/điểm → Gemini chọn ID hướng dẫn → kiểm tra ID → dựng báo cáo.

**Vai trò AI bản 0.1:** chọn hướng dẫn phù hợp từ các ứng viên truy xuất được và trả
kế hoạch JSON. Báo cáo tiếng Việt được dựng bằng mẫu và nội dung đã duyệt.
Chưa cho AI viết tự do remediation hoặc kết luận kỹ thuật mới. Đây là nền tảng
RAG sinh báo cáo có kiểm soát, chưa phải chatbot hoàn chỉnh hoặc nghiên cứu hoàn tất.

Gemini nhận ID finding, tiêu đề, CWE, cờ có bằng chứng và ứng viên hướng dẫn.
URL đích, mức độ, raw evidence và response body không gửi trong payload hiện tại.
Không đưa thông tin bí mật vào tiêu đề/ID finding. Các trường đầu vào không được
coi là chỉ dẫn cho model. Nếu API lỗi hoặc trả ID sai, lệnh dừng, không âm thầm
chuyển sang demo. Nếu thư mục output có báo cáo của lần trước, kiểm tra timestamp;
lần thất bại không cập nhật các file đó.

## Cấu trúc thư mục

| Đường dẫn | Trách nhiệm |
|---|---|
| `data/raw/owasp/` | Kho hướng dẫn OWASP có nguồn, được duyệt trước |
| `data/raw/scans/` | Kết quả kiểm thử đầu vào, tách khỏi kho OWASP |
| `data/processed/` | Chunks, vectors, manifest sinh tự động; không sửa tay |
| `data/reports/` | Báo cáo Markdown và JSON đầu ra |
| `src/rag/config.py` | Đọc cấu hình |
| `src/rag/loader.py` | Đọc/kiểm tra kho; helper đọc MD/TXT/PDF có text |
| `src/rag/chunker.py` | Chia đoạn trong phạm vi từng thẻ/mục |
| `src/rag/embeddings.py` | Tạo embedding E5, tiền tố query/passage |
| `src/rag/vector_store.py` | Lưu vectors NumPy, kiểm tra cấu hình và hash kho |
| `src/rag/retriever.py` | Truy xuất và lọc hướng dẫn |
| `src/rag/parsers/` | Parser normalized JSON và ZAP traditional JSON |
| `src/rag/schemas.py` | Cấu trúc finding và thẻ nguồn |
| `src/rag/llm.py` | Gemini structured output; chế độ demo riêng |
| `src/rag/validators.py` | Từ chối ID lạ, sai finding, thiếu finding, nội dung tự do |
| `src/rag/report_builder.py` | Ghép dữ liệu, nguồn và hướng dẫn thành báo cáo |
| `src/rag/pipeline.py` | Điều phối toàn bộ luồng |
| `scripts/` | Các điểm chạy CLI |
| `tests/` | Kiểm thử parser, truy xuất, nguồn và điều kiện từ chối |
| `notebooks/` | Chỗ thử nghiệm, chưa có notebook mẫu |

`.venv` và `.pytest_cache` được tạo khi dùng; không đóng gói sẵn.

## Định dạng kết quả kiểm thử được hỗ trợ

### JSON chuẩn hóa của project

```json
{
  "schema_version": 1,
  "tool": "Tên công cụ và phiên bản",
  "findings": [
    {
      "id": "F-001",
      "title": "SQL Injection",
      "cwe": "CWE-89",
      "severity": "high",
      "location": "https://example.test/search?q=...",
      "evidence": ["Bằng chứng thực sự có trong kết quả công cụ"]
    }
  ]
}
```

```powershell
python scripts/generate_report.py --input data/raw/scans/my-scan.json --format normalized --mode gemini --output data/reports/my-scan
```

Không tự đặt bằng chứng hoặc CWE nếu công cụ không có căn cứ. Khi không biết CWE,
dùng `unknown` hoặc bỏ trường đó; hệ thống sẽ không suy đoán hướng dẫn theo tên lỗi.
Mức độ được giữ đúng như đầu vào, không phải điểm đánh giá lại của project.
ID finding phải duy nhất. Nhập tối đa 10 MiB/file và 10.000 bản ghi; nhánh sinh báo cáo qua Gemini giới hạn 100 bản ghi/lần.

### ZAP traditional JSON

Hỗ trợ cấu trúc `site[].alerts[].instances[]`, không phải mọi loại JSON export
của ZAP. Mỗi instance tạo một finding; `evidence` lấy từ evidence của instance,
không lấy attack payload làm bằng chứng và không dùng solution từ scanner thay
cho nguồn OWASP đã duyệt. Confidence/parameter/payload được giữ trong `details` từ phiên bản 0.5. Response của instance có thể bổ sung bằng chứng.

```powershell
python scripts/generate_report.py --input data/raw/scans/zap-example.json --format zap --mode demo --output data/reports/zap-demo
```

Parser đã kiểm thử trên fixture giả lập theo cấu trúc này, chưa xác nhận bằng
file export thực tế của bạn. Bản 0.5 bổ sung Burp XML, Nuclei JSONL, Nessus XML,
Nmap XML và khối kết quả cuối trong log sqlmap. Xem `SCANNER_INPUTS.md` để biết
đúng định dạng và giới hạn. Chưa hỗ trợ báo cáo HTML/PDF/CSV.

## Nguồn OWASP và giới hạn “không bịa”

Kho khởi đầu chỉ có 2 thẻ: SQLi và XSS. Xem `data/raw/owasp/README.md`.
Mỗi thẻ chứa hướng dẫn tiếng Việt, điều kiện áp dụng, trích mục ngắn, tên tài liệu,
URL chính thức và ngày đối chiếu. `approved` là cờ duyệt của project, không phải
chứng nhận của OWASP. Người nghiên cứu cần kiểm tra lại các thẻ trước đánh giá chính thức.

Ràng buộc thực thi:

- Không có evidence → không đính kèm remediation.
- Không có thẻ phù hợp/được duyệt → trả lời chưa đủ căn cứ.
- Model chỉ xuất ID thuộc danh sách ứng viên của đúng finding; không tự viết URL hoặc cách sửa.
- Văn bản hướng dẫn và đường link được code lấy từ kho đã duyệt.
- Đổi kho/model/chunk config → phải ingest lại; tránh dùng vector cũ với tài liệu mới.
- Báo cáo có hash đầu vào, hash kho, model và thời điểm để đối chiếu.

Các ràng buộc này giảm bịa nội dung nhưng không đảm bảo chọn đúng trong mọi ngữ cảnh.
Việc có evidence chưa chứng minh evidence đó đủ mạnh. CWE có thể sai ngay từ
đầu vào. Hai thẻ có sẵn không bao phủ toàn bộ cách sửa hay toàn bộ OWASP.
Chưa đánh giá true/false positive, chưa tự suy luận CVSS, không khẳng định lỗi
nằm ở một dòng code, không kiểm chứng bản vá, không quét/retest hệ thống.

`RAG_MIN_SCORE=0.75` là ngưỡng thử nghiệm cần hiệu chỉnh, không phải xác suất.
`TOP_K=4`, chunk 800 ký tự/overlap 120 chỉ là điểm xuất phát. Các chunks không
vượt qua ranh giới thẻ. E5 dùng prefix `query: ` / `passage: ` và từ chối input
quá giới hạn tokenizer thay vì cắt mất phần cuối. Model embedding khác có thể
cần adapter riêng; không mặc định đổi tên model là giữ nguyên cơ chế đúng.

## Kiểm thử

Không cài thêm thư viện vẫn chạy được bộ kiểm thử core:

```powershell
python -m unittest discover -s tests -v
```

Sau khi cài full requirements, có thể dùng:

```powershell
python -m pytest -q
```

Xem `VALIDATION.md` để biết phần nào đã kiểm tra khi giao project. Chưa có kết quả
thực nghiệm về chất lượng AI. Khi phát triển tiếp, cần bộ finding gán nhãn, thẻ
OWASP được duyệt độc lập và so sánh baseline/RAG trên cùng dữ liệu, thay vì dùng
số test code pass làm bằng chứng chất lượng báo cáo.

## Nguồn kỹ thuật

- E5: https://huggingface.co/intfloat/multilingual-e5-small
- Google Gen AI Python SDK: https://github.com/googleapis/python-genai
- Structured output: https://ai.google.dev/gemini-api/docs/structured-output
- OWASP: các link mục nguồn được lưu trực tiếp trong `cards.json`.


## Tập 02 — Load & Chunk tài liệu gốc (mới trong 0.2)

Chạy từ thư mục project, không cần key hoặc model embedding:

```powershell
python scripts/preview_chunks.py
```

Lệnh mặc định đọc `data/raw/owasp/documents/`, quét cả thư mục con và hỗ trợ
`.md`, `.markdown`, `.txt`, `.pdf`. Hai tài liệu có sẵn là tài liệu kỹ thuật minh
họa tự viết, **không phải nguồn OWASP**. Không đưa thư mục kết quả scanner vào
corpus tài liệu. Tránh trộn hướng dẫn project/README với tài liệu nguồn thực tế.

- `Document`: source tương đối + text + SHA-256 file + metadata tùy chọn.
- `Chunk`: giữ source, index, start/end, text, hash và metadata của Document.
- Mặc định 800 ký tự/chunk, overlap 120; bước di chuyển là 680 ký tự.
- Không chia xuyên qua ranh giới giữa hai file; không bỏ mất đường dẫn thư mục con.
- File không hỗ trợ/rỗng được liệt kê SKIP. File lỗi cần sửa trước khi tiếp tục.
- PDF có text cần pypdf đã cài; PDF ảnh chưa có OCR. Test PDF hiện dùng mock, chưa kiểm tra trên PDF thật.

Kết quả:

- `data/processed/load-chunk/chunks.jsonl`: một chunk trên mỗi dòng JSON.
- `data/processed/load-chunk/summary.json`: số tài liệu/chunk, cấu hình và file bị bỏ qua.

Muốn đổi cấu hình thử nghiệm:

```powershell
python scripts/preview_chunks.py --chunk-size 800 --overlap 120
python scripts/preview_chunks.py --raw data/raw/owasp/documents --output data/processed/load-chunk
```

Preview dùng giá trị mặc định từ Settings hoặc cờ CLI, **không đọc .env** để
vẫn chạy được bằng Python thuần cho Markdown/text. Lệnh ingest/AI vẫn dùng .env
như trước. Thư mục output phải nằm ngoài thư mục raw đang đọc.

Có thể thêm `ten-file.md.meta.json` cạnh `ten-file.md`, chứa object JSON với
`title`, `url`, `section`, `retrieved_on` nếu có. Metadata được giữ nguyên,
không tự xác thực rằng URL hay nội dung đúng và không tự cấp quyền approved.
Ngày thu thập/URL chỉ điền khi thực sự biết, không tự đặt.

Đây là bước chuẩn bị corpus. Từ bản 0.3, `ingest_documents.py` nối trực tiếp
loader/chunker này với E5 và document vector store (xem Tập 03 bên dưới).
File chunks.jsonl vẫn là bản preview; ingest đọc lại raw bằng cùng loader/chunker
để không vô tình dùng preview đã cũ. `ingest.py` tiếp tục xử lý cards.json cho
nhánh báo cáo. Corpus tài liệu chưa tự động trở thành remediation đã duyệt.

Overlap giảm nguy cơ thiếu ngữ cảnh ở ranh giới, không đảm bảo giữ nguyên mọi ý.
800 ký tự không đồng nghĩa 800 token. Các ví dụ và test kiểm tra 1291/1530 ký tự
cho đúng 5 chunk; demo đi kèm hiển thị số lượng theo nội dung mẫu thực tế.


## Tập 03 — Embedding và retrieval local (mới trong 0.3)

Mục tiêu: nối corpus tài liệu của Tập 02 với embedding E5 trên CPU, lưu vectors
cùng nguồn, embed câu hỏi và lấy top-k context. Chưa sinh câu trả lời bằng LLM.

### Cài và chạy

Trong venv, chỉ cài nhóm retrieval nếu chưa cần Gemini:

```powershell
python -m pip install -e ".[retrieval]"
python scripts/ingest_documents.py
python scripts/retrieve.py "Vì sao cần giữ đường dẫn nguồn khi chia tài liệu?" --top-k 3
```

Lần ingest đầu cần internet để tải model nếu máy chưa có cache. Không cần API key.
Model dùng `intfloat/multilingual-e5-small`, chạy CPU, prefix `passage: ` cho tài
liệu và `query: ` cho câu hỏi. Encode yêu cầu normalize; lưu thành float32.
E5-small có 384 chiều; với 5 chunk mẫu dự kiến shape `(5, 384)`. Shape thực tế
được in khi chạy. Bản bàn giao chưa chạy E5 thật nên đây không phải số đo của môi
trường kiểm tra project.

Sau khi có đủ model trong cache, có thể yêu cầu không truy cập mạng để tải model:

```powershell
python scripts/ingest_documents.py --offline
python scripts/retrieve.py "Overlap giúp gì khi chia đoạn?" --top-k 3 --offline
```

Nếu thiếu cache, `--offline` báo lỗi thay vì tải model. Local nghĩa là tính toán
trên máy, không có nghĩa lần cài thư viện/tải model đầu tiên không cần internet.
Nếu `.env` có sẵn, nhóm retrieval đã bao gồm python-dotenv để đọc nó.
GEMINI_API_KEY/GEMINI_CHAT_MODEL có thể để trống trong toàn bộ Tập 03.

### File và kết quả

`data/processed/documents/` chứa:

- `vector_store.npz`: ma trận vectors float32 đã normalize, không dùng pickle.
- `vector_store.meta.json`: text, source, index, start/end, metadata gốc, hash
  corpus/chunks/vectors, tên model/revision và cấu hình chunk.

Query đọc lại store, kiểm tra model/cấu hình/corpus còn khớp, chỉ embed câu hỏi.
Không embed lại toàn bộ tài liệu mỗi lần hỏi. Tính `vectors @ q`, xếp giảm dần
bằng NumPy và trả về text/source/index/offset/score/metadata.
Cùng điểm thì giữ thứ tự chunk ban đầu. top-k lớn hơn số chunk trả tối đa số hiện có.

```powershell
python scripts/retrieve.py "Nguồn của mỗi đoạn được lưu ở đâu?" --top-k 4 --json
python scripts/retrieve.py "Nguồn của mỗi đoạn được lưu ở đâu?" --top-k 4 --min-score 0.8
```

Mặc định nhánh document retrieval lấy top-k không có ngưỡng, để quan sát thứ hạng
như Tập 03. `--min-score` là tùy chọn thử nghiệm; điểm cosine không phải xác suất
câu trả lời đúng và ngưỡng 0.8 không phải chuẩn chung. `RAG_MIN_SCORE` trong .env
vẫn dành cho nhánh truy xuất thẻ đã duyệt, không tự áp vào lệnh retrieve.py.
Nếu không đoạn nào qua ngưỡng, trả kết quả rỗng, không viết câu trả lời.

Đổi tài liệu/sidecar, model, revision, chunk size hoặc overlap thì ingest lại.
Để tái lập thí nghiệm giữa các máy/thời điểm, nên điền EMBED_REVISION bằng commit
model đã kiểm tra và lưu lockfile môi trường. Khi revision để trống, chỉ tên model
không bảo đảm nội dung trên máy chủ model không đổi về sau.
Checksum phát hiện hỏng/ghép nhầm store; không phải chữ ký xác thực nguồn OWASP.

### Hai nhánh trong project

| Mục đích | Ingest | Truy xuất | Store |
|---|---|---|---|
| Học và kiểm tra corpus tài liệu, Tập 02–03 | `ingest_documents.py` | `retrieve.py` | `data/processed/documents/` |
| Báo cáo có gợi ý từ thẻ đã duyệt, bản nền | `ingest.py` | `ask.py --cwe ...` / `generate_report.py` | `data/processed/e5/` |

Nhánh mới ở `src/rag/document_store.py`, dùng lại loader/chunker/E5Embedding.
Corpus vẫn có hai tài liệu minh họa kỹ thuật, không phải tài liệu OWASP thật.
Retrieval không tự biến tài liệu thành căn cứ sửa lỗi. Bản 0.4 nối context với hỏi đáp qua `answer.py` và kiểm tra ID nguồn/trích đoạn.
Nhánh báo cáo kiểm thử vẫn dùng hướng dẫn đã duyệt riêng; không tự lấy câu trả
lời tự do làm remediation chính thức.

### Kiểm tra và giới hạn hiện tại

33 unittest đã chạy PASS, trong đó 9 test mới kiểm tra phép tính NumPy, lưu/đọc
NPZ, xếp hạng, source, ngưỡng, vector lỗi, store cũ và ingest/query dùng encoder giả.
Test wrapper E5 dùng mock để kiểm tra prefix, CPU, cache và dtype, không đo chất
lượng semantic retrieval. Nếu máy chưa có NumPy, 9 test mới được ghi SKIP rõ ràng.
Môi trường bàn giao chưa cài được sentence-transformers, chưa tải/chạy model E5,
không có score retrieval E5 thực tế để báo cáo. Không đính kèm store vector giả
mang nhãn E5. Gemini API calls = 0 trong toàn bộ luồng Tập 03.

Nguồn API:
- https://sbert.net/docs/package_reference/sentence_transformer/SentenceTransformer.html
- https://huggingface.co/intfloat/multilingual-e5-small


## Tập 04 — Context + Generate + Sources (mới trong 0.4)

Luồng hỏi đáp tài liệu đã nối trong code:

Question → E5 query → retrieve top-k → context có nguồn → Gemini → kiểm tra trích dẫn → answer + sources.

### Chạy hỏi đáp

Cài full requirements trong venv. Điền GEMINI_API_KEY và GEMINI_CHAT_MODEL vào
.env theo hướng dẫn ở trên. Nếu chưa có store tài liệu thì ingest trước:

```powershell
python -m pip install -r requirements.txt
python scripts/ingest_documents.py
python scripts/answer.py "Overlap giúp gì khi chia tài liệu?"
python scripts/answer.py "Dự án có hỗ trợ thanh toán bằng MoMo không?" --json
```

Câu đầu có nội dung liên quan trong tài liệu mẫu. Câu thứ hai dự kiến cần từ chối
vì tài liệu mẫu không chứng minh có/không hỗ trợ MoMo. Đây là tình huống kiểm tra
đề xuất, **chưa có output Gemini thật để chứng minh model sẽ xử lý đúng**.

Khi E5 đã được cache:

```powershell
python scripts/answer.py "Tên file nguồn dùng để làm gì?" --offline-embeddings
```

`--offline-embeddings` chỉ áp dụng E5; Gemini vẫn cần mạng/API. Nhánh hỏi đáp gửi
câu hỏi và các chunk context đã chọn (bao gồm nguồn/metadata) tới Gemini. Không
gửi toàn bộ corpus; ngân sách context mặc định 12000 ký tự JSON. Đây là ngân sách
ký tự để giới hạn kích thước đầu vào, không phải số token chính xác.

### Cấu trúc code

| Thành phần | Vai trò |
|---|---|
| `context.py` | Giữ nguyên chunk + source, cấp ID S1/S2, loại trùng và giới hạn context |
| `prompts.py` | System prompt chỉ dùng context, schema structured output |
| `llm.py / GeminiLLM` | Điểm gọi Gemini chung cho hỏi đáp và kế hoạch báo cáo |
| `qa.py / RAGPipeline.answer()` | Retrieve → context → generate → validate → RAGAnswer |
| `scripts/answer.py` | CLI trả lời tiếng Việt hoặc xuất JSON ra stdout |

Context chứa text, đường dẫn nguồn, index, offsets, score, hash và metadata.
Prompt serialize JSON để tách câu hỏi/context thành trường dữ liệu. Đây không
phải biện pháp loại trừ hoàn toàn prompt injection; nội dung vẫn cần được coi là
không đáng tin cậy. Không thực thi lệnh hoặc gọi công cụ từ context.

### Kiểm tra nguồn bằng code

Model phải trả JSON gồm `status` và `statements`. Mỗi statement có `text` và
`citations`, mỗi citation có `source_id` và `quote` nguyên văn từ đúng chunk.
Chương trình tự lấy tên file nguồn; không yêu cầu model tự viết đường link.

- Không có chunk được đưa vào context: trả thiếu thông tin, không gọi Gemini.
- Model trả insufficient_context: hiện câu từ chối cố định, không suy luận thành
  'có hỗ trợ' hoặc 'không hỗ trợ'.
- ID nguồn lạ, thiếu citation, quote không có trong chunk, JSON sai hoặc câu từ
  chối kèm claim: chặn output, trả status rejected_output. CLI exit code 2.
- Lỗi API/thiếu dependency: lỗi thực thi, không giả thành 'tài liệu không có thông tin'.
- `sources` chỉ chứa nguồn thực sự được model trích dẫn và qua kiểm tra.
- `retrieved_sources` trong JSON giữ context đã gửi để đối chiếu (không bao gồm
  chunk bị loại do ngân sách context).
- `statements` giữ nguyên các câu và trích đoạn để người kiểm tra có thể đối chiếu.

**Giới hạn quan trọng:** một quote có thật không chứng minh statement diễn giải
đúng ý quote, cũng không chứng minh nguồn là OWASP hay hướng dẫn phù hợp hệ thống.
Code hiện kiểm tra cấu trúc, ID và sự tồn tại trích đoạn; chưa tự kiểm chứng ngữ
nghĩa/entailment. Prompt và retrieval score không bảo đảm hết hallucination.
Câu trả lời hỏi đáp là bản sinh tự động cần đánh giá; không thay thế nhánh
remediation từ thẻ đã duyệt trong generate_report.py.

Hai tài liệu mẫu vẫn là nội dung kỹ thuật tự viết. Để tiến tới đề tài thực tế,
cần corpus OWASP chính thức có URL/mục/ngày lấy, kết quả kiểm thử thật và đánh giá
câu trả lời trên cả câu có dữ liệu lẫn câu ngoài phạm vi. Project chưa được chứng
minh là hệ thống báo cáo OWASP hoàn chỉnh chỉ vì đã ghép đủ bốn bước hướng dẫn.

### Kiểm thử bản 0.4

44 unittest PASS trong môi trường bàn giao. Có test context rỗng không gọi model,
score cao vẫn có thể từ chối, nguồn bịa, quote sai chunk, thiếu citation, JSON sai,
lỗi API, và bảo toàn nguồn đã trích. Các phản hồi Gemini trong test đều được mock.
E5 thật/Gemini thật chưa chạy; không có bằng chứng thực nghiệm về chất lượng
trả lời hay khả năng từ chối trên model thực tế. Xem VALIDATION.md.
