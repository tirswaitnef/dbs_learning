# Lộ trình học RAG — Tập 01 đến Tập 04

Tài liệu này giữ lại các bài học từng bước của project. Trạng thái và cách dùng
hiện tại (bản 0.10, gồm web UI và chế độ `owasp`) nằm trong [README](../README.md).

> Nội dung từ Tập 02 trở đi được chuyển **nguyên văn** từ README cũ (bản 0.2–0.4).
> Số test và các câu như "chưa chạy E5/Gemini thật" là trạng thái **tại thời điểm đó**;
> trạng thái mới nhất xem [VALIDATION.md](../VALIDATION.md). Các lệnh trong bài vẫn
> dùng được với bản 0.10.

| Tập | Nội dung | Lệnh chính |
|---|---|---|
| 01 (bản nền 0.1) | Báo cáo từ thẻ OWASP đã duyệt: chunk thẻ → E5 → lọc CWE/điểm → Gemini chỉ chọn ID thẻ → kiểm tra ID → dựng báo cáo | `ingest.py`, `ask.py`, `generate_report.py --mode gemini` (xem README) |
| 02 | Load & chunk tài liệu gốc, giữ nguồn và offset | `preview_chunks.py` |
| 03 | Embedding E5 trên CPU, vector store NumPy, truy xuất top-k | `ingest_documents.py`, `retrieve.py` |
| 04 | Context có nguồn → Gemini → kiểm tra trích dẫn | `answer.py` |

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
