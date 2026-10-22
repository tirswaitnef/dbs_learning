# BÁO CÁO THỰC NGHIỆM ĐỊNH LƯỢNG HỆ THỐNG AI & HYBRID RAG

- **Số lượng truy vấn kiểm chuẩn (Ground-Truth Security IR Queries):** `24` kịch bản CSDL & Web-to-DB
- **Kho tri thức mục tiêu:** `25` tài liệu OWASP Cheat Sheet Series chuyên biệt CSDL (`552,584` bytes, `819` chunks)
- **Bộ biểu diễn Vector Dense:** `Unsupervised Truncated-SVD LSA (96-dim float32, offline corpus fit)`

## 1. Thực nghiệm Ablation Tầng Truy xuất Tri thức (Retrieval Architecture Ablation)

| Phương pháp truy xuất | Doc Hit@1 | Doc Hit@3 | Doc Hit@5 | Doc MRR | Section Hit@1 | Section Hit@3 | Section Hit@5 | Section MRR | Độ trễ TB (ms/query) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Dense Vector Only (Cosine)** | `58.3%` | `70.8%` | `87.5%` | `0.6694` | `37.5%` | `62.5%` | `75.0%` | `0.5184` | `0.22 ms` |
| **Lexical BM25 (Plain Chunk, No Heading Context)** | `58.3%` | `83.3%` | `95.8%` | `0.7358` | `16.7%` | `66.7%` | `75.0%` | `0.4191` | `0.38 ms` |
| **Heading-Boosted BM25 (Markdown Section Trail)** | `70.8%` | `83.3%` | `91.7%` | `0.7963` | `45.8%` | `75.0%` | `79.2%` | `0.6126` | `0.38 ms` |
| **Hybrid Search (Dense + Heading BM25 + RRF + Query Expansion)** | `75.0%` | `79.2%` | `91.7%` | `0.8112` | `50.0%` | `70.8%` | `79.2%` | `0.6292` | `28.73 ms` |

## 2. Thực nghiệm Thu gọn Kho Tri thức Chuyên biệt CSDL (`137` Cheat Sheets gốc vs `25` Cheat Sheets CSDL)

| Chỉ số đo lường | Kho OWASP Đầy đủ (`137` files) | Kho OWASP Chuyên biệt CSDL (`25` files) | Mức cải thiện / Thay đổi |
| :--- | :---: | :---: | :---: |
| Số lượng tệp Markdown | `137` | `25` | **Giảm `81.8%` nhiễu ngoài phạm vi** |
| Dung lượng văn bản gốc | `2,680,473 B` | `552,584 B` | **Giảm `79.4%` dung lượng** |
| Số lượng Chunks lập chỉ mục | `3977` | `819` | **Giảm `79.4%` không gian tìm kiếm** |
| Dense Cosine `Doc MRR` | `0.4767` | `0.6694` | **`+19.27` điểm %** |
| Hybrid RRF `Doc MRR` | `0.5683` | `0.8112` | **`+24.29` điểm %** |
| Hybrid RRF `Section MRR` | `0.4567` | `0.6292` | **`+17.25` điểm %** |
| Độ trễ truy xuất Hybrid TB | `135.43 ms` | `28.73 ms` | **Nhanh hơn `4.71x`** |

## 3. Thực nghiệm Kiểm chứng Trích xuất AI, Tương quan Đa nguồn & Chống ảo giác (Guardrail Evaluation)

| Chỉ số kiểm chứng an toàn AI | Kết quả thực nghiệm |
| :--- | :---: |
| **Precision trích xuất bản ghi kiểm thử** | `100.0%` |
| **Recall trích xuất bản ghi kiểm thử** | `100.0%` |
| **F1-Score trích xuất tổng hợp** | `100.0%` |
| **Độ chính xác ánh xạ mã CWE** | `100.0%` |
| **Độ chính xác phân loại trạng thái (`Đã xác nhận` / `Có dấu hiệu` / `Không xác nhận được`)** | `100.0%` |
| **Tỷ lệ chặn đứng ảo giác đối kháng (Adversarial Hallucination Block Rate)** | `6/6` (**`100.0%`**) |
