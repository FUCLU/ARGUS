# Quyết định xử lý các khác biệt code ↔ paper

Nguồn: `papers/gap-analysis.md`, mục 6. Số thứ tự # khớp bảng đó.

Loại quyết định:
- **SỬA**: đổi code theo paper
- **GIỮ**: giữ code hiện tại (ghi lý do)
- **THỬ**: paper không rõ, cần thử nghiệm nhiều giá trị

## A. Quyết định về điểm khác biệt

| # | Khác biệt | Quyết định | Ghi chú |
|---|---|---|---|
| 1 | Dataset: fixture 160 hàm CWE-125 thay vì artifact SVEN 254; thiếu PrimeVul | **SỬA (hoãn)** | Người dùng tự xử lý sau |
| 2 | Cơ chế Stage 1 | *Chưa quyết* | Đề xuất SỬA theo paper, kèm B1–B6 bên dưới. Người dùng tạm gác để dọn repo trước |
| 3 | Adjudicator độc lập; Defender đọc claim của Prosecutor; luật cứng `NO_DEFENSE ⇒ V` | **SỬA (đã làm)** | Theo Hình 1 và Pt. 4: Prosecutor ∥ Defender độc lập trên cùng $C_i$, Adjudicator nhận $(P_i, D_i, C_i)$, một lượt. Luật cứng đã bỏ, chỉ còn validation cấu trúc và trích dẫn dòng |
| 5 | Bỏ phiếu 3 vòng, hoà ⇒ VULNERABLE | **SỬA (đã làm)** | Hệ quả của #3: bỏ `--rounds`, một lượt, không bỏ phiếu |
| 4, 11 | Abstain/lỗi/không-có-ứng-viên; CWE $t_i$ trong prompt | *Chưa hỏi* | Hỏi tiếp. Hình 1 không vẽ đường mang $t_i$ vào Stage 3 |
| 6 | Mã thô cho LLM | **SỬA (đã làm)** | Gỡ nhánh fallback; ứng viên thiếu `compact_code` ⇒ `invalid_candidate_or_context` |
| 12 | `thinking`, `max_tokens` | **THỬ** (đã chọn mặc định) | `configs/llm.yaml`: `thinking: false` (thinking chiếm ~93% completion token), `max_tokens: 4096`. Ablation bật/tắt chưa chạy |
| 17 | Hai bộ prompt Stage 3 | **SỬA (đã làm)** | `--profile faithful` (mặc định, `prompts/faithful/`, chỉ theo mô tả paper, bỏ INSUFFICIENT_EVIDENCE) và `enhanced` (`prompts/`). Xem `docs/stage3_plan.md` |
| 18 | Báo cáo mẫu số metric | **SỬA (đã làm)** | `summary.json` ghi `n_total`, `n_valid`, `n_error`, `error_causes` (tr. 10) |
| 8–10, 13–16 | Các điểm Stage 1/2, metric, baseline | *Chưa hỏi* | Sau khi xong Stage 3 |

## B. Quyết định về cấu trúc repo (do người dùng yêu cầu)

| Việc | Quyết định | Chi tiết |
|---|---|---|
| Artifact Stage 1/2 cũ và mã Stage 2 | **SỬA (đã làm)** | Xoá `run_context.py`, `context.py`, `codebadger.py`, `primevul_source.py`, `sven_100pairs_*`. Lấy lại từ `9a7ede2` khi cần |
| `data/stage2.jsonl` | **GIỮ** | Chuyển thành fixture `data/fixtures/stage2.jsonl`, là input cố định duy nhất của Stage 3 cho tới khi viết lại Stage 1/2 |
| Protocol compact, code-only, direct-source | **SỬA (đã làm)** | Giữ ABP làm nền để sửa theo paper |
| Bố cục | **SỬA (đã làm)** | `sinkkb/` → `argus/{llm,stage3}`, `scripts/`, `configs/`, `data/{fixtures,raw}`, `tests/` |
| Cấu hình LLM | **SỬA (đã làm)** | `configs/llm.yaml` + `argus/llm/config.py`; thay `STAGE_SETTINGS`, biến môi trường model/provider và cờ `--provider` |
| Commit lịch sử của trợ lý | **SỬA (đã làm)** | `git reset --soft 9a7ede2`; thay đổi để ở working tree, chưa commit. Các commit sau đó (Stage 3 plan, `--profile`, faithful prompts, `thinking: false`) cũng đã reset về `9a7ede2`; HEAD hiện chỉ có commit đầu của người dùng |

## C. Câu hỏi mở cho điểm #2 (Stage 1), chưa quyết

| # | Câu hỏi | Đề xuất |
|---|---|---|
| B1 | Nội dung KB (API ↔ CWE) | SỬA: tự xây từ mô tả CWE và tài liệu API, đóng băng trước khi chạy test |
| B2 | KB chỉ 4 CWE hay rộng hơn | THỬ: {4 CWE, mở rộng} |
| B3 | Chuẩn hoá tên callee | SỬA: bỏ namespace, `__builtin_`, `std::` |
| B4 | Có tính `a[i]` (`<operator>.indexAccess`) là ứng viên không | THỬ: {chỉ non-operator đúng chữ paper, thêm indexAccess} |
| B5 | Hàm không có ứng viên | SỬA: gán Benign, đếm riêng |
| B6 | Prompt fallback và schema output | SỬA: tự viết, JSON có schema |
