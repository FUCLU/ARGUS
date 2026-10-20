/op# Gap analysis: paper ARGUS (NSS-SocialSec 2026, paper 93) so với repo `Vulhihi`

- **Cập nhật:** 2026-10-21, sau refactor (working tree trên commit `9a7ede2`, chưa commit). Bản đầu khảo sát code gốc `sinkkb/`; bản này phản ánh repo `argus/` hiện tại.
- **Quy ước:** `[tr. X]` = trang paper (xem `papers/notes.md`). `file:dòng` = vị trí trong repo hiện tại. **[SUY ĐOÁN]** = suy luận, chưa kiểm chứng bằng cách chạy.
- **Giới hạn:** không đọc `.env`, `.env.example`, `_env_keys.py`. Chưa gọi LLM hay Joern; kiểm tra bằng `--dry-run` và 7 test.
- Mã đã xoá vẫn lấy lại được từ commit `9a7ede2`.

---

## 0. Tóm tắt

1. **Repo chưa tái hiện được bảng nào của paper.** Chưa có run nào đi qua Stage 1 → 2 → 3 trên artifact của paper.
2. **Stage 1 và Stage 2 đã bị xoá khỏi repo** (Stage 1 không có nguồn từ đầu; mã Stage 2 lệch phiên bản với dữ liệu). Hai stage này sẽ viết lại theo paper. Chỉ còn lại `data/fixtures/stage2.jsonl` làm input cố định cho Stage 3.
3. **Stage 3 đã sửa theo paper** (Prosecutor ∥ Defender độc lập, Adjudicator riêng, một lượt). Còn lệch: xử lý lỗi/hàm không có ứng viên, CWE $t_i$ chưa vào prompt.
4. **Đã dọn:** protocol compact và code-only, chế độ direct-source, nhánh đưa mã thô cho LLM. LLM đã chuyển sang `configs/llm.yaml`.
5. **Dataset** đúng của paper (SVEN 254) đã có trong `data/raw/llmxcpg/` nhưng chưa nối vào pipeline; PrimeVul chưa có. Người dùng sẽ tự xử lý sau (xem `decisions.md`, #1).

---

## 1. Bản đồ: phần của paper ↔ file/hàm trong repo

| Phần paper | Trang | Vị trí trong repo | Tình trạng |
|---|---|---|---|
| CPG (Joern) | tr. 9 | Không còn. Client CodeBadger đã xoá (`codebadger.py`, lấy từ `9a7ede2`) | Thiếu, viết lại cùng Stage 2 |
| Security Knowledge Base (Bảng 2) | tr. 4–5 | Không có. Artifact Stage 1 cũ tham chiếu `kb/cwe_sink_cards.json`, file không tồn tại | Thiếu |
| Stage 1: exact API match + LLM fallback | tr. 5–6 | Không có mã, không có artifact (artifact cũ đã xoá) | Thiếu |
| Stage 2: slicing, augmentation, interprocedural | tr. 6–7 | Không còn mã. Chỉ còn đầu ra mẫu `data/fixtures/stage2.jsonl` (160 mẫu, 472 ứng viên) | Thiếu, viết lại |
| Stage 3: Prosecutor | tr. 7 | `argus/stage3/protocol.py` `prosecutor_prompt`, `ValidationEngine.validate`; `prompts/prosecutor.txt` | Có |
| Stage 3: Defender | tr. 7 | `protocol.py` `defender_prompt`; `prompts/defender.txt` | Có, độc lập với Prosecutor |
| Stage 3: Adjudicator, Pt. 4 | tr. 7 | `protocol.py` `adjudicator_prompt`, `AdjudicatorVerdict`; `prompts/adjudicator.txt` | Có |
| Gộp mức hàm (≥1 Vulnerable ⇒ Vulnerable) | tr. 7 | `argus/stage3/runner.py` `_aggregate` (:448) | Có, kèm khác biệt xử lý lỗi (2.6) |
| Metric ACC/P/R/F1 trên mẫu hợp lệ | tr. 9–10 | `runner.py` (:871 trở đi, khối đếm tp/fp/fn/tn và `summary.json`) | Có |
| Metric theo CWE (Bảng 7) | tr. 11 | Không có | Thiếu |
| Qwen3-32B, temperature 0 | tr. 9 | `configs/llm.yaml`, `argus/llm/config.py`, `argus/llm/client.py` | Có, cấu hình được |
| Lưu vết ứng viên, ngữ cảnh, output agent | tr. 9, 13 | `requests.jsonl`, `stage3.jsonl`, `summary.json` trong `outputs/runs/<timestamp>/` | Có (không còn `packets/`) |
| Dataset SVEN 254 (Bảng 3) | tr. 8 | `data/raw/llmxcpg/sven_test.json`, khớp Bảng 3 | Có dữ liệu, chưa nối pipeline |
| Dataset PrimeVul 80 | tr. 8 | Không có | Thiếu |
| Audit trùng lặp exact | tr. 8, 13 | Kết quả: `data/raw/llmxcpg/*.audit.json`. Script sinh ra không có | Có kết quả, không có mã |
| Baseline LLMxCPG | tr. 9–10 | Không có | Thiếu |
| Test | — | `tests/test_stage3_fixture.py`, `tests/test_llm_config.py` (7 test) | Mới thêm |
| (Ngoài paper) pair metrics | — | `runner.py` `pair_consistency_metrics` (:478) | Giữ làm phụ |

---

## 2. Chỗ code KHÁC paper (còn lại sau refactor)

### 2.1 Stage 1 và Stage 2
Không còn mã để so sánh. Phần "cần làm" khi viết lại, theo paper:

| Hạng mục | Paper | Ghi chú từ code/artifact cũ (đã xoá) |
|---|---|---|
| Chọn ứng viên | Exact API match trên tên callee đã chuẩn hoá; LLM fallback chỉ khi hàm không có match, tối đa 3 cặp, revalidate với CPG node [tr. 5–6] | Artifact cũ: LLM + truy xuất KB cho **mọi** hàm (`top_k_cards=8`, pool 12, tối đa 3 ứng viên), CWE ngoài 4 loại (787: 115, 120: 78…) |
| Loại node | Chỉ non-operator invocation [tr. 5] | Ứng viên cũ là biểu thức tuỳ ý theo dòng |
| Neo node | 1 CPG node duy nhất làm slicing criterion; không ánh xạ được thì **không chuyển tiếp** [tr. 6] | Code cũ đoán node từ biểu thức (`select_anchor`) |
| Budget và thứ tự ưu tiên | Ưu tiên candidate, operands, checks, interprocedural; sắp theo vị trí nguồn [tr. 7] | Code cũ: SINK → GUARDS → BACKWARD → SYMBOL → CALL → FORWARD, cắt ở 120 dòng, nên toán hạng và liên thủ tục xếp sau backward slice |
| Hệ quả control-flow của guard | Giữ cả predicate lẫn hệ quả [tr. 6] | Code cũ chỉ lấy predicate; `stage2.jsonl` có `guard_evidence` do mã khác sinh ra |
| Giới hạn cũ | Không nêu giá trị | backward 20, forward 10, 8 toán hạng, call-hops 1, ≤16 call site, 12 method, 40 dòng/method |
| Fixture hiện có | — | `schema_version=context-v2.1`; 11/472 ngữ cảnh không có `compact_code` (anchor không resolve) |

### 2.2 Stage 3: kiến trúc tác tử

Sau lần sửa theo Hình 1: Prosecutor và Defender độc lập trên cùng $C_i$, Adjudicator nhận $(P_i, D_i, C_i)$, một lượt, không bỏ phiếu. Dòng đã khớp paper đánh dấu ✓.

| Hạng mục | Code hiện tại | Paper |
|---|---|---|
| Ai đưa ra verdict | Adjudicator riêng (`AdjudicatorVerdict`) ✓ | Adjudicator riêng: $V_i=\mathrm{Judge}(P_i,D_i,C_i)$ [tr. 7] |
| Defender có đọc Prosecutor | Không ✓ | Độc lập (Hình 1: không có mũi tên giữa hai vai) |
| Số vòng và bỏ phiếu | Một lượt, không bỏ phiếu; `--rounds` đã bỏ ✓ | Một lượt (Hình 1) |
| Luật quyết định cứng | Đã bỏ ✓. Chỉ còn validation cấu trúc (JSON, trích dẫn dòng có trong ngữ cảnh); hướng dẫn quyết định nằm trong `prompts/adjudicator.txt` | Adjudicator tự đánh giá [tr. 7] |
| CWE $t_i$ trong prompt | Không. Prompt chỉ có `{api_name}`, `{sink_json}`, `{function_code}`, `{prosecutor_json}`, `{prior_context}`, `{round_instruction}`. `cwe_candidate` chỉ lưu ở output | $h_i=(a_i,t_i)$ [tr. 4]; không rõ có đưa vào prompt không |
| Mã thô cho LLM | **Đã gỡ.** Ngữ cảnh không có `compact_code` ⇒ `invalid_candidate_or_context` (`runner.py` `context_prompt_code` :255) | Không đưa mã thô [tr. 2, 6] ✓ |
| Repair JSON | 1 lần sửa định dạng + 1 lần sửa validation cho mỗi lời gọi (`call`, `call_validated`) | Không nêu |
| Thứ tự gọi | Tuần tự: Prosecutor, Defender, Adjudicator (độc lập về dữ liệu; temperature 0 nên tương đương song song) | Hình 1 vẽ song song |

### 2.3 LLM và decoding (nay trong `configs/llm.yaml`)

| Hạng mục | Mặc định hiện tại | Paper |
|---|---|---|
| Model | `qwen/qwen3-32b` (OpenRouter) | Qwen3-32B [tr. 9] ✓ |
| Temperature | 0 | 0 "whenever supported" [tr. 9] ✓ |
| `max_tokens` | 4096 | Không nêu |
| `thinking` | `false` (OpenRouter `reasoning`; openai-compatible gửi `enable_thinking`). `null` = không gửi | Không nêu |
| Retry/timeout | 3 lần, backoff 2^n, 180 s | Không nêu |
| Seed, số lần chạy | Không có seed; một run mỗi cấu hình | Không nêu |

Thay đổi so với trước refactor: Stage 3 qua openai-compatible trước đây **không** gửi `enable_thinking`; nay gửi theo cấu hình. Mọi cấu hình LLM nằm trong `run_signature` và `requests.jsonl`.

### 2.4 Dữ liệu

| Hạng mục | Hiện tại | Paper |
|---|---|---|
| Fixture Stage 3 | `data/fixtures/stage2.jsonl`: 160 hàm đầy đủ, toàn CWE-125 (80 V / 80 B), từ `data/fixtures/sven_test_oracle.jsonl` (590 mẫu, có CWE-476) | SVEN artifact 254 mẫu, CWE-125/190/416 [tr. 8] |
| Artifact đúng | `data/raw/llmxcpg/sven_test.json`: 254 mẫu (129 V / 125 B), khớp Bảng 3; input là slice CPG của LLMxCPG (2–105 dòng) | Dùng nguyên vẹn [tr. 8–9] |
| Lọc trùng | `sven_test_unique_consistent.json`: 66 mẫu (26 V / 40 B); đã bỏ 8 nhóm nhãn mâu thuẫn (51 dòng) | Giữ nguyên, chỉ audit [tr. 8, 13] |
| PrimeVul | Không có | 80 mẫu [Bảng 3] |
| Trường gửi cho model | Chỉ `sink_json`, `compact_code`; loại label/CWE/pair_id | Không dùng gold label/CWE [tr. 8] ✓ |

### 2.5 Fixture lệch phiên bản mã
`data/fixtures/stage2.jsonl` có các trường `context_document`, `guard_evidence`, `operand_evidence`, `evidence_requirements`, `query_errors`, `evidence_scope`. Mã sinh ra chúng không có trong repo (cả bản đầu lẫn `9a7ede2`), nên fixture không tái sinh được.

### 2.6 Cách tính chỉ số

| Hạng mục | Code | Paper |
|---|---|---|
| Mẫu số | Chỉ mẫu có `prediction ∈ {V, B}` | Mẫu số = dự đoán hợp lệ [tr. 10] ✓ |
| Hàm không có ứng viên | Gán **BENIGN** và tính vào metric (`runner.py` `process_sample`, trạng thái `no_candidates`) | Không nêu (notes 6.1-6) |
| Một số ứng viên lỗi | Có ≥1 V ⇒ V dù ứng viên khác lỗi; còn lại B + lỗi ⇒ `None`, bị loại (`_aggregate`) | ≥1 V ⇒ V [tr. 7]; trường hợp lỗi không nêu. Thiên về recall |
| Theo CWE | Không có | Bảng 7 |
| Định dạng | Số thực 4 chữ số | % 2 chữ số |
| Thêm | FPR, pair metrics | Không có |

---

## 3. Phần paper có mà repo chưa có

1. **Stage 1 đầy đủ + KB** [tr. 4–6].
2. **Stage 2 theo paper** (Joern/CPG, neo node duy nhất, giữ hệ quả guard, thứ tự ưu tiên budget) [tr. 6–7].
4. **Dữ liệu và pipeline** cho SVEN 254 và PrimeVul 80 [tr. 8].
5. **Metric theo CWE** và báo cáo mẫu lỗi theo lớp/CWE [tr. 10–11, 13].
6. **Baseline LLMxCPG** [tr. 9–10].
7. **Script audit trùng lặp** (exact + normalized-code) [tr. 8].

---

## 4. File thừa, file tạm, code chết

**Đã dọn trong lần refactor:** `_tmp_lines.py`; protocol compact và code-only cùng 5 prompt, schema và few-shot của chúng; chế độ `--direct-source`; nhánh `[FUNCTION SOURCE FALLBACK]`; `STAGE_SETTINGS` và 3 lớp client riêng; `jsonschema` trong requirements; artifact Stage 1/2 cũ (`sven_100pairs_*`); `sven_reconstructed_dedup.json`.

**Còn lại, có thể dọn:**

| Đối tượng | Lý do |
|---|---|
| `outputs/runs/*` | Toàn bộ là run code-only/protocol đã xoá (v1–v8). Chỉ giữ để tham khảo; đã gitignore |
| `outputs/review_latest_sven_run.md`, `outputs/README.md` | Nói về run code-only cũ |
| `__pycache__/*.pyc` mồ côi ở gốc, `.pytest_cache/` | Bytecode của file đã xoá |
| `argus/stage3/runner.py` `_augment_legacy_call_context` (:~200) | Chỉ để tương thích renderer cũ |
| `argus/stage3/runner.py` `latest_results` / tham số `--stage1` | Stage 1 sẽ có định dạng mới |
| `argus/io.py` `read_jsonl` | Trùng với `runner.read_jsonl` |
| `protocol.py` `round_triage_status(verdict, claim, review)` | Hai tham số không dùng |
| `mcp` trong `requirements.txt`, `openai` | Không còn import nào; `mcp` sẽ cần lại cho Stage 2 nếu dùng CodeBadger |

---

## 5. Lệnh chạy hiện tại

```powershell
python -m pip install -r requirements.txt pytest
python -m pytest -q                                   # 7 test
python scripts/run_stage3.py --dry-run                # kiểm tra join, không gọi API
python scripts/run_stage3.py --limit 5 --workers 1
python scripts/run_stage3.py --llm-config configs/llm.yaml --model qwen3-32b --workers 4
```
Mặc định: `--stage2 data/fixtures/stage2.jsonl`, `--data data/fixtures/sven_test_oracle.jsonl`, `--workers 4`. Không có bước train (ARGUS không fine-tune [tr. 9]). Stage 1 và 2 hiện không có lệnh chạy.

Chưa có kết quả Stage 3 nào trên fixture; các số trong `outputs/runs/` (F1 khoảng 55–62%) thuộc protocol code-only đã xoá và **không** so được với paper.

---

## 6. Xếp hạng khác biệt theo mức ảnh hưởng

Thang: **Rất cao** = không so được với paper nếu chưa sửa; **Cao** = có thể làm lệch P/R vài điểm % trở lên; **Trung bình**; **Thấp**. Mức ảnh hưởng là **[SUY ĐOÁN]**, chưa đo bằng ablation. Cột "Trạng thái" cho biết lần refactor đã xử lý đến đâu.

| # | Khác biệt | Mức | Trạng thái |
|---|---|---|---|
| 1 | Dataset: fixture 160 hàm CWE-125 thay vì artifact 254; thiếu PrimeVul | Rất cao | **Hoãn**, người dùng tự làm |
| 2 | Stage 1: cơ chế khác paper, không có mã/KB | Rất cao | Mã cũ đã xoá; chờ viết lại |
| 3 | Không có Adjudicator độc lập; Defender đọc Prosecutor; luật cứng `NO_DEFENSE ⇒ V` | Cao | **Đã sửa** theo Hình 1 |
| 4 | Xử lý abstain/lỗi/không-có-ứng-viên ảnh hưởng mẫu số | Cao | Một phần: compact (abstain) đã xoá; còn khác biệt ở `_aggregate` |
| 5 | Bỏ phiếu 3 vòng, hoà ⇒ VULNERABLE | Cao | **Đã sửa** (một lượt) |
| 6 | Đưa mã thô cho LLM | Cao | **Đã gỡ** (11/472 ứng viên nay báo invalid) |
| 7 | Lọc artifact 254 → 66 | Cao (cho run đó) | Run code-only đã xoá; file lọc vẫn có trong `data/raw` |
| 8 | Mã Stage 2 lệch fixture | Trung bình–Cao | Mã Stage 2 đã xoá; fixture không tái sinh được |
| 9 | Thứ tự ưu tiên budget, guard thiếu hệ quả control-flow | Trung bình | Chờ viết lại Stage 2 |
| 10 | Tối đa 3 ứng viên/hàm | Trung bình | Chờ viết lại Stage 1/2 |
| 11 | CWE $t_i$ không vào prompt Stage 3 | Trung bình | Chưa xử lý |
| 12 | Thinking mode, max_tokens không nêu trong paper | Trung bình | **Đã chuyển sang config**; cần chọn giá trị (THỬ) |
| 13 | Liên thủ tục chỉ trong snippet | Trung bình–Thấp | Chờ viết lại Stage 2 |
| 14 | Độ sâu slice, ngân sách call | Thấp–Trung bình | Chờ viết lại Stage 2 |
| 15 | Không có metric theo CWE; N hợp lệ theo lớp | Thấp | Chưa xử lý |
| 16 | Thiếu baseline LLMxCPG | Thấp | Chưa xử lý |
| 17 | Thiếu tests, README lỗi thời, file tạm | Thấp | **Đã xử lý** (7 test, README mới) |
