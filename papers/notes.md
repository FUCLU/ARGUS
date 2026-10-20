# Notes: ARGUS — Evidence Context Construction and Adversarial Validation for Vulnerability Detection

- **File:** `NSS-SocialSec_2026_paper__93.pdf`, 15 trang, bản ẩn danh (Anonymous Author(s)).
- **Không có phụ lục / supplementary:** paper kết thúc bằng Conclusion (tr. 13–14) rồi References (tr. 14–15); không có mục Appendix, không có link code/dataset/supplementary (bản ẩn danh). Code artifact được nhắc ở tr. 9 nhưng không kèm đường dẫn.
- **Quy ước trích dẫn:** `[tr. X]` = số trang in ở header PDF. Tôi đã kiểm tra số này trùng với số trang của file PDF. `[Bảng N]`, `[Pt. (k)]` = bảng / phương trình trong paper.
- **Quy ước đánh dấu:**
  - Không có nhãn = paper ghi rõ, kèm trang.
  - **[SUY ĐOÁN]** = paper không nói rõ. Đây là diễn giải, kiến thức bên ngoài, hoặc số tính ngược của tôi.
  - **⚠️** = paper mơ hồ hoặc tự mâu thuẫn (có trích dẫn trang hai phía).
- **Cách trích văn bản:** dùng `pdftotext`. Một số ký hiệu toán học bị mất khi trích (xem mục 2). **Hình 1 (tr. 5) là ảnh raster** nên `pdftotext` không trích được chữ; đã render ảnh ra và đọc trực tiếp (xem mục 2.5). Nội dung đọc từ hình được ghi kèm nhãn **[HÌNH 1]**.

---

## 1. Bài toán và đóng góp chính

### 1.1 Bài toán
- **Nhiệm vụ:** phát hiện lỗ hổng ở **mức hàm**, phân loại nhị phân **Vulnerable / Benign** [tr. 4 Pt. 2; tr. 7; tr. 9 "function-level binary classification"], cho chương trình C/C++ (Joern dựng CPG "for C/C++ programs", tr. 9).
- **Hai khó khăn được nêu:** [tr. 1–2]
  1. **Xây ngữ cảnh:** đưa nguyên hàm/repo vào thì thừa mã không liên quan; cắt quá mạnh thì mất quan hệ quyết định thao tác có nguy hiểm không. Slicing giúp bớt nhiễu, nhưng "a smaller slice is not necessarily a sufficient security context" (slice nhỏ hơn chưa chắc đủ ngữ cảnh bảo mật). [tr. 2]
  2. **Suy luận thiếu căn cứ:** LLM có thể dựa vào dấu hiệu bề mặt hoặc giả định không có căn cứ [tr. 2]; safeguard "are not always explicitly validated before classification" (không phải lúc nào cũng được kiểm chứng tường minh trước khi phân loại). [tr. 1]
- **Hướng giải quyết:** framework 3 giai đoạn: sensitive operation identification → program context construction → vulnerability validation [tr. 2]. Tức là tách "localization, context construction, and validation" (định vị, xây ngữ cảnh, kiểm chứng). [tr. 4]

### 1.2 Ba đóng góp [tr. 2]
1. **Security-Sensitive Candidate Identification:** neo vào call site cụ thể trong CPG; kết hợp exact API matching với LLM fallback có ràng buộc cho các thao tác đặc thù của dự án.
2. **Program Context Construction:** ngữ cảnh riêng cho từng ứng viên, gồm backward/forward slice, control dependency, bằng chứng mức nguồn, quan hệ liên thủ tục có giới hạn; không đưa mã thô cho LLM.
3. **Adversarial Vulnerability Validation:** phân tích bằng chứng đối lập trên cùng ngữ cảnh, rồi một Adjudicator riêng đưa ra verdict cuối.

### 1.3 Kết quả tóm tắt (Abstract) [tr. 1]
- PrimeVul (artifact được đánh giá): **R 100.00%, P 57.58%, F1 73.08%**.
- SVEN: **R 75.27%, P 52.63%, F1 61.95%**.
- Tác giả tự mô tả ARGUS là "recall-oriented detector" (thiên về recall); giảm false positive là hướng cải thiện quan trọng [tr. 1; nhắc lại tr. 12, 14].

### 1.4 Công trình liên quan và vị trí của ARGUS [tr. 2–4, Bảng 1]
- **LLM-based VD:** zero/few-shot, CoT, ICL, fine-tuning, RAG [tr. 2]; Vul-RAG truy xuất nguyên nhân, điều kiện kích hoạt, bản vá lịch sử [tr. 2–3]. Hạn chế: với mã thô, mô hình phải tự suy cùng lúc thao tác, phụ thuộc, điều kiện kích hoạt và safeguard [tr. 3].
- **Program-grounded:** IRIS [8], **LLMxCPG [5]**, RepoAudit [3]. LLMxCPG được chọn làm **baseline chính** vì gần nhất (CPG-guided context) [tr. 3].
- **Multi-agent:** VulTrial [12] (mock-court + review board), MulVul [13], MAVUL [6], VulAgent [11]. Khác biệt của ARGUS: Prosecutor và Defender nhận **cùng một ngữ cảnh tái dựng bằng phân tích tĩnh** [tr. 3].
- **Bảng 1 (tr. 4):**

| Khía cạnh | LLMxCPG | VulTrial | ARGUS |
|---|---|---|---|
| Program analysis | CPG-guided static analysis | No dedicated static-analysis stage | CPG-guided static analysis |
| Context construction | Vulnerability-focused program slices | Source code provided to role-specific agents | Candidate-specific program context |
| Reasoning organization | Downstream vulnerability classification | Multi-agent mock-court interaction | Prosecutor–Defender–Adjudicator validation |
| Evidence grounding | Reasoning over CPG-derived slices | Reasoning over source code and inter-agent arguments | Reasoning over a shared reconstructed program context |
| Counter-evidence handling | Considered within downstream reasoning | Introduced through opposing agent roles | Explicitly evaluated against supporting evidence |
| Decision mechanism | Vulnerability classification | Review-board decision | Evidence adjudication |

---

## 2. Phương pháp / kiến trúc chi tiết

> **Ghi chú trích xuất:** trong Pt. (2), (3), (4) các ký hiệu toán học bị mất khi trích text. Tôi điền **∈** cho Pt. (2), (4) và **∪** cho Pt. (3) là **[SUY ĐOÁN]**, dựa trên ngữ cảnh ("V_i ? {Vulnerable, Benign}"; "C_dep = C_back ? C_forward ? C_ctrl"). Cần kiểm tra lại trên PDF render.

### 2.1 Hình thức hoá [tr. 4]
- Chương trình $P$, CPG: $G = \mathrm{CPG}(P)$ (không đánh số).
- Ứng viên: $h_i = (a_i, t_i)$ **(Pt. 1)**, với $a_i$ là thao tác nhạy cảm và $t_i$ là loại lỗ hổng.
- Stage 2 tạo $C_i$; Stage 3 cho $V_i \in \{\text{Vulnerable}, \text{Benign}\}$ **(Pt. 2)**.

Luồng: `CPG (Joern) → Stage 1: ứng viên h_i → Stage 2: ngữ cảnh C_i (không LLM) → Stage 3: Prosecutor + Defender → Adjudicator → V_i → gộp mức hàm`

### 2.2 Stage 1: Sensitive Operation Identification [tr. 4–6]
- Chỉ **định vị**; có thao tác nhạy cảm **không** có nghĩa là có lỗ hổng [tr. 4]. Phân loại để dành tới khi đã tái dựng hành vi xung quanh [tr. 6].

**a) Security Knowledge Base** [tr. 4–5, Bảng 2]
- "Curated" [tr. 4]; "manually curated" [tr. 13].
- Cố định trước khi đánh giá cuối, không cập nhật theo dự đoán hay lỗi trên tập test [tr. 4–5]. Entry nào chỉnh trong lúc phát triển cũng được đóng băng trước đánh giá [tr. 5]. Mapping API–CWE đóng băng, không đổi theo dự đoán test [tr. 13].
- Nguồn xây dựng: mô tả CWE công khai, ngữ nghĩa API có tài liệu, mẫu thao tác liên quan bảo mật; không từ dự đoán benchmark [tr. 5].
- Hai phần [tr. 5]:
  - **Exact API mappings:** khớp tất định giữa *normalized CPG call names* và CWE.
  - **Semantic reasoning cards:** operation kind, operand roles, candidate-selection rule, exclusion rule, program evidence. Dùng "when no exact API match is available" (khi không có exact match).
- **Bảng 2 (tr. 5), schema KB:**

| Field | Description |
|---|---|
| Knowledge ID | Unique identifier of a knowledge entry |
| CWE | Associated CWE category |
| Weakness | Human-readable vulnerability type |
| Operation kind | Semantic class of the sensitive operation |
| API / pattern | Concrete API names or operation patterns associated with the entry |
| Operand roles | Security-relevant operands, such as buffer, index, size, or object pointer |
| Selection rule | Condition under which a concrete CPG call is treated as a candidate |
| Exclusion rule | Conditions under which a matched operation should not be selected |
| Evidence to inspect | Program properties relevant to downstream vulnerability reasoning |

- **Ví dụ (tr. 5):** entry *indexed-read*, CWE-125: ứng viên là thao tác đọc bộ nhớ; operand roles = base object + index; loại trừ câu lệnh tính toán/kiểm tra index; hướng suy luận tới giá trị index, object extent, backward data flow, bounds check.

**b) Candidate Identification** [tr. 5–6]
1. Trích **non-operator invocation nodes** từ CPG, chuẩn hoá tên callee [tr. 5].
2. Khớp exact API mappings; mỗi match tạo **một ứng viên cho mỗi CWE liên kết** [tr. 6].
3. "When no exact candidate is found" (khi không tìm được exact candidate nào) thì gọi **constrained LLM fallback** [tr. 6]:
   - Input: hàm đích + invocation nodes từ CPG + semantic reasoning cards.
   - Chọn **tối đa 3** giả thuyết operation–CWE.
   - Không được đưa vào biểu thức nguồn tuỳ ý; mỗi thao tác phải ứng với một CPG node có thật và được **revalidate** trước Stage 2.
   - ⚠️ "No exact candidate" tính theo **hàm** (cả hàm không có match nào) hay theo **từng invocation**? **[SUY ĐOÁN]** Theo hàm, vì input của fallback là cả hàm đích.

### 2.3 Stage 2: Program Context Construction [tr. 6–7]
- **Không dùng LLM** ở Stage 2 [tr. 7].

**a) Program slicing** [tr. 6]
- Ánh xạ $a_i$ tới **một CPG node duy nhất** làm slicing criterion; ứng viên không ánh xạ được rõ ràng thì **không chuyển tiếp**.
- Backward slice: định nghĩa/tính toán ảnh hưởng tới ứng viên. Forward slice: thao tác bị ứng viên ảnh hưởng. Control dependency: điều kiện quyết định câu lệnh liên quan có chạy không.
- **Pt. (3):** $C_i^{dep} = C_i^{back} \cup C_i^{forward} \cup C_i^{ctrl}$ (ký hiệu ∪ là [SUY ĐOÁN], xem ghi chú trên).
- Theo dõi thêm các biến liên quan tới ứng viên: def/use, phép tính size, index, offset, allocation liên quan.

**b) Context augmentation** [tr. 6–7]
- **Mức nguồn (AST):** khai báo, định nghĩa, allocation, dùng toán hạng, câu lệnh kiểm tra. Với mỗi check, giữ **cả predicate lẫn hệ quả control-flow** [tr. 6].
- **Bounded interprocedural analysis:** theo caller–callee và argument–parameter mappings "on demand" (khi cần), để tìm nguồn argument ở caller, ngữ nghĩa wrapper, tác động của callee. Chỉ giữ thông tin nối với ứng viên qua quan hệ chương trình [tr. 6–7].

**c) Hậu xử lý** [tr. 7]
- Khử trùng lặp, dựng lại câu lệnh nhiều dòng, **sắp theo vị trí trong mã nguồn**.
- Vượt context budget thì "prioritizes the candidate, its operands, relevant checks, and interprocedural dependencies" (ưu tiên ứng viên, toán hạng, check liên quan, phụ thuộc liên thủ tục).
  - **[SUY ĐOÁN]** Paper chỉ liệt kê, **không nói đây là thứ tự ưu tiên** hay chỉ là tập được ưu tiên giữ lại.
- ⚠️ Paper chỉ định nghĩa $C_i^{dep}$; **không có công thức cho $C_i$ cuối cùng** (dep + augmentation + hậu xử lý). **[SUY ĐOÁN]** $C_i$ = $C_i^{dep}$ ∪ phần augmentation, sau khi khử trùng, sắp xếp và cắt theo budget.

### 2.4 Stage 3: Vulnerability Validation [tr. 7]
- **Prosecutor:** bằng chứng ủng hộ: unsafe value propagation, insufficient bounds, arithmetic overflow, invalid object lifetime, absence of an effective check.
- **Defender:** phản chứng: bounds checks, input validation, path constraints, terminating error handling, object reinitialization, ownership transfer, safe cleanup.
- Hai vai dùng **đúng cùng ngữ cảnh**, chỉ khác mục tiêu phân tích.
- **Adjudicator** nhận phân tích của hai bên cùng với $C_i$, kiểm tra lập luận có được ngữ cảnh ủng hộ không, và xét điều kiện lỗ hổng còn khả thi không:
  **Pt. (4):** $V_i = \mathrm{Judge}(P_i, D_i, C_i),\; V_i \in \{\text{Vulnerable}, \text{Benign}\}$, với $P_i$, $D_i$ là phân tích của Prosecutor và Defender.
- **Gộp mức hàm:** các ứng viên kiểm chứng độc lập; hàm là Vulnerable nếu ≥ 1 ứng viên Vulnerable, ngược lại là Benign [tr. 7]. Viết gọn $V(f)=\text{Vuln} \iff \exists i: V_i=\text{Vuln}$ (ký hiệu do tôi viết lại, nội dung đúng như paper).
- **[HÌNH 1]** Prosecutor và Defender chạy **một lượt, độc lập**: $C_i$ rẽ nhánh tới cả hai, **không có mũi tên nào giữa Prosecutor và Defender**, và không có vòng lặp hay bỏ phiếu. Prosecutor xuất $P_i$ ("Supporting analysis"), Defender xuất $D_i$ ("Counter-analysis"). Văn bản chỉ nói "Their analyses are then passed, together with C_i, to an Adjudicator" (phân tích của hai bên được chuyển cùng C_i cho Adjudicator), không nói rõ có nhiều vòng hay tương tác không; hình trả lời câu hỏi này. Hình không vẽ bước gộp mức hàm, bước này chỉ có trong văn bản.

### 2.5 Nội dung Hình 1 (tr. 5) [HÌNH 1]
Hình gồm 3 khung ngang, đánh số 1–3, đọc từ ảnh render.

- **Khung 1 "Sensitive Operation Identification":** `Target Function → CPG → API Knowledge Base`. Nhánh "Exact candidates found" đi thẳng tới ô **"Operation-Type Candidate $h_i=(a_i,t_i)$"**. Nhánh "No exact candidates" đi xuống ô nét đứt **"LLM-assisted fallback"**, rồi vào cùng ô $h_i$.
- **Khung 2 "Program Context Construction"**, ghi chú nét đứt **"(Static Program Analysis Only)"**. Chuỗi: $h_i$ → **Slicing Criterion** (ghi chú "Unique CPG node") → **Program Slices** (Backward Slice, Forward Slice, Control Dependencies) → **Context Augmentation** (AST structure; Var. defs/uses; **Allocations/checks + control-flow effects**; Interprocedural (bounded)) → **Program Context $C_i$**.
- **Khung 3 "Vulnerability Validation":** $C_i$ rẽ nhánh tới **Prosecutor** ("searches for evidence supporting the vulnerability") và **Defender** ("searches for counter-evidence"). Prosecutor cho "Supporting analysis $P_i$", Defender cho "Counter-analysis $D_i$"; cả hai vào **Adjudicator**. Một đường nhãn **"program context"** đi từ $C_i$ thẳng tới Adjudicator (khớp Pt. 4: $\mathrm{Judge}(P_i, D_i, C_i)$). Đầu ra: **"Candidate verdict $V_i$: Vulnerable or Benign"**.

Điều hình xác nhận hoặc thêm so với văn bản:
1. Prosecutor và Defender **độc lập**, một lượt, không có vòng lặp (mục 2.4).
2. Chỉ $C_i$ đi vào Stage 3; $h_i=(a_i,t_i)$ chỉ đi vào Stage 2 (Slicing Criterion). Hình **không vẽ** đường nào mang $t_i$ tới agent, nên việc $t_i$ có nằm trong $C_i$ hay prompt không **vẫn không rõ** (6.3-17b).
3. Fallback được vẽ ở mức "không có exact candidate" (không nói theo hàm hay theo invocation, giữ nguyên ⚠️ ở 2.2b).
4. Stage 2 nhấn mạnh "Static Program Analysis Only", khớp với "không dùng LLM" [tr. 7].

---

## 3. Dataset và cách xử lý dữ liệu

### 3.1 Thành phần (Bảng 3, tr. 8, "released evaluation artifacts")

| Dataset | CWE | Vulnerable | Benign | Total |
|---|---|---|---|---|
| PrimeVul | CWE-125 | 10 | 10 | 20 |
| | CWE-190 | 10 | 10 | 20 |
| | CWE-415 | 10 | 10 | 20 |
| | CWE-416 | 10 | 10 | 20 |
| | **Total** | **40** | **40** | **80** |
| SVEN | CWE-125 | 50 | 41 | 91 |
| | CWE-190 | 35 | 35 | 70 |
| | CWE-416 | 44 | 49 | 93 |
| | **Total** | **129** | **125** | **254** |

(Văn bản tr. 8 nhắc lại đúng các số này.)

### 3.2 PrimeVul [tr. 8]
- Bản gốc: C/C++ thực tế; giảm nhiễu nhãn, trùng mã và rò rỉ thời gian; **6.968** hàm vulnerable từ **6.827** commit sửa lỗi; **140** CWE.
- Dùng **evaluation artifact phát hành kèm LLMxCPG [5]**: 80 mẫu (40 V / 40 B), 4 CWE × (10 V + 10 B).
- ⚠️ tr. 8 viết "The same evaluation set is used for ARGUS and our LLMxCPG experiments" (cùng tập đánh giá cho ARGUS và thí nghiệm LLMxCPG). Nhưng tr. 10 nói số LLMxCPG ở Bảng 5 là **số của paper gốc**, và tr. 13 nói **vẫn cần** "a completed same-sample PrimeVul reproduction of LLMxCPG" (một bản tái hiện LLMxCPG trên PrimeVul với cùng mẫu). Tức là trên PrimeVul, so sánh cùng mẫu thực tế **chưa được thực hiện**.

### 3.3 SVEN [tr. 8]
- Dataset mức hàm tuyển chọn thủ công từ commit sửa lỗi bảo mật thực tế [4].
- Dùng **artifact SVEN phát hành kèm LLMxCPG**: 254 mẫu, CWE-125/190/416.
- Mỗi hàm là một input độc lập; **không** cung cấp thông tin cặp vulnerable–fixed, patch diff, quan hệ cặp khi suy luận.

### 3.4 Kiểm soát trùng lặp / rò rỉ
- Danh sách mẫu **đóng băng trước suy luận**, dùng lại cho các phương pháp so sánh trực tiếp [tr. 8, 12–13].
- Audit trùng lặp **exact** và **normalized-code** [tr. 8, 13].
- Không dùng vulnerable–fixed relations, patch, CVE descriptions, **gold CWE labels** cho suy luận hay chọn ứng viên [tr. 8]. Ground-truth labels cũng không lộ cho ARGUS [tr. 13].
- Nếu phương pháp tái hiện dùng dev/few-shot, phải loại khỏi tập đánh giá các mẫu trùng normalized-code identity [tr. 8].
- Quan hệ vulnerable–fixed chỉ giữ làm metadata đánh giá [tr. 13].
- Không thêm/bớt mẫu theo output mô hình; execution failure được ghi lại tường minh [tr. 9].
- Artifact phát hành **không khớp hoàn toàn** thống kê tổng hợp trong paper LLMxCPG; tác giả giữ nguyên artifact, không chỉnh cho khớp [tr. 8, 9, 13, 14].

---

## 4. Toàn bộ hyperparameter và cấu hình thí nghiệm

### 4.1 ARGUS (mục "ARGUS Configuration", tr. 9; **không có bảng riêng**)

| Hạng mục | Giá trị | Trang |
|---|---|---|
| Ngôn ngữ cài đặt | Python | tr. 9 |
| CPG | Joern, cho chương trình C/C++ | tr. 9 |
| LLM | **Qwen3-32B** cho "All LLM-based components". Các thành phần LLM được nêu trong paper: fallback Stage 1 (tr. 6); Prosecutor, Defender, Adjudicator (tr. 12) | tr. 9 |
| Fine-tuning | Không fine-tune trên PrimeVul hay SVEN | tr. 9 |
| Temperature | **0** "whenever supported" (khi được hỗ trợ) | tr. 9 |
| Prompt và cấu hình mô hình | Giống nhau trên hai artifact | tr. 9 |
| Số giả thuyết fallback tối đa | **3** cặp operation–CWE | tr. 6 |
| Điều kiện gọi fallback | Khi không có exact candidate | tr. 5–6 |
| Thành phần ngữ cảnh | backward slice, forward slice, control dependencies, source-level augmentation, bounded interprocedural analysis | tr. 6–7, 9 |
| LLM ở Stage 2 | Không | tr. 7 |
| Khi vượt budget | Ưu tiên ứng viên, toán hạng, check, phụ thuộc liên thủ tục ([SUY ĐOÁN] về thứ tự, xem 2.3c) | tr. 7 |
| Gộp mức hàm | ≥ 1 ứng viên Vulnerable ⇒ hàm Vulnerable | tr. 7 |
| Lưu vết | Ứng viên, ngữ cảnh, output trung gian của agent, dự đoán cuối | tr. 9, 13 |
| **Không được nêu** | Phiên bản Joern, context budget, độ sâu slicing, giới hạn liên thủ tục, max input/output tokens, top-p, seed, thinking mode, quantization, framework serving, prompt | (xem mục 6) |

### 4.2 Baseline LLMxCPG tái hiện (Bảng 4, tr. 10; mô tả tr. 9)

| Item | Reproduction setting (nguyên văn có tóm tắt) |
|---|---|
| Source code | Authors' released LLMxCPG implementation |
| Repository revision | Recorded from the exact snapshot used in our experiments (**không có giá trị**) |
| Base checkpoint | QwQ-32B-Preview for LLMxCPG-D |
| Fine-tuning | LoRA rank **8**, alpha **4**, learning rate **10⁻⁴** "**as reported by LLMxCPG**" |
| Prompt templates | Released LLMxCPG prompts, unchanged where available |
| Joern / CPG pipeline | Same released workflow used by the reproduced baseline |
| Decoding parameters | Recorded from the local inference configuration (**không có giá trị**) |
| Input/output limits | Recorded from the local inference configuration (**không có giá trị**) |
| Context budget | Recorded from the released/local reproduction configuration (**không có giá trị**) |
| Evaluation samples | Same frozen released sample identities used by ARGUS |

- ⚠️ Các tham số LoRA là số **trích từ paper LLMxCPG gốc** (tr. 9: "The original paper reports…"), **không phải** cấu hình tác giả ARGUS xác nhận đã chạy. Paper không nói họ tự fine-tune lại hay dùng checkpoint đã phát hành ("released checkpoint" có được nhắc ở tr. 9, nhưng không có giá trị).
- tr. 9: các định danh cài đặt (revision, checkpoint, Joern version, decoding, max input/output length, context budget, evaluation script) "are reported with the released code artifact" (được báo cáo kèm code artifact phát hành). **Không có trong paper.**

### 4.3 Metric và xử lý lỗi [tr. 9–10]
- ACC, P, R, F1 cho phân loại nhị phân mức hàm [tr. 9]. Precision = "reliability of vulnerable predictions" (độ tin cậy của dự đoán vulnerable); Recall = tỉ lệ hàm vulnerable phát hiện được [tr. 9–10]. Suy ra lớp positive = Vulnerable (suy từ định nghĩa, khớp với ma trận nhầm lẫn tr. 10).
- "For every table, the metric denominator is the number of samples that produced an evaluable binary prediction." (Với mọi bảng, mẫu số metric là số mẫu cho ra dự đoán nhị phân đánh giá được.) Lỗi pipeline báo cáo riêng [tr. 10]. Tr. 13 nhắc lại: "we report the number of valid predictions used for each metric" (báo cáo số dự đoán hợp lệ dùng cho từng metric).
- **[SUY ĐOÁN]** Kết quả là **một lần chạy duy nhất**. Paper không nói số lần chạy hay seed; tr. 13 chỉ nói "repeated sampling" (lấy mẫu lặp lại) là việc cần làm trước khi kết luận mạnh hơn.

---

## 5. Kết quả cần tái hiện

> Mọi số trong các bảng dưới đây đã được đối chiếu lại với paper. Các ma trận nhầm lẫn có nhãn [SUY ĐOÁN] là **tính ngược** bằng brute-force: duyệt mọi (TP, FP, TN, FN) nguyên với số mẫu V/B không vượt Bảng 3, làm tròn 2 chữ số thập phân. Mỗi trường hợp ra **đúng 1 nghiệm**, trừ trường hợp ghi chú khác. Phép tính này dựa trên giả định paper nói ở tr. 10: metric tính trên các mẫu hợp lệ.

### 5.1 RQ1: PrimeVul (Bảng 5, tr. 10)

| Method | Result source (nguyên văn) | ACC | P | R | F1 |
|---|---|---|---|---|---|
| LLMxCPG | "Original paper / Local rerun" ⚠️ | 72.50 | 100.00 | 45.00 | 62.06 |
| **ARGUS** | Local run on released artifact | **63.64** | **57.58** | **100.00** | **73.08** |

- Caption và văn bản: ARGUS có **77 dự đoán hợp lệ / 80 input**; **TP 38, FP 28, TN 11, FN 0** [tr. 10, ghi trong cả đoạn 4.1 và 4.2].
- Kiểm tra: 49/77 = 63.64 ✓; 38/66 = 57.58 ✓; F1 = 76/104 = 73.08 ✓.
- [SUY ĐOÁN] Từ TP + FN = 38 và FP + TN = 39: **2 mẫu vulnerable và 1 mẫu benign** bị lỗi. Paper chỉ nói 3 lỗi, không nói thuộc lớp nào.
- ⚠️ Cột nguồn ghi "Original paper / Local rerun", nhưng tr. 10 nói đây là "results reported in the original publication" (kết quả công bố trong paper gốc), và so sánh cùng artifact "requires the locally rerun LLMxCPG result" (cần kết quả LLMxCPG chạy lại local). ⇒ Đây là **số trích**, không phải rerun.
- [SUY ĐOÁN] F1 LLMxCPG tính từ P = 100, R = 45 là 62.07; paper ghi 62.06 (có thể cắt thay vì làm tròn).

### 5.2 RQ1: SVEN (Bảng 6, tr. 11)

| Method | ACC | P | R | F1 | Nguồn (tr. 11) |
|---|---|---|---|---|---|
| VulSim | 33.00 | 31.00 | 31.00 | 31.00 | Từ đánh giá trong paper LLMxCPG |
| VulBERTA-CNN | 50.00 | 51.00 | 38.00 | 44.00 | như trên |
| VulBERTA-MLP | 50.00 | 50.00 | 37.00 | 43.00 | như trên |
| ReGVD | 51.00 | 53.00 | 46.00 | 55.00 ⚠️ | như trên |
| LLMxCPG | 62.61 | 66.67 | 42.48 | 51.89 | **Chạy lại local** trên artifact SVEN |
| **ARGUS** | **55.21** | **52.63** | **75.27** | **61.95** | Chạy local |

- So sánh cùng artifact chỉ là LLMxCPG vs ARGUS: ARGUS cao hơn R và F1; LLMxCPG cao hơn ACC và P [tr. 11].
- ⚠️ ReGVD: F1 tính từ P = 53, R = 46 là **49.25**, không phải 55.00. VulSim (31), CNN (43.55 → 44), MLP (42.53 → 43) thì nhất quán.
- **Paper không báo cáo số mẫu hợp lệ hay ma trận nhầm lẫn cho SVEN** (Bảng 6 không có caption "N valid predictions" như Bảng 5).
- [SUY ĐOÁN] Tính ngược (nghiệm duy nhất):
  - **ARGUS:** TP 70, FP 63, TN 36, FN 23 ⇒ **N = 192/254** (93 V + 99 B), tức khoảng **62 mẫu không có dự đoán hợp lệ**, không được nhắc tới (mâu thuẫn với cam kết ở tr. 10, 13).
  - **LLMxCPG:** TP 48, FP 24, TN 101, FN 65 ⇒ **N = 238/254** (113 V + 125 B).
  - ⇒ Hai phương pháp **có thể** được tính trên hai tập mẫu hợp lệ khác nhau.

### 5.3 RQ2: Theo CWE trên PrimeVul (Bảng 7, tr. 11)

| CWE | ACC | P | R | F1 | [SUY ĐOÁN] TP/FP/TN/FN (n hợp lệ / 20) |
|---|---|---|---|---|---|
| CWE-125 | 65.00 | 58.82 | 100.00 | 74.07 | 10/7/3/0 (20) |
| CWE-190 | 57.89 | 55.56 | 100.00 | 71.43 | 10/8/1/0 (19): 1 benign lỗi |
| CWE-415 | 57.89 | 52.94 | 100.00 | 69.23 | 9/8/2/0 (19): 1 vuln lỗi |
| CWE-416 | 73.68 | 64.29 | 100.00 | 78.26 | 9/5/5/0 (19): 1 vuln lỗi |

- [SUY ĐOÁN] Tổng các dòng: TP 38 / FP 28 / TN 11 / FN 0, n = 77, khớp Bảng 5.
- Paper (tr. 11): recall vẫn cao, precision thay đổi theo CWE. CWE-125 cần lập luận về memory extent/index/offset/access bound; CWE-190 về lan truyền giá trị số học và ràng buộc; CWE-415/416 về lifetime, deallocation, alias, sử dụng sau đó.
- **Không có bảng theo CWE cho SVEN** (RQ2 chỉ trình bày PrimeVul).

### 5.4 RQ3: Phân tích lỗi, **chỉ định tính, không có số** [tr. 11–12]
- **Stage 1:** chọn thao tác hợp lý cho CWE nhưng không phải thao tác quyết định ⇒ slice sai hướng; wrapper đặc thù dự án khó [tr. 11–12].
- **Stage 2:** thiếu dependency, alias, ràng buộc liên thủ tục hoặc check hiệu quả. Lỗi lặp lại: lấy được guard nhưng **không lấy được hệ quả control-flow** của nó [tr. 12].
- **Stage 3:** có đủ thông tin nhưng cân nhắc sai; bounds check, terminating path, safe lifetime transition bị đánh giá thấp. Điều này khớp với profile precision–recall [tr. 12].
- Kết luận: giảm FP cần cả phủ ngữ cảnh rộng hơn lẫn nhận diện tốt hơn khi nào phản chứng thực sự vô hiệu hoá điều kiện lỗ hổng [tr. 12].

### 5.5 Checklist tái hiện
- [ ] Bảng 5: ARGUS / PrimeVul (80 input): 63.64 / 57.58 / 100.00 / 73.08 trên 77 dự đoán hợp lệ; TP 38, FP 28, TN 11, FN 0.
- [ ] Bảng 6: ARGUS / SVEN (254 input): 55.21 / 52.63 / 75.27 / 61.95 (số mẫu hợp lệ: paper không ghi; [SUY ĐOÁN] 192).
- [ ] Bảng 6: LLMxCPG rerun / SVEN: 62.61 / 66.67 / 42.48 / 51.89 ([SUY ĐOÁN] 238 hợp lệ).
- [ ] Bảng 7: 4 dòng theo CWE trên PrimeVul.
- [ ] Ghi lại số mẫu lỗi pipeline và nguyên nhân cho từng dataset và từng phương pháp.
- [ ] (Thêm, paper chưa làm) Rerun LLMxCPG trên artifact PrimeVul để có so sánh cùng mẫu (tr. 10, 13).

### 5.6 Hạn chế và threats to validity tác giả tự nêu [tr. 12–13]
- **Phủ thao tác nhạy cảm:** Stage 1 dựa trên invocation node, nên kém với lỗ hổng mà thao tác then chốt là **language primitive** (primitive của ngôn ngữ) thay vì lời gọi hàm [tr. 12].
- **Phủ phân tích chương trình:** phụ thuộc độ chính xác của CPG và giới hạn phân tích. Indirect call, pointer alias, macro, ngữ nghĩa riêng của dự án, phụ thuộc ngoài phạm vi liên thủ tục có thể bị thiếu [tr. 12].
- **Kiểm chứng bằng LLM:** không có đảm bảo hình thức. Verdict **Benign = "absence of an established vulnerability"** (chưa xác lập được lỗ hổng với bằng chứng thu được), **không phải** chứng minh an toàn [tr. 12].
- **Internal validity:** kết quả phụ thuộc phiên bản Joern, cấu hình trích graph, context budget, prompt, checkpoint, decoding [tr. 12–13].
- **Data selection:** artifact PrimeVul nhỏ nên ước lượng (ví dụ Recall) kém ổn định; kết quả chỉ đặc trưng cho artifact, không phải toàn bộ PrimeVul [tr. 13].
- **Knowledge-base bias:** KB thủ công có thể làm kết quả tổng quát hoá bị đánh giá quá cao; tác giả giảm rủi ro bằng cách đóng băng KB và phân biệt exact match với fallback để đo trong tương lai [tr. 13].
- **Construct validity:** metric nhị phân không chứng minh định vị đúng vị trí lỗ hổng; cần benchmark localization riêng [tr. 13].
- **Conclusion validity:** cần đánh giá rộng hơn, repeated sampling, thêm LLM backbone, và **hoàn tất rerun LLMxCPG cùng mẫu trên PrimeVul** [tr. 13].

---

## 6. Những chi tiết paper không nói rõ

### 6.1 Knowledge base và Stage 1
1. **Nội dung KB** (số entry, danh sách API ↔ CWE, các semantic card) **không công bố**; chỉ có schema (Bảng 2) và 1 ví dụ [tr. 5].
2. **Quy tắc chuẩn hoá tên callee** không mô tả [tr. 5].
3. ⚠️ Stage 1 chỉ lấy "non-operator invocation nodes" [tr. 5], nhưng ví dụ KB là entry *indexed-read* CWE-125 [tr. 5]. Paper không giải thích ứng viên đọc-theo-chỉ-số được tạo thế nào. **[SUY ĐOÁN, kiến thức ngoài paper]** Trong Joern, `a[i]` được biểu diễn là `<operator>.indexAccess`, tức là một operator call, nên sẽ bị loại bởi tiêu chí trên. Hạn chế ở tr. 12 (language primitives) có vẻ thừa nhận điểm này.
4. Prompt, format output và cách parse của LLM fallback không có.
5. "Revalidated before Stage 2" [tr. 6]: tiêu chí revalidate không nêu.
6. Hàm **không có ứng viên nào** sau cả exact match và fallback thì được gán Benign hay tính là lỗi pipeline? Không nói.
7. **[SUY ĐOÁN]** Vì không dùng gold CWE [tr. 8], ứng viên có thể mang **bất kỳ CWE nào trong KB**. Paper không nói KB có giới hạn ở 4 CWE đánh giá hay không. Nếu có giới hạn thì đó vẫn là một dạng prior từ dataset.
8. Tỉ lệ exact match / fallback, số ứng viên trung bình mỗi hàm: không báo cáo (tr. 13 nói sẽ đo trong tương lai).
9. Phạm vi "no exact candidate" là theo hàm hay theo invocation: mơ hồ (xem 2.2b).

### 6.2 Stage 2
10. Cách cài đặt slicing (dùng slice có sẵn của Joern hay tự viết), độ sâu backward/forward: không nêu.
11. Giới hạn của "bounded interprocedural" (độ sâu call graph) và tiêu chí "on demand": không nêu [tr. 6–7].
12. **Context budget**: đơn vị và giá trị không có [tr. 7, 9]. Thứ tự ưu tiên khi cắt cũng không rõ (xem 2.3c).
13. Công thức hay định nghĩa của $C_i$ cuối cùng và **format trình bày ngữ cảnh cho LLM** (có số dòng, chú thích vai trò không…): không có.
14. **Phiên bản Joern**: không ghi cho cả ARGUS lẫn baseline [tr. 9, 12].
15. Liên thủ tục cần mã của caller/callee; **artifact có kèm mã repo xung quanh không**, và ARGUS lấy caller/callee từ đâu? Paper không nói. **[SUY ĐOÁN]** Nếu artifact chỉ chứa hàm đơn lẻ thì phân tích liên thủ tục sẽ bị hạn chế.

### 6.3 Stage 3 và LLM
16. **Toàn bộ prompt** Prosecutor/Defender/Adjudicator, format output, cách parse verdict: không có.
17. Số vòng tranh luận và việc agent có thấy output của nhau không: văn bản không nói rõ; **Hình 1 cho thấy một lượt, độc lập** (xem 2.4, 2.5).
17b. Prompt của Prosecutor/Defender/Adjudicator có chứa CWE $t_i$ của ứng viên không: không nói rõ (hình không vẽ đường mang $t_i$ vào Stage 3).
18. **Qwen3-32B**: thinking mode, quantization, framework serving, max tokens, top-p, seed: không nêu. "Temperature 0 whenever supported" không nói rõ khi nào thì không hỗ trợ [tr. 9].
19. Không có ablation, không có chi phí/thời gian, không có số lần chạy hay variance.

### 6.4 Đánh giá và số liệu
20. ⚠️ Nguồn số LLMxCPG ở Bảng 5 tự mâu thuẫn ("Original paper / Local rerun" so với văn bản tr. 10, 13). Câu "same evaluation set… for our LLMxCPG experiments" ở tr. 8 không khớp với việc chưa có rerun trên PrimeVul.
21. ⚠️ ReGVD (Bảng 6): F1 không nhất quán với P và R (49.25 so với 55.00).
22. **SVEN: số dự đoán hợp lệ và lỗi pipeline không báo cáo** cho ARGUS và LLMxCPG ([SUY ĐOÁN] 192 và 238; xem 5.2), dù tr. 10 và tr. 13 cam kết báo cáo mẫu số.
23. Nguyên nhân 3 lỗi pipeline trên PrimeVul và việc chúng thuộc lớp/CWE nào: không nói ([SUY ĐOÁN] suy ngược ở 5.1, 5.3).
24. **Kết quả audit trùng lặp** (số mẫu trùng, cách chuẩn hoá mã, có loại mẫu nào không): không báo cáo [tr. 8, 13].
25. Cấu hình LLMxCPG chạy lại trên SVEN: dùng checkpoint đã phát hành hay tự fine-tune theo LoRA ở Bảng 4? Biến thể nào? Paper chỉ nhắc LLMxCPG-D [tr. 9–10]; mọi ô "Recorded…" trong Bảng 4 đều không có giá trị.
26. Mẫu benign trong artifact có phải là **bản đã vá** của chính mẫu vulnerable (dạng cặp) không: không nói. tr. 13 nhắc "vulnerable–fixed relationships are retained only as evaluation metadata" (quan hệ vulnerable–fixed chỉ giữ làm metadata đánh giá), cho thấy *có* tồn tại quan hệ cặp, nhưng tỉ lệ cặp không rõ.
27. Không có link code (bản ẩn danh); các định danh cài đặt được nói là có trong code artifact phát hành [tr. 9].
28. ~~Hình 1 không trích được chữ~~ **Đã xem Hình 1** (mục 2.5). Hình bổ sung: Prosecutor và Defender độc lập; đường "program context" tới Adjudicator; $t_i$ chỉ vào Stage 2.

---

## Phụ lục: Nhật ký đối chiếu (so với bản notes trước)

| # | Loại | Nội dung bản trước | Sửa thành |
|---|---|---|---|
| 1 | **Sai** | "Số LLMxCPG ở Bảng 5 khớp hoàn hảo với tập 80 mẫu 40/40" và coi đó là điểm lạ | Sai: với P = 100, R = 45, **mọi tập cân bằng** đều cho ACC 72.50 (brute-force ra cả nghiệm 40 mẫu lẫn 80 mẫu). Không chứng minh được gì nên đã bỏ; chỉ giữ ghi chú làm tròn 62.06/62.07 |
| 2 | **Thiếu** | Ghi "cùng tập mẫu dùng cho ARGUS và LLMxCPG" (tr. 8) mà không nêu mâu thuẫn | Thêm ⚠️ mâu thuẫn với tr. 10, 13 (mục 3.2, 6.4-20) |
| 3 | Suy đoán chưa đánh dấu | Thứ tự ưu tiên budget (1)→(4) | [SUY ĐOÁN]: paper chỉ liệt kê |
| 4 | Suy đoán chưa đánh dấu | Ký hiệu ∪ (Pt. 3) và ∈ (Pt. 2, 4) | Ghi rõ ký hiệu bị mất khi trích; [SUY ĐOÁN] |
| 5 | Suy đoán chưa đánh dấu | "Định dạng LNCS", "Hình 1 là ảnh raster" | Bỏ LNCS; Hình 1 đã được render và đọc, xem 2.5 |
| 6 | Suy đoán chưa đánh dấu | Joern `<operator>.indexAccess` | [SUY ĐOÁN, kiến thức ngoài paper] |
| 7 | **Sai** (không có trong paper) | "Biến thể LLMxCPG-D/-C" | Paper chỉ nhắc LLMxCPG-D; đã bỏ "-C" |
| 8 | Suy đoán chưa đánh dấu | "Các hàm trong artifact là hàm đơn lẻ" | [SUY ĐOÁN] và viết lại thành câu hỏi mở |
| 9 | Suy đoán chưa đánh dấu | Agent chạy một vòng, độc lập; một lần chạy, không seed | Agent một vòng, độc lập: **đã xác nhận bằng Hình 1** [HÌNH 1]. Một lần chạy, không seed: vẫn [SUY ĐOÁN] |
| 10 | Diễn đạt quá đà | Tác giả "hứa công bố" cấu hình | Paper viết hiện tại: "are reported with the released code artifact" |
| 11 | Diễn đạt quá đà | Bảng 1: "Nằm ngầm trong suy luận downstream" | Giữ nguyên văn tiếng Anh |
| 12 | Thiếu ngữ cảnh | LoRA rank 8 / alpha 4 / lr 1e-4 trình bày như cấu hình đã chạy | Ghi rõ là số "as reported by LLMxCPG", tức trích từ paper gốc |
| 13 | Thiếu | Không có mục Limitations / Threats to Validity | Thêm mục 5.6 (tr. 12–13) |
| 14 | Thiếu | Mơ hồ fallback theo hàm hay theo invocation | Thêm ⚠️ (2.2b, 6.1-9) |
| 15 | Bổ sung kiểm chứng | Ma trận nhầm lẫn suy ngược trước đó chỉ là ước lượng | Đã brute-force: mỗi trường hợp có đúng 1 nghiệm; vẫn giữ nhãn [SUY ĐOÁN] |
| — | Đúng | Mọi số trong Abstract, Bảng 3, 5, 6, 7, thống kê PrimeVul (6.968 / 6.827 / 140), "tối đa 3", Qwen3-32B, temperature 0, QwQ-32B-Preview, LoRA 8/4/1e-4 | Khớp paper, giữ nguyên |
| 16 | Bổ sung từ hình | Hình 1 chưa được xem | Đã render và đọc Hình 1: thêm mục 2.5, xác nhận Prosecutor/Defender độc lập một lượt, sửa 2.4, 6.3-17, 6.4-28 |
