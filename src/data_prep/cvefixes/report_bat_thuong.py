"""Văn bản mục 5 của data_report.md (Bất thường, giả định, sai khác so với đặc tả).

Do người viết, ghi lại các quyết định người dùng đã duyệt; 11_report.py chèn nguyên văn vào báo cáo. Để ở dạng module
Python (không phải file .md riêng) để gói gửi đi không chứa hai bản của cùng một đoạn văn.
"""

TEXT = r"""
### 5.1. Sai khác có chủ đích so với đặc tả gốc (người dùng đã duyệt ngày 16/11/2026)

Các điểm dưới đây **không có trong quy trình MVD**; khi so sánh kết quả CVEfixes với MVD cần nhớ chúng.

1. **Ngôn ngữ (bước A + B).** Bước A giữ dòng có `file_change.programming_language` thuộc 7 ngôn ngữ (bỏ 59.528 dòng). Bước B lấy ngôn ngữ theo đuôi file khi đuôi rõ ràng (`.c`→C; `.cc .cpp .cxx .c++ .hpp .hh .hxx`→C++; `.cs`→C#; `.go`→Go; `.java`→Java; `.js .mjs .cjs .jsx`→JavaScript; `.py`→Python). Đuôi rõ ràng của ngôn ngữ/định dạng khác thì bỏ dòng (118 dòng, trong đó 91 dòng `.ts` bị CVEfixes gán JavaScript). Đuôi không rõ (`.h`, `.inc`, không đuôi, `.in`, `.inl`, `.ipp`, `.tcc`, `.tpp`, `.h++`, `.pyw`, `.es6`, `.jsm`) thì giữ theo `programming_language`. Có 1.194 dòng đổi ngôn ngữ, lớn nhất là 900 dòng file `.c` bị gán C++ (→ C) và 187 dòng `.cc/.cxx/.cpp` bị gán C (→ C++). Bảng chéo đầy đủ và bảng đối chiếu với bước 3 ở mục 3.1; script `05_extract.py` có `assert` cho đối chiếu này. Đuôi lấy từ phần sau dấu chấm cuối cùng của tên file, chữ thường, nên `.d.ts` được tính là `.ts`.
2. **Quy tắc R0: mã sinh tự động, mã đóng gói, thư viện chép vào.** Một dòng bị đánh dấu nếu thỏa ít nhất một điều kiện: (a) đường dẫn chứa thư mục `node_modules|bower_components|vendor|third_party|dist`; (b) tên file `.min.js`, `-min.js`, `.bundle.js`, `-bundle.js`, `.pack.js`, `.packed.js`; (c) hàm có dòng dài hơn 1.000 ký tự; (d) file_change có hơn 300 dòng `method_change` (ngưỡng 300 đã chọn sau khi xem ngưỡng 100 và 1.000). Bước 4 chỉ đánh dấu (`r0_reason`), bước 5 bỏ trước khi tính `unit_id`. R0 bỏ 168.580 / 218.302 dòng thô (77,2%), trong đó 167.237 dòng JavaScript (95,6% số dòng JavaScript): JavaScript của CVEfixes chủ yếu là file gộp/minified, ví dụ `mermaid.min.js` một mình có 19.042 hàm. Sau R0, JavaScript còn 7.620 dòng.
   - **Go mất 21,2% vì R0, vượt ngưỡng dừng 20%; người dùng đã duyệt giữ nguyên.** 1.319 / 1.325 dòng Go bị bỏ đến từ đúng một commit: `5016fb8d7cdff38c79e22e8293e58300f8d3bd57` của BishopFox/sliver (CVE-2024-41111). Commit này chép nguyên thư viện `vendor/github.com/tetratelabs/wazero/...` (101 file mới, change_type ADD, toàn bộ target=0). Không kể commit này thì R0 chỉ bỏ 0,1% số dòng Go. Script giữ điều kiện dừng 20% nhưng miễn riêng commit này.
   - Các ngôn ngữ khác mất dưới 0,3% vì R0.
   - **Còn sót thư viện chép vào ngoài thư mục vendor** (DOMPurify `purify*.js`, `katex/contrib/mhchem.js`, `marked.js`, `jquery-ui.js`, `ckeditor/.../wsc.js`, `mxgraph/mxClient.js`, ...). Theo quyết định của người dùng, không lọc thêm theo tên file mà đánh dấu để phân tích độ nhạy (mục 4).
3. **`n_vuln_funcs_in_commit` tính sau R0**: số `unit_id` khác nhau có target=1 trong cùng `commit_hash`, trên mọi dòng `method_change` (kể cả ngoài 7 ngôn ngữ và dòng bị bỏ ở bước B), trừ dòng R0 và hàm rỗng. `n_vuln_funcs_in_commit_raw` tính trước R0 để đối chiếu. Không dùng để lọc.
4. **Cột đánh dấu bổ sung trong `units_v1.parquet` (chỉ đánh dấu, không lọc; script `10b_flags_len768.py`):**
   - `n_tokens`: độ dài token UniXcoder của bước 9.
   - `is_paired`: đúng nếu ở ít nhất một lần xuất hiện, trong cùng `file_change` có dòng thô mang nhãn ngược lại và cùng `method_name`. Cách tính như mục 6.6 (chỉ xét dòng không bị R0) nhưng áp dụng cho cả nhãn 1 và nhãn 0. 32.555 / 46.411 đơn vị v1 có `is_paired` đúng. Trong phần ghép được, tỷ lệ nhãn 1 gần 50%; phần không ghép được chủ yếu là nhãn 0 (khoảng 14% nhãn 1), vì hàm mới thêm hoặc đổi tên trong commit vá không có bản trước (mục 3.7).
   - `cvefixes_only_eval`: `in_mvd_cve` sai và `in_mvd_func` sai. Đây là tập kiểm tra cho thí nghiệm "huấn luyện trên MVD, kiểm tra trên CVEfixes"; 9 đơn vị v2 trùng hàm với MVD nhưng khác CVE đã bị loại khỏi tập này.
5. **Tập `groups_and_folds_cvefixes_v2_len768.csv`** = file fold v2 bỏ các đơn vị có `n_tokens` > 768, giữ nguyên mọi cột và giá trị (fold, group, inner_val giữ như v2, không chia lại). Lý do: MVD không có hàm nào dài quá 768 token, nên đây là tập chính khi so sánh với MVD. Bỏ 8.177 / 36.748 đơn vị v2 (22,3%), nhiều nhất ở C (4.905 đơn vị, 35,6%). Mỗi ngôn ngữ ở mỗi fold vẫn đủ hai nhãn ở train, validation và test (đã `assert`). Vì không chia lại, cỡ fold và cỡ validation nội bộ của v2_len768 không còn cân bằng như v2.
6. **Tập `groups_and_folds_cvefixes_v2_len768_paired.csv`** = file fold v2_len768 chỉ giữ đơn vị có `is_paired` đúng, giữ nguyên mọi cột và giá trị, không chia lại fold. Lý do: MVD gần như chỉ gồm cặp trước/sau với tỷ lệ nhãn 1 khoảng 50%, nên đây là **tập chính khi so sánh với MVD**. Còn 19.907 / 28.571 đơn vị; tỷ lệ nhãn 1 là 49,8% (48,7–50,3% tùy ngôn ngữ). Trong đó 12.982 đơn vị có `cvefixes_only_eval` đúng (tỷ lệ nhãn 1 là 49,8%). Mỗi ngôn ngữ ở mỗi fold vẫn đủ hai nhãn ở train, validation và test (đã `assert`; script dừng và không ghi file nếu có ô thiếu nhãn). Ô nhỏ nhất là validation nội bộ của C# ở fold 2 (8 nhãn 1, 9 nhãn 0): chỉ số đánh giá trên validation của C# sẽ dao động nhiều (mục 3.7).

Cột bổ sung ngoài danh sách của đặc tả:
- `raw_functions.parquet`: `r0_reason`, `n_vuln_funcs_in_commit_raw`, `unit_id`, `is_empty`, `max_line_len`, `n_methods_in_file_change`, `method_change_id`, `file_change_id`, `programming_language` (gốc), `file_ext`, `change_type` (lấy nguyên từ `file_change`, dạng `ModificationType.ADD` ...).
- `units_v1.parquet`: `n_vuln_funcs_in_commit_raw` (lớn nhất qua các lần xuất hiện), `change_types` (các change_type khác nhau, ngăn bởi `;`), `in_mvd_cve`, `in_mvd_func` (bước 8, `09_mvd_compare.py`), `n_tokens`, `is_paired`, `cvefixes_only_eval` (bước 9b, `10b_flags_len768.py`). Chạy lại `06_units_v1.py` thì phải chạy lại cả các bước sau.
- `units_v1.csv.gz`: cùng nội dung `units_v1.parquet` (đủ mọi cột, kể cả `func`), UTF-8, để kiểm tra độc lập; script đọc lại và `assert` `unit_id`, `func` khớp parquet. Không có trong file zip.

### 5.2. Cấu trúc dữ liệu khác mô tả và giả định đã đưa ra

- **Gói v1.0.8 không có sẵn `CVEfixes.db`**, chỉ có bản dump SQL nén `Data/CVEfixes_v1.0.8.sql.gz`. Cơ sở dữ liệu được dựng lại đúng như `INSTALL.md` hướng dẫn (dump → sqlite3), đọc thẳng từ zip: 382.923 câu lệnh, 0 câu lệnh lỗi UTF-8, `PRAGMA quick_check` = ok.
- Bảng và cột khớp mục 5 của đặc tả; có thêm bảng `cve`, `cwe`, `repository` (không dùng).
  - Mọi cột khai báo TEXT, không có khóa chính hay chỉ mục.
  - `before_change` là chuỗi `'True'`/`'False'`; trên mẫu 300 hàm mỗi loại, hàm `'True'` nằm trong `code_before`, hàm `'False'` nằm trong `code_after` (schema.md mục 7).
  - Đường dẫn trống lưu là chuỗi `'None'` (không phải NULL) và được coi là trống.
  - `change_type` có dạng `ModificationType.MODIFY/ADD/DELETE/RENAME`.
- **`file_change` không có `repo_url`**, nên chỉ nối được sang `fixes` theo `hash`:
  - 4 hash xuất hiện ở 2 `repo_url`. Ba hash chỉ khác chữ hoa/thường hoặc tên chủ repo: anything-llm (mintplex-labs / Mintplex-Labs), pyrad (wichert / pyradius), alltube (rudloff / Rudloff). Hash còn lại là cùng commit trên Bitbucket và GitHub (snakeyaml).
  - 508 hash gắn với nhiều CVE (tối đa 21).
  - Hàm của các commit này nhận **toàn bộ** CVE, CWE và repo của hash: lưu dạng danh sách ngăn bởi `;` ở dòng thô, rồi tách ra trước khi gộp ở bước 5. Hệ quả là các CVE cùng commit được nối thành một cụm ở bước 6.
- `raw_id` = `rowid` của dòng `method_change` trong cơ sở dữ liệu (thứ tự của bản dump). Mỗi dòng `method_change` là một dòng thô, không nhân dòng theo số CVE.
- **Hàm thuộc file bị xóa có `programming_language = 'unknown'`** (16.123 dòng, toàn target=1, 16.116 dòng thuộc change_type DELETE) và bị bỏ ở bước A (đã duyệt), dù 8.993 dòng trong đó là file `.js` và 249 dòng là file `.c`.
- Không có hàm rỗng sau chuẩn hóa trong các dòng còn lại sau R0.
- **Tỷ lệ ghép cặp** (mục 6.6) là 86–95% tùy ngôn ngữ. Khoảng 10% hàm target=1 không có hàm target=0 cùng tên trong cùng file: hàm bị xóa hoặc đổi tên trong commit vá.

### 5.3. Điểm lạ trong kết quả

- **R2 loại nhiều hơn MVD ở Python (42,6%), Java (33,2%), Go (30,9%)** vì CVEfixes có đường dẫn file nên áp dụng được R2 theo đường dẫn: 3.407 đơn vị bị loại chỉ vì đường dẫn, còn MVD không có đường dẫn. 30 mẫu ngẫu nhiên trong `audit_r2_sample.md` đều nằm trong thư mục hoặc file kiểm thử thật (`src/test/java/...`, `*_test.go`, `tests/test_*.py`). Tổng v2 loại 20,8% đơn vị v1, gần mức ~20% của MVD v2.
- **Hai cụm khổng lồ:** C++ cụm CVE-2020-15211 (tensorflow, 532 đơn vị, 12% số đơn vị C++) và C# cụm CVE-2017-16806 (Ulterius/server, 156 đơn vị, 15% số đơn vị C#). Theo `build_folds.py`, chúng không bao giờ nằm trong validation nội bộ.
- **Hàm C dài:** trung vị 506 token và 35,6% đơn vị C v2 vượt 768 token, cao hơn hẳn các ngôn ngữ khác (Java 7,3%, C# 8,6%). Vì vậy v2_len768 mất nhiều đơn vị C nhất (mục 5.1, điểm 5).
- **Rò rỉ tiềm ẩn ở tập "CVE mới":** 9 đơn vị v2 có `in_mvd_cve` sai nhưng `in_mvd_func` đúng (cùng hàm, khác CVE). Cột `cvefixes_only_eval` đã loại 9 đơn vị này (25.455 đơn vị v2, 19.008 đơn vị v2_len768; mục 3.7).
- **`raw_functions.parquet` chỉ khoảng 0,3 GiB** dù cột `code` thô là 42,9 GiB: phần lớn là hàm lồng nhau trong file JavaScript minified, lặp lại rất nhiều nên nén zstd rất tốt. `unit_id` được tính lại từ `func` đọc ra ở bước 5 và khớp với giá trị bước 4 ở mọi dòng không bị R0.

### 5.4. Môi trường và các việc chưa làm

- **pandas 3.1.1, pyarrow 26.0.1, Python 3.13.15** (`environment.txt`). Đặc tả không ghim phiên bản. `clean_rules.py` và `build_folds.py` chạy không cảnh báo, và `build_folds.build` chạy hai lần cho kết quả giống hệt (đã `assert`). Tuy nhiên không kiểm tra lại được việc chúng tái tạo đúng file fold MVD dưới các phiên bản này, vì gói không chứa tập đơn vị đầy đủ của MVD.
- **Tokenizer:** transformers 5.23.0, tokenizers 0.23.3, lớp `RobertaTokenizer`, revision cố định như mục 11. Không cài PyTorch (không cần cho tokenizer).
- **RAM 15,2 GB nhưng chỉ khoảng 1,5 GB trống khi chạy:** mọi bước đọc `method_change` theo khối 100 dòng (giá trị `code` lớn nhất 3,7 MB) và không giữ cột `code` của cả bảng trong bộ nhớ. Hai truy vấn gom nhóm trong SQL có đụng tới cột `code` đã báo hết bộ nhớ nên không dùng.
- **Mục 14.2 (dataset riêng tư trên Kaggle `cvefixes-v2-inputs`) chưa làm:** máy chưa cài kaggle CLI và không có `~/.kaggle/kaggle.json`. Cần tải lên tay: `units_v1.parquet`, `groups_and_folds_cvefixes_v1.csv`, `groups_and_folds_cvefixes_v2.csv`, `groups_and_folds_cvefixes_v2_len768.csv`, `groups_and_folds_cvefixes_v2_len768_paired.csv`.
"""
