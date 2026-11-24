# Cấu trúc cơ sở dữ liệu CVEfixes v1.0.8

- File: `cvefixes_work/db/CVEfixes.db`, 51,688,558,592 byte (48.14 GiB), dựng từ `CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz` (382,923 câu lệnh SQL, 48.24 GiB văn bản SQL).
- Số câu lệnh có byte không phải UTF-8 hợp lệ (đã thay bằng U+FFFD): 0.

## 1. Các bảng

| bảng | số dòng | số cột |
|---|---|---|
| commits | 12,107 | 16 |
| cve | 11,873 | 34 |
| cwe | 272 | 7 |
| cwe_classification | 12,198 | 2 |
| file_change | 51,342 | 16 |
| fixes | 12,923 | 3 |
| method_change | 277,948 | 13 |
| repository | 4,249 | 10 |

Chỉ mục / view / trigger: không có.

### `commits`

| # | cột | kiểu khai báo | NOT NULL | khóa chính |
|---|---|---|---|---|
| 0 | hash | TEXT | 0 | 0 |
| 1 | repo_url | TEXT | 0 | 0 |
| 2 | author | TEXT | 0 | 0 |
| 3 | author_date | TEXT | 0 | 0 |
| 4 | author_timezone | TEXT | 0 | 0 |
| 5 | committer | TEXT | 0 | 0 |
| 6 | committer_date | TEXT | 0 | 0 |
| 7 | committer_timezone | TEXT | 0 | 0 |
| 8 | msg | TEXT | 0 | 0 |
| 9 | merge | TEXT | 0 | 0 |
| 10 | parents | TEXT | 0 | 0 |
| 11 | num_lines_added | TEXT | 0 | 0 |
| 12 | num_lines_deleted | TEXT | 0 | 0 |
| 13 | dmm_unit_complexity | TEXT | 0 | 0 |
| 14 | dmm_unit_interfacing | TEXT | 0 | 0 |
| 15 | dmm_unit_size | TEXT | 0 | 0 |

### `cve`

| # | cột | kiểu khai báo | NOT NULL | khóa chính |
|---|---|---|---|---|
| 0 | cve_id | TEXT | 0 | 0 |
| 1 | published_date | TEXT | 0 | 0 |
| 2 | last_modified_date | TEXT | 0 | 0 |
| 3 | description | TEXT | 0 | 0 |
| 4 | nodes | TEXT | 0 | 0 |
| 5 | severity | TEXT | 0 | 0 |
| 6 | obtain_all_privilege | TEXT | 0 | 0 |
| 7 | obtain_user_privilege | TEXT | 0 | 0 |
| 8 | obtain_other_privilege | TEXT | 0 | 0 |
| 9 | user_interaction_required | TEXT | 0 | 0 |
| 10 | cvss2_vector_string | TEXT | 0 | 0 |
| 11 | cvss2_access_vector | TEXT | 0 | 0 |
| 12 | cvss2_access_complexity | TEXT | 0 | 0 |
| 13 | cvss2_authentication | TEXT | 0 | 0 |
| 14 | cvss2_confidentiality_impact | TEXT | 0 | 0 |
| 15 | cvss2_integrity_impact | TEXT | 0 | 0 |
| 16 | cvss2_availability_impact | TEXT | 0 | 0 |
| 17 | cvss2_base_score | TEXT | 0 | 0 |
| 18 | cvss3_vector_string | TEXT | 0 | 0 |
| 19 | cvss3_attack_vector | TEXT | 0 | 0 |
| 20 | cvss3_attack_complexity | TEXT | 0 | 0 |
| 21 | cvss3_privileges_required | TEXT | 0 | 0 |
| 22 | cvss3_user_interaction | TEXT | 0 | 0 |
| 23 | cvss3_scope | TEXT | 0 | 0 |
| 24 | cvss3_confidentiality_impact | TEXT | 0 | 0 |
| 25 | cvss3_integrity_impact | TEXT | 0 | 0 |
| 26 | cvss3_availability_impact | TEXT | 0 | 0 |
| 27 | cvss3_base_score | TEXT | 0 | 0 |
| 28 | cvss3_base_severity | TEXT | 0 | 0 |
| 29 | exploitability_score | TEXT | 0 | 0 |
| 30 | impact_score | TEXT | 0 | 0 |
| 31 | ac_insuf_info | TEXT | 0 | 0 |
| 32 | reference_json | TEXT | 0 | 0 |
| 33 | problemtype_json | TEXT | 0 | 0 |

### `cwe`

| # | cột | kiểu khai báo | NOT NULL | khóa chính |
|---|---|---|---|---|
| 0 | index | INTEGER | 0 | 0 |
| 1 | cwe_id | TEXT | 0 | 0 |
| 2 | cwe_name | TEXT | 0 | 0 |
| 3 | description | TEXT | 0 | 0 |
| 4 | extended_description | TEXT | 0 | 0 |
| 5 | url | TEXT | 0 | 0 |
| 6 | is_category | INTEGER | 0 | 0 |

### `cwe_classification`

| # | cột | kiểu khai báo | NOT NULL | khóa chính |
|---|---|---|---|---|
| 0 | cve_id | TEXT | 0 | 0 |
| 1 | cwe_id | TEXT | 0 | 0 |

### `file_change`

| # | cột | kiểu khai báo | NOT NULL | khóa chính |
|---|---|---|---|---|
| 0 | file_change_id | TEXT | 0 | 0 |
| 1 | hash | TEXT | 0 | 0 |
| 2 | filename | TEXT | 0 | 0 |
| 3 | old_path | TEXT | 0 | 0 |
| 4 | new_path | TEXT | 0 | 0 |
| 5 | change_type | TEXT | 0 | 0 |
| 6 | diff | TEXT | 0 | 0 |
| 7 | diff_parsed | TEXT | 0 | 0 |
| 8 | num_lines_added | TEXT | 0 | 0 |
| 9 | num_lines_deleted | TEXT | 0 | 0 |
| 10 | code_after | TEXT | 0 | 0 |
| 11 | code_before | TEXT | 0 | 0 |
| 12 | nloc | TEXT | 0 | 0 |
| 13 | complexity | TEXT | 0 | 0 |
| 14 | token_count | TEXT | 0 | 0 |
| 15 | programming_language | TEXT | 0 | 0 |

### `fixes`

| # | cột | kiểu khai báo | NOT NULL | khóa chính |
|---|---|---|---|---|
| 0 | cve_id | TEXT | 0 | 0 |
| 1 | hash | TEXT | 0 | 0 |
| 2 | repo_url | TEXT | 0 | 0 |

### `method_change`

| # | cột | kiểu khai báo | NOT NULL | khóa chính |
|---|---|---|---|---|
| 0 | method_change_id | TEXT | 0 | 0 |
| 1 | file_change_id | TEXT | 0 | 0 |
| 2 | name | TEXT | 0 | 0 |
| 3 | signature | TEXT | 0 | 0 |
| 4 | parameters | TEXT | 0 | 0 |
| 5 | start_line | TEXT | 0 | 0 |
| 6 | end_line | TEXT | 0 | 0 |
| 7 | code | TEXT | 0 | 0 |
| 8 | nloc | TEXT | 0 | 0 |
| 9 | complexity | TEXT | 0 | 0 |
| 10 | token_count | TEXT | 0 | 0 |
| 11 | top_nesting_level | TEXT | 0 | 0 |
| 12 | before_change | TEXT | 0 | 0 |

### `repository`

| # | cột | kiểu khai báo | NOT NULL | khóa chính |
|---|---|---|---|---|
| 0 | repo_url | TEXT | 0 | 0 |
| 1 | repo_name | TEXT | 0 | 0 |
| 2 | description | TEXT | 0 | 0 |
| 3 | date_created | TEXT | 0 | 0 |
| 4 | date_last_push | TEXT | 0 | 0 |
| 5 | homepage | TEXT | 0 | 0 |
| 6 | repo_language | TEXT | 0 | 0 |
| 7 | owner | TEXT | 0 | 0 |
| 8 | forks_count | TEXT | 0 | 0 |
| 9 | stars_count | TEXT | 0 | 0 |

## 2. So với mô tả ở mục 5 của đặc tả

Mọi bảng và cột nêu ở mục 5 đều có, đúng tên.

Bảng có thêm ngoài mục 5: `cve`, `cwe`, `repository`.

## 3. Giá trị của `method_change.before_change`

| giá_trị | kiểu_lưu | số_dòng |
|---|---|---|
| False | text | 151349 |
| True | text | 126599 |

## 4. Khóa nối giữa các bảng

`method_change.file_change_id`:

| kiểu | n | n_khác_nhau |
|---|---|---|
| text | 277948 | 25010 |

`file_change.file_change_id`: kiểu pandas `str`, 51,342 dòng, 51,342 giá trị khác nhau (duy nhất).

`method_change.method_change_id`: 277,948 dòng, 277,948 giá trị khác nhau.

- Dòng `method_change` không tìm thấy `file_change_id` trong `file_change`: 0 / 277,948.
- `fixes`: 12,923 dòng; 12,923 bộ (cve_id, hash, repo_url) khác nhau; 11,873 CVE; 12,103 hash; 4,249 repo.
- Hash trong `fixes` xuất hiện ở **nhiều hơn một `repo_url`**: 4 hash (tối đa 2 repo cho một hash).
- Hash gắn với nhiều hơn một CVE: 508 (tối đa 21 CVE cho một hash).
- `commits`: 12,107 dòng; 12,103 hash khác nhau; 12,107 cặp (hash, repo_url) khác nhau.
- `file_change`: 51,342 dòng; 11,185 hash khác nhau; hash không có trong `commits`: 0; hash không có trong `fixes`: 0.
- `file_change` **không có** cột `repo_url`, nên từ `file_change` chỉ nối được sang `fixes`/`commits` theo `hash`.
- Hash trong `fixes` không có `file_change` nào: 918 / 12,103.
- `cwe_classification`: 12,198 dòng; 11,873 CVE; CVE có nhiều hơn một CWE: 305; CVE của `fixes` không có dòng CWE: 0.
- Giá trị `cwe_id` hay gặp: `CWE-79` (1,794), `NVD-CWE-noinfo` (1,162), `CWE-125` (553), `CWE-787` (450), `CWE-20` (408), `CWE-89` (403), `CWE-119` (384), `CWE-22` (383).

## 5. Ngôn ngữ (`file_change.programming_language`)

| programming_language | giữ (7 ngôn ngữ MVD) | số file_change | hàm before_change=False | hàm before_change=True |
|---|---|---|---|---|
| PHP |  | 12464 | 23499 | 4758 |
| C | có | 6220 | 8410 | 6241 |
| unknown |  | 4126 | 0 | 16123 |
| JavaScript | có | 3656 | 91929 | 82999 |
| Markdown |  | 2942 | 2388 | 2403 |
| Python | có | 2753 | 4793 | 2775 |
| Java | có | 2571 | 5285 | 3102 |
| TypeScript |  | 2563 | 1909 | 1039 |
| C++ | có | 2252 | 3351 | 2058 |
| Go | có | 1919 | 4403 | 1880 |
| Ruby |  | 1917 | 2621 | 1462 |
| HTML |  | 1499 | 169 | 164 |
| Shell |  | 1081 | 36 | 30 |
| CoffeeScript |  | 735 | 78 | 52 |
| SQL |  | 685 | 38 | 23 |
| C# | có | 484 | 724 | 470 |
| Batchfile |  | 457 | 2 | 1 |
| Scala |  | 395 | 379 | 232 |
| Lua |  | 393 | 101 | 73 |
| Perl |  | 341 | 59 | 23 |
| Rust |  | 331 | 468 | 327 |
| Objective-C |  | 328 | 349 | 263 |
| CSS |  | 319 | 0 | 0 |
| Haskell |  | 157 | 5 | 3 |
| Matlab |  | 148 | 31 | 10 |
| TeX |  | 142 | 7 | 2 |
| PowerShell |  | 139 | 43 | 4 |
| Swift |  | 133 | 268 | 79 |
| Jupyter Notebook |  | 104 | 1 | 1 |
| R |  | 68 | 0 | 0 |
| Erlang |  | 11 | 2 | 2 |
| None |  | 9 | 1 | 0 |

### Đối chiếu với đuôi file (7 ngôn ngữ được giữ)

| ngôn ngữ | số file_change | đuôi file (số file) | file có đuôi không khớp |
|---|---|---|---|
| C | 6,220 | .c (5,110), .h (913), .cc (42), .cpp (24), .cxx (20), .s (17), .in (11), .pro (11), .patch (7), .l (6), .re (5), .xs (5), .hh (4), .y (4), .vim (4), (không đuôi) (3), .v (3), .hpp (2), .txt (2), .edl (2), .vala (2), .js (2), .fs (2), .rb (2), .ftl (2), .ac (1), .pgc (1), .out (1), .c++ (1), .pp (1), .sp (1), .def (1), .inc (1), .rl (1), .ci (1), .license (1), .go (1), .pas (1), .py (1), .lex (1) | 197 |
| C++ | 2,252 | .cc (803), .cpp (522), .h (383), .c (370), .cxx (34), .hpp (33), .css (26), .scss (16), .hh (12), .c++ (9), .js (8), .php (4), .csproj (4), .inc (4), .rc (3), .in (2), .t (2), .ycp (1), .xst (1), .java (1), .map (1), .l (1), (không đuôi) (1), .result (1), .conf (1), .vala (1), .patch (1), .gradle (1), .kts (1), .clif (1), .v (1), .ipp (1), .yxx (1), .rs (1) | 455 |
| C# | 484 | .cs (437), .xml (11), .cshtml (9), .h (6), .java (5), .csproj (4), .map (3), .config (2), .sln (2), .c (2), .in (1), (không đuôi) (1), .skin (1) | 47 |
| Go | 1,919 | .go (1,766), .mod (30), .sum (27), .json (19), .js (11), (không đuôi) (8), .cs (5), .out (5), .c (5), .h (4), .clif (4), .txt (3), .s (3), .man (3), .pem (3), .am (2), .html (2), .ts (2), .lock (2), .awk (1), .gitignore (1), .prettierignore (1), .boot (1), .rb (1), .toml (1), .eslintrc (1), .skin (1), .py (1), .md (1), .proto (1), .neon (1), .mzn (1), .sol (1), .in (1) | 153 |
| Java | 2,571 | .java (2,436), (không đuôi) (62), .mf (10), .c (9), .as (9), .php (9), .vala (5), .aj (5), .groovy (3), .ejs (3), .jsp (3), .ts (3), .log (2), .h (2), .sol (2), .cs (2), .xmi (1), .cls (1), .cpp (1), .html (1), .json (1), .prefs (1) | 135 |
| JavaScript | 3,656 | .js (2,653), .json (459), .ts (97), .htm (88), .map (42), .php (35), .result (31), .jsx (28), .tt (25), .html (18), .vue (16), .c (14), .mjs (12), .lock (11), .svg (9), .ser (8), .dart (6), .sol (6), .txt (5), .pbtxt (5), (không đuôi) (5), .twig (4), .xml (4), .gradle (4), .tsx (4), .jsp (3), .py (3), .proto (3), .md (3), .cjs (3), .gitattributes (3), .go (3), .mts (3), .h (2), .eslintrc (2), .nix (2), .es6 (2), .tpl (2), .libsonnet (2), .jsm (2), .rdoc (1), .cpp (1), .as (1), .out (1), .css (1), .ctp (1), .pbxproj (1), .jshintrc (1), .po (1), .cc (1), .response (1), .groovy (1), .t (1), .rb (1), .properties (1), .jison (1), .less (1), .strings (1), .tcl (1), .include (1), .yml (1), .cshtml (1), .removed (1), .rs (1), .jsonc (1), .svelte (1), .kt (1), .nycrc (1), .parcelrc (1) | 960 |
| Python | 2,753 | .py (2,412), .svg (51), .po (44), (không đuôi) (41), .txt (27), .vim (19), .json (15), .lock (14), .yaml (12), .toml (12), .yml (9), .php (8), .vm (7), .html (5), .ac (4), .build (4), .rst (4), .nim (4), .pyx (4), .htmlt (4), .md (4), .conf (3), .js (3), .pxi (3), .cairo (3), .h (2), .expect (2), .expectf (2), .ini (2), .out (2), .in (2), .exs (2), .tt (2), .css (2), .cfg (2), .properties (1), .log (1), .pyj (1), .bzl (1), .cgi (1), .doctest (1), .patch (1), .rb (1), .c (1), .graphql (1), .diff (1), .scm (1), .rs (1), .h2 (1), .postgres (1), .j2 (1), .erb (1) | 341 |

File **không** được gán một trong 7 ngôn ngữ nhưng có đuôi của ngôn ngữ đó: C: 587, C++: 70, C#: 18, Go: 51, Java: 45, JavaScript: 1,083, Python: 56.

## 6. Đường dẫn và loại thay đổi trong `file_change`

- `new_path`: NULL 0, chuỗi `'None'` 4,124, rỗng 0.
- `old_path`: NULL 0, chuỗi `'None'` 9,269, rỗng 0.
- `filename`: NULL 0, chuỗi `'None'` 0, rỗng 0.
- `change_type`: `ModificationType.MODIFY` 37,639, `ModificationType.ADD` 9,269, `ModificationType.DELETE` 4,124, `ModificationType.RENAME` 310.

## 7. Kiểm tra ý nghĩa của `before_change` trên mẫu

Lấy ngẫu nhiên (seed 20261115) 300 hàm mỗi giá trị `before_change` trong 7 ngôn ngữ, rồi kiểm tra `code` của hàm (đã chuẩn hóa xuống dòng, bỏ khoảng trắng hai đầu từng dòng) có nằm trong `code_before` hay `code_after` của file tương ứng.

| before_change | số mẫu | chỉ trong code_before | chỉ trong code_after | trong cả hai | không thấy ở bản nào |
|---|---|---|---|---|---|
| False | 300 | 0 | 299 | 1 | 0 |
| True | 300 | 296 | 0 | 4 | 0 |

