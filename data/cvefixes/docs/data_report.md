# Báo cáo dữ liệu CVEfixes v2 (đề tài CNTT-2026-50)

Ngày tạo báo cáo: 2026-11-16. Mọi số liệu do các script trong `scripts/` sinh ra; chạy lại theo thứ tự `01` → `10`, `10b`, `11`, `12` cho cùng kết quả.

## 1. Nguồn dữ liệu

| mục | giá trị |
|---|---|
| Bộ dữ liệu | CVEfixes v1.0.8 (công bố 2024-07-28), DOI 10.5281/zenodo.13118970 |
| Nguồn | https://zenodo.org/records/13118970 |
| File tải | `CVEfixes_v1.0.8.zip`, 12,708,711,268 byte (11.84 GiB) |
| MD5 (Zenodo / tính lại) | `4586a358977acfa4c60b1a2cdd096221` / `4586a358977acfa4c60b1a2cdd096221` (khớp) |
| Ngày tải | 2026-11-16 |
| Bản dump SQL trong zip | `CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz`: 12,660,640,828 byte nén; 51,797,823,337 byte (48.24 GiB) sau giải nén (đọc thẳng từ zip, không ghi ra đĩa) |
| Cơ sở dữ liệu SQLite | `cvefixes_work/db/CVEfixes.db`, 51,688,558,592 byte (48.14 GiB), 382,923 câu lệnh SQL, PRAGMA quick_check = ok |
| Dung lượng đĩa cần | khoảng 60 GiB (zip + SQLite), cộng `raw_functions.parquet` 0.3 GiB |

## 2. Số lượng qua từng bước

Số dòng (đến `sau bỏ unit_id mâu thuẫn`) hoặc số đơn vị (bốn hàng cuối), theo ngôn ngữ và nhãn:

| bước | C t=1 | C t=0 | C++ t=1 | C++ t=0 | C# t=1 | C# t=0 | Go t=1 | Go t=0 | Java t=1 | Java t=0 | JavaScript t=1 | JavaScript t=0 | Python t=1 | Python t=0 | tổng | bị bỏ | lý do |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| method_change thuộc 7 ngôn ngữ (theo programming_language) | 6,241 | 8,410 | 2,058 | 3,351 | 470 | 724 | 1,880 | 4,403 | 3,102 | 5,285 | 82,999 | 91,929 | 2,775 | 4,793 | 218,420 |  | bảng có 277,948 dòng; bước A bỏ 59,528 dòng của ngôn ngữ khác |
| sau bước A, B (dòng thô, raw_functions.parquet) | 6,571 | 8,812 | 1,740 | 2,950 | 477 | 730 | 1,862 | 4,381 | 3,093 | 5,279 | 82,965 | 91,892 | 2,771 | 4,779 | 218,302 | 118 | bước B: chuyển ngôn ngữ theo đuôi file, bỏ đuôi của ngôn ngữ/định dạng khác |
| sau bỏ R0 | 6,570 | 8,811 | 1,735 | 2,945 | 477 | 730 | 1,859 | 3,059 | 3,092 | 5,278 | 2,730 | 4,890 | 2,769 | 4,777 | 49,722 | 168,580 | R0 a/b/c/d |
| sau bỏ hàm rỗng | 6,570 | 8,811 | 1,735 | 2,945 | 477 | 730 | 1,859 | 3,059 | 3,092 | 5,278 | 2,730 | 4,890 | 2,769 | 4,777 | 49,722 | 0 | rỗng sau chuẩn hóa |
| sau bỏ unit_id mâu thuẫn | 6,272 | 8,509 | 1,639 | 2,843 | 433 | 686 | 1,829 | 3,029 | 2,922 | 5,108 | 2,602 | 4,763 | 2,616 | 4,620 | 47,871 | 1,851 | cả hai nhãn hoặc nhiều ngôn ngữ |
| units_v1 (đơn vị) | 6,173 | 8,370 | 1,622 | 2,798 | 410 | 660 | 1,670 | 2,868 | 2,829 | 4,926 | 2,515 | 4,388 | 2,596 | 4,586 | 46,411 |  | gộp dòng cùng unit_id |
| v2 (đơn vị) | 5,852 | 7,910 | 1,460 | 2,347 | 393 | 602 | 1,137 | 2,000 | 2,035 | 3,148 | 2,046 | 3,693 | 1,633 | 2,492 | 36,748 | 9,663 | R1, R2, R3 |
| v2_len768 (đơn vị) | 3,777 | 5,080 | 1,064 | 1,685 | 352 | 557 | 999 | 1,812 | 1,865 | 2,938 | 1,670 | 3,205 | 1,404 | 2,163 | 28,571 | 8,177 | n_tokens > 768 (sai khác có chủ đích, mục 5.1) |
| v2_len768_paired (đơn vị) | 3,399 | 3,381 | 998 | 987 | 309 | 326 | 872 | 881 | 1,697 | 1,759 | 1,379 | 1,389 | 1,260 | 1,270 | 19,907 | 8,664 | is_paired sai (sai khác có chủ đích, mục 5.1) |

Chi tiết lý do loại ở từng bước nằm trong mục 3. Bước 5 loại 888 unit_id mang cả hai nhãn (1,807 dòng) và 22 unit_id ở nhiều ngôn ngữ (44 dòng).

## 3. Chi tiết từng bước

Bao gồm: tỷ lệ ghép cặp (mục 12.3) ở 3.1, phân bố `n_vuln_funcs_in_commit` (mục 12.4) ở 3.2, thống kê cụm và bảng fold × ngôn ngữ (mục 12.6) ở 3.3, số hàm bị loại theo R1/R2/R3 (mục 12.5) ở 3.4, đối chiếu MVD (mục 12.7) ở 3.5, độ dài token (mục 12.8) ở 3.6. Mục 3.7 (yêu cầu bổ sung): tập v2_len768, số đơn vị tách theo `is_paired` kèm tỷ lệ nhãn 1, tập kiểm tra `cvefixes_only_eval`, và tập v2_len768_paired (tập chính khi so sánh với MVD).

### 3.1. Bước 4: trích xuất hàm thô

Bảng `method_change` có 277,948 dòng (target=1: 126,599; target=0: 151,349). Mỗi dòng `method_change` là một dòng thô; `raw_id` = `rowid` của dòng trong cơ sở dữ liệu (thứ tự của bản dump).

#### 4.1 Ngôn ngữ

**Bước A** bỏ 59,528 dòng của các ngôn ngữ khác (mục 6.2: đếm nhưng không giữ):

| programming_language (không giữ) | target=1 | target=0 | tổng |
|---|---|---|---|
| PHP | 4,758 | 23,499 | 28,257 |
| unknown | 16,123 | 0 | 16,123 |
| Markdown | 2,403 | 2,388 | 4,791 |
| Ruby | 1,462 | 2,621 | 4,083 |
| TypeScript | 1,039 | 1,909 | 2,948 |
| Rust | 327 | 468 | 795 |
| Objective-C | 263 | 349 | 612 |
| Scala | 232 | 379 | 611 |
| Swift | 79 | 268 | 347 |
| HTML | 164 | 169 | 333 |
| Lua | 73 | 101 | 174 |
| CoffeeScript | 52 | 78 | 130 |
| Perl | 23 | 59 | 82 |
| Shell | 30 | 36 | 66 |
| SQL | 23 | 38 | 61 |
| PowerShell | 4 | 43 | 47 |
| Matlab | 10 | 31 | 41 |
| TeX | 2 | 7 | 9 |
| Haskell | 3 | 5 | 8 |
| Erlang | 2 | 2 | 4 |
| Batchfile | 1 | 2 | 3 |
| Jupyter Notebook | 1 | 1 | 2 |
| None | 0 | 1 | 1 |
| Tổng | 27,074 | 32,454 | 59,528 |

**Bước A và B**: bảng chéo `programming_language` gốc (hàng) × ngôn ngữ cuối (cột), số dòng `method_change`:

| gốc \ cuối | C | C++ | C# | Go | Java | JavaScript | Python | bỏ ở bước A | bỏ ở bước B | tổng (gốc) |
|---|---|---|---|---|---|---|---|---|---|---|
| C | 14,456 | 187 | 0 | 0 | 0 | 8 | 0 | 0 | 0 | 14,651 |
| C++ | 900 | 4,496 | 0 | 0 | 8 | 5 | 0 | 0 | 0 | 5,409 |
| C# | 0 | 0 | 1,194 | 0 | 0 | 0 | 0 | 0 | 0 | 1,194 |
| Go | 15 | 0 | 9 | 6,238 | 0 | 19 | 0 | 0 | 2 | 6,283 |
| Java | 6 | 3 | 4 | 0 | 8,364 | 0 | 0 | 0 | 10 | 8,387 |
| JavaScript | 2 | 4 | 0 | 5 | 0 | 174,814 | 4 | 0 | 99 | 174,928 |
| Python | 4 | 0 | 0 | 0 | 0 | 11 | 7,546 | 0 | 7 | 7,568 |
| khác (ngoài 7 ngôn ngữ) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 59,528 | 0 | 59,528 |
| tổng (cuối) | 15,383 | 4,690 | 1,207 | 6,243 | 8,372 | 174,857 | 7,550 | 59,528 | 118 | 277,948 |

Các chuyển đổi (gốc khác cuối) và đuôi file gây ra:

| gốc | cuối | số dòng | target=1 | target=0 | đuôi file gây chuyển đổi (số dòng) |
|---|---|---|---|---|---|
| C | C++ | 187 | 78 | 109 | .cc (94), .cxx (48), .cpp (45) |
| C | JavaScript | 8 | 3 | 5 | .js (8) |
| C++ | C | 900 | 398 | 502 | .c (900) |
| C++ | Java | 8 | 0 | 8 | .java (8) |
| C++ | JavaScript | 5 | 0 | 5 | .js (5) |
| Go | C | 15 | 8 | 7 | .c (15) |
| Go | C# | 9 | 5 | 4 | .cs (9) |
| Go | JavaScript | 19 | 6 | 13 | .js (19) |
| Go | bỏ ở bước B | 2 | 1 | 1 | .ts (2) |
| Java | C | 6 | 2 | 4 | .c (6) |
| Java | C# | 4 | 2 | 2 | .cs (4) |
| Java | C++ | 3 | 0 | 3 | .cpp (3) |
| Java | bỏ ở bước B | 10 | 5 | 5 | .ts (6), .php (4) |
| JavaScript | C | 2 | 1 | 1 | .c (2) |
| JavaScript | C++ | 4 | 2 | 2 | .cpp (2), .cc (2) |
| JavaScript | Go | 5 | 2 | 3 | .go (5) |
| JavaScript | Python | 4 | 2 | 2 | .py (4) |
| JavaScript | bỏ ở bước B | 99 | 37 | 62 | .ts (91), .kt (6), .rs (2) |
| Python | C | 4 | 2 | 2 | .c (4) |
| Python | JavaScript | 11 | 1 | 10 | .js (11) |
| Python | bỏ ở bước B | 7 | 3 | 4 | .rs (4), .rb (2), .php (1) |

Quy tắc bước B: đuôi trong bảng ánh xạ → lấy theo đuôi (`.c`→C, `.cc`→C++, `.cpp`→C++, `.cxx`→C++, `.c++`→C++, `.hpp`→C++, `.hh`→C++, `.hxx`→C++, `.cs`→C#, `.go`→Go, `.java`→Java, `.js`→JavaScript, `.mjs`→JavaScript, `.cjs`→JavaScript, `.jsx`→JavaScript, `.py`→Python); đuôi không rõ (`(không đuôi)`, `.es6`, `.h`, `.h++`, `.in`, `.inc`, `.inl`, `.ipp`, `.jsm`, `.pyw`, `.tcc`, `.tpp`) → giữ `programming_language`; mọi đuôi khác → bỏ. Đuôi lấy từ tên file cuối của `file_path` (`new_path`, nếu là `'None'` thì `old_path`, rồi `filename`), chữ thường, phần sau dấu chấm cuối cùng (nên `.d.ts` được tính là `.ts`).

Đối chiếu với bảng ngôn ngữ của bước 3 (đã `assert` trong script): với mỗi ngôn ngữ, bảng bước 3 − bỏ ở bước B − chuyển ra + chuyển vào = sau A và B; và 218,302 + 59,528 (bước A) + 118 (bước B) = 277,948.

| ngôn ngữ | bảng bước 3 | bỏ ở bước B | chuyển ra | chuyển vào | sau A và B | chênh so với bước 3 |
|---|---|---|---|---|---|---|
| C | 14,651 | 0 | 195 | 927 | 15,383 | 732 |
| C++ | 5,409 | 0 | 913 | 194 | 4,690 | -719 |
| C# | 1,194 | 0 | 0 | 13 | 1,207 | 13 |
| Go | 6,283 | 2 | 43 | 5 | 6,243 | -40 |
| Java | 8,387 | 10 | 13 | 8 | 8,372 | -15 |
| JavaScript | 174,928 | 99 | 15 | 43 | 174,857 | -71 |
| Python | 7,568 | 7 | 15 | 4 | 7,550 | -18 |
| Tổng | 218,420 | 118 | 1,194 | 1,194 | 218,302 | -118 |

Sau bước A và B còn **218,302 dòng thô**:

| ngôn ngữ | target=1 | target=0 | tổng |
|---|---|---|---|
| C | 6,571 | 8,812 | 15,383 |
| C++ | 1,740 | 2,950 | 4,690 |
| C# | 477 | 730 | 1,207 |
| Go | 1,862 | 4,381 | 6,243 |
| Java | 3,093 | 5,279 | 8,372 |
| JavaScript | 82,965 | 91,892 | 174,857 |
| Python | 2,771 | 4,779 | 7,550 |
| Tổng | 99,479 | 118,823 | 218,302 |

#### 4.2 Quy tắc R0 (mã sinh tự động / đóng gói / thư viện chép vào)

Chỉ đánh dấu ở bước này (cột `r0_reason`), bước 5 mới bỏ. `r0_reason` là điều kiện đầu tiên thỏa theo thứ tự a, b, c, d: a: thư mục node_modules/bower_components/vendor/third_party/dist; b: tên file .min/.bundle/.pack(ed).js; c: có dòng dài hơn 1.000 ký tự; d: file_change có hơn 300 dòng method_change. Đường dẫn so khớp không phân biệt hoa thường, phân cách `/`.

Số dòng bị đánh dấu theo điều kiện đầu tiên thỏa, theo ngôn ngữ và nhãn:

| ngôn ngữ | số dòng | a (t=1) | a (t=0) | b (t=1) | b (t=0) | c (t=1) | c (t=0) | d (t=1) | d (t=0) | R0 tổng | % bị R0 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| C | 15,383 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 2 | 0.01 |
| C++ | 4,690 | 5 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 10 | 0.21 |
| C# | 1,207 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Go | 6,243 | 0 | 1,319 | 0 | 0 | 3 | 3 | 0 | 0 | 1,325 | 21.2 |
| Java | 8,372 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 2 | 0.02 |
| JavaScript | 174,857 | 14,535 | 14,469 | 55,260 | 57,147 | 10,048 | 13,637 | 392 | 1,749 | 167,237 | 95.6 |
| Python | 7,550 | 0 | 0 | 0 | 0 | 2 | 2 | 0 | 0 | 4 | 0.05 |
| Tổng | 218,302 | 14,540 | 15,793 | 55,260 | 57,147 | 10,055 | 13,644 | 392 | 1,749 | 168,580 | 77.2 |

Điều kiện d với các ngưỡng 100, 300 và 1.000 (cột *d với ngưỡng*: mọi dòng thuộc file_change vượt ngưỡng, không xét thứ tự; cột *R0 tổng*: số dòng bị R0 nếu dùng ngưỡng đó):

| ngôn ngữ | d với ngưỡng 100 | R0 tổng nếu ngưỡng 100 | d với ngưỡng 300 | R0 tổng nếu ngưỡng 300 | d với ngưỡng 1,000 | R0 tổng nếu ngưỡng 1,000 |
|---|---|---|---|---|---|---|
| C | 127 | 129 | 0 | 2 | 0 | 2 |
| C++ | 0 | 10 | 0 | 10 | 0 | 10 |
| C# | 0 | 0 | 0 | 0 | 0 | 0 |
| Go | 688 | 1,831 | 0 | 1,325 | 0 | 1,325 |
| Java | 117 | 119 | 0 | 2 | 0 | 2 |
| JavaScript | 161,427 | 167,682 | 151,924 | 167,237 | 124,589 | 166,135 |
| Python | 115 | 119 | 0 | 4 | 0 | 4 |
| Tổng | 162,474 | 169,890 | 151,924 | 168,580 | 124,589 | 167,478 |

Số dòng thỏa từng điều kiện (không xét thứ tự, một dòng có thể thỏa nhiều điều kiện): a: 30,333, b: 118,505, c: 91,612, d: 151,924.

30 file JavaScript còn nhiều hàm nhất sau R0 (để kiểm tra còn sót file đóng gói):

| file_path | repo_url | commit | số hàm | target=1 |
|---|---|---|---|---|
| lib/client.js | https://github.com/mscdex/ssh2 | f763271f41 | 116 | 47 |
| js/DivControl.js | https://github.com/OS4ED/openSIS-Classic | 81799fd1de | 110 | 54 |
| upload/templates/freshcat/js/backend.js | https://github.com/BlackCatDevelopment/BlackCatCMS | a817755828 | 110 | 53 |
| public/assets/katex/contrib/mhchem.js | https://github.com/HAWK-Digital-Environments/HAWKI | 146967f314 | 109 | 0 |
| simple-git/src/git.js | https://github.com/steveukx/git-js | 774648049e | 100 | 50 |
| lib/server.js | https://github.com/mscdex/ssh2 | f763271f41 | 98 | 41 |
| lib/protocol/SFTP.js | https://github.com/mscdex/ssh2 | f763271f41 | 86 | 0 |
| apps/web/public/sandbox.js | https://github.com/vriteio/vrite | 1877683b93 | 74 | 35 |
| static/js/ckeditor/plugins/wsc/dialogs/wsc.js | https://github.com/IlchCMS/Ilch-2.0 | 381e15f39d | 73 | 0 |
| src/js/admin.js | https://github.com/ioBroker/ioBroker.admin | 16b2b325ab | 72 | 36 |
| lib/protocol/Protocol.js | https://github.com/mscdex/ssh2 | f763271f41 | 64 | 0 |
| wp-admin/js/updates.js | https://github.com/WordPress/WordPress | 8c82515ab6 | 62 | 16 |
| assets/js/bms.js | https://github.com/unilogies/bumsys | 86e29dd23d | 56 | 0 |
| scripts/functions.imgmappin.admin.js | https://github.com/wp-plugins/easy2map-photos | 503d9ee248 | 54 | 27 |
| src/main/webapp/mxgraph/mxClient.js | https://github.com/jgraph/drawio | 3d3f819d7a | 54 | 27 |
| lib/purify.es.js | https://github.com/1j01/mind-map | 9617e6084d | 50 | 0 |
| app/webroot/js/action_table.js | https://github.com/MISP/MISP | bb3b7a7e91 | 46 | 23 |
| src/main/webapp/js/diagramly/Dialogs.js | https://github.com/jgraph/drawio | 3d3f819d7a | 44 | 22 |
| src/main/webapp/js/diagramly/EditorUi.js | https://github.com/jgraph/drawio | d37894baf1 | 43 | 19 |
| src/js/adminAdapters.js | https://github.com/ioBroker/ioBroker.admin | 16b2b325ab | 42 | 21 |
| pcsd/public/js/pcsd.js | https://github.com/ClusterLabs/pcs | acdbbe8307 | 41 | 14 |
| js/marked.js | https://github.com/volca/markdown-preview | 1181f044a5 | 40 | 0 |
| plugins/DOMPurify/purify.js | https://github.com/nilsteampassnet/teampass | 39b774cba1 | 40 | 0 |
| plugins/DOMPurify/purify.cjs.js | https://github.com/nilsteampassnet/teampass | 39b774cba1 | 39 | 0 |
| plugins/DOMPurify/purify.es.js | https://github.com/nilsteampassnet/teampass | 39b774cba1 | 39 | 0 |
| assets/js/jquery-ui/jquery-ui.js | https://github.com/semplon/GeniXCMS | d885eb2000 | 38 | 19 |
| lib/crypto/modules/NodeCryptoModule/NodeCryptoModule.js | https://github.com/pubnub/javascript | fb6cd0417c | 37 | 0 |
| lib/crypto/modules/NodeCryptoModule/nodeCryptoModule.js | https://github.com/pubnub/javascript | fb6cd0417c | 37 | 0 |
| test/test-client-server.js | https://github.com/mscdex/ssh2 | f763271f41 | 36 | 15 |
| src/main/webapp/js/diagramly/EditorUi.js | https://github.com/jgraph/drawio | ea012baba6 | 35 | 12 |

Sau khi bỏ R0 còn 49,722 dòng (bước 5 mới bỏ thật):

| ngôn ngữ | target=1 | target=0 | tổng |
|---|---|---|---|
| C | 6,570 | 8,811 | 15,381 |
| C++ | 1,735 | 2,945 | 4,680 |
| C# | 477 | 730 | 1,207 |
| Go | 1,859 | 3,059 | 4,918 |
| Java | 3,092 | 5,278 | 8,370 |
| JavaScript | 2,730 | 4,890 | 7,620 |
| Python | 2,769 | 4,777 | 7,546 |
| Tổng | 19,232 | 30,490 | 49,722 |

Trong đó hàm rỗng sau chuẩn hóa (bước 5 bỏ): 0 dòng (trên toàn bộ dòng thô: 1).

#### 4.3 Tỷ lệ ghép cặp (mục 6.6)

Với mỗi hàm target=1, kiểm tra trong cùng `file_change` có hàm target=0 cùng `name` hay không. Cột *sau R0*: chỉ xét các dòng không bị R0 ở cả hai phía.

| ngôn ngữ | hàm t=1 (thô) | có cặp (thô) | tỷ lệ % (thô) | hàm t=1 (sau R0) | có cặp (sau R0) | tỷ lệ % (sau R0) |
|---|---|---|---|---|---|---|
| C | 6,571 | 6,063 | 92.3 | 6,570 | 6,062 | 92.3 |
| C++ | 1,740 | 1,648 | 94.7 | 1,735 | 1,643 | 94.7 |
| C# | 477 | 420 | 88.1 | 477 | 420 | 88.1 |
| Go | 1,862 | 1,653 | 88.8 | 1,859 | 1,650 | 88.8 |
| Java | 3,093 | 2,829 | 91.5 | 3,092 | 2,828 | 91.5 |
| JavaScript | 82,965 | 73,708 | 88.8 | 2,730 | 2,347 | 86.0 |
| Python | 2,771 | 2,440 | 88.1 | 2,769 | 2,438 | 88.0 |
| Tổng | 99,479 | 88,761 | 89.2 | 19,232 | 17,388 | 90.4 |

#### 4.4 `n_vuln_funcs_in_commit`

Số `unit_id` khác nhau có target=1 trong cùng `commit_hash`, tính trên mọi ngôn ngữ của `method_change` (kể cả ngoài 7 ngôn ngữ và các dòng bị bỏ ở bước B), bỏ hàm rỗng. `n_vuln_funcs_in_commit` bỏ các dòng R0; `n_vuln_funcs_in_commit_raw` tính trước R0. Không dùng để lọc.

Phân bố theo commit (chỉ commit có ít nhất một hàm target=1):

|  | trung vị | p90 | p99 | lớn nhất | số commit có ≥1 hàm t=1 |
|---|---|---|---|---|---|
| sau R0 | 1.0 | 7.0 | 41.1 | 2,219 | 7,091 |
| trước R0 (raw) | 1.0 | 7.0 | 50.7 | 5,156 | 7,132 |

Đã ghi `raw_functions.parquet`: 218,302 dòng, 398 nhóm dòng, 0.31 GiB (gồm cả dòng R0). Các cột: `raw_id`, `func`, `language`, `target`, `cve_id`, `cwe_id`, `repo_url`, `commit_hash`, `file_path`, `method_name`, `signature`, `r0_reason`, `n_vuln_funcs_in_commit`, `n_vuln_funcs_in_commit_raw`, `unit_id`, `is_empty`, `max_line_len`, `n_methods_in_file_change`, `method_change_id`, `file_change_id`, `programming_language`, `file_ext`, `change_type`.

### 3.2. Bước 5: tập sạch v1

| bước | còn lại | bị bỏ | lý do |
|---|---|---|---|
| dòng thô (sau bước A, B) | 218,302 |  |  |
| bỏ R0 | 49,722 | 168,580.0 | R0 a/b/c/d (chỉnh sửa có chủ đích) |
| bỏ hàm rỗng | 49,722 | 0 | rỗng sau chuẩn hóa |
| bỏ unit_id mâu thuẫn | 47,871 | 1,851.0 | cả hai nhãn: 888 unit_id / 1,807 dòng; nhiều ngôn ngữ: 22 unit_id / 44 dòng; cả hai lý do: 0 unit_id |
| gộp thành đơn vị | 46,411 | 1,460.0 | dòng trùng unit_id gộp lại |

Dòng bị bỏ vì unit_id mâu thuẫn, theo ngôn ngữ và nhãn:

| ngôn ngữ | target=1 | target=0 |
|---|---|---|
| C | 298 | 302 |
| C++ | 96 | 102 |
| C# | 44 | 44 |
| Go | 30 | 30 |
| Java | 170 | 170 |
| JavaScript | 128 | 127 |
| Python | 153 | 157 |

**units_v1**: 46,411 đơn vị.

| ngôn ngữ | target=1 | target=0 | tổng |
|---|---|---|---|
| C | 6,173 | 8,370 | 14,543 |
| C++ | 1,622 | 2,798 | 4,420 |
| C# | 410 | 660 | 1,070 |
| Go | 1,670 | 2,868 | 4,538 |
| Java | 2,829 | 4,926 | 7,755 |
| JavaScript | 2,515 | 4,388 | 6,903 |
| Python | 2,596 | 4,586 | 7,182 |
| Tổng | 17,815 | 28,596 | 46,411 |

`n_occurrences`: trung vị 1, lớn nhất 16; đơn vị xuất hiện nhiều hơn một lần: 1,017. Đơn vị có nhiều hơn một CVE: 3,559; nhiều hơn một commit: 297.

#### Phân bố `n_vuln_funcs_in_commit` (mục 12.4)

Tỷ lệ đơn vị v1 thuộc commit có 0, 1, 2–5, 6–20, trên 20 hàm có lỗ hổng (giá trị lớn nhất qua các lần xuất hiện). Bucket 0: đơn vị chỉ thuộc commit không có hàm target=1 nào ngoài R0 (ví dụ commit chỉ thêm hàm mới).

`n_vuln_funcs_in_commit` sau R0:

| ngôn ngữ | số đơn vị | 0 (%) | 1 (%) | 2–5 (%) | 6–20 (%) | >20 (%) |
|---|---|---|---|---|---|---|
| C | 14,543 | 6.5 | 23.6 | 27.9 | 23.6 | 18.4 |
| C++ | 4,420 | 8.9 | 16.9 | 24.4 | 23.8 | 26.0 |
| C# | 1,070 | 2.0 | 10.0 | 16.6 | 27.3 | 44.1 |
| Go | 4,538 | 3.0 | 8.1 | 24.8 | 25.1 | 39.0 |
| Java | 7,755 | 5.9 | 6.4 | 18.5 | 28.7 | 40.6 |
| JavaScript | 6,903 | 5.8 | 13.2 | 20.7 | 25.8 | 34.5 |
| Python | 7,182 | 5.6 | 11.2 | 27.8 | 31.4 | 24.1 |
| Tổng | 46,411 | 5.9 | 14.8 | 24.3 | 26.2 | 28.7 |

`n_vuln_funcs_in_commit` trước R0 (raw):

| ngôn ngữ | số đơn vị | 0 (%) | 1 (%) | 2–5 (%) | 6–20 (%) | >20 (%) |
|---|---|---|---|---|---|---|
| C | 14,543 | 6.5 | 23.6 | 27.9 | 23.6 | 18.4 |
| C++ | 4,420 | 8.9 | 16.9 | 24.4 | 23.8 | 26.0 |
| C# | 1,070 | 2.0 | 10.0 | 16.6 | 27.3 | 44.1 |
| Go | 4,538 | 3.0 | 8.0 | 24.9 | 25.1 | 39.0 |
| Java | 7,755 | 5.9 | 6.4 | 18.4 | 28.6 | 40.8 |
| JavaScript | 6,903 | 4.5 | 13.7 | 20.5 | 25.1 | 36.1 |
| Python | 7,182 | 5.6 | 11.2 | 27.8 | 31.4 | 24.1 |
| Tổng | 46,411 | 5.7 | 14.9 | 24.3 | 26.1 | 29.0 |

### 3.3. Bước 6: gom cụm CVE và chia fold (v1)

`build_folds.build` nguyên bản: cụm = thành phần liên thông của CVE (toàn cục, xuyên ngôn ngữ); 5 fold greedy phân tầng ngôn ngữ × nhãn (seed 42); cụm khổng lồ = cụm chiếm hơn 10% số đơn vị của một ngôn ngữ; validation nội bộ của fold k là bin 9 trong 10 bin (seed 100+k), không chứa cụm khổng lồ.

Tổng: 46,411 đơn vị, 6,175 cụm, 2 cụm khổng lồ.

#### Thống kê cụm (`cluster_stats_cvefixes_v1.csv`)

| language | n_units | n_clusters | median_cluster | max_cluster | top1_share | effective_clusters | giant_clusters_gt10pct | clusters_spanning_langs |
|---|---|---|---|---|---|---|---|---|
| C | 14,543 | 3,064 | 2.0 | 442 | 0.03 | 353.2 | 0 | 42 |
| C# | 1,070 | 82 | 4.0 | 156 | 0.146 | 18.1 | 1 | 4 |
| C++ | 4,420 | 793 | 2.0 | 532 | 0.12 | 42.6 | 1 | 143 |
| Go | 4,538 | 353 | 4.0 | 440 | 0.097 | 39.1 | 0 | 6 |
| Java | 7,755 | 483 | 6.0 | 631 | 0.081 | 68.0 | 0 | 24 |
| JavaScript | 6,903 | 788 | 3.0 | 568 | 0.082 | 74.9 | 0 | 56 |
| Python | 7,182 | 823 | 4.0 | 231 | 0.032 | 160.7 | 0 | 144 |

#### Cụm khổng lồ (chiếm hơn 10% số đơn vị của ít nhất một ngôn ngữ)

| cụm | fold | số đơn vị | số CVE | theo ngôn ngữ | repo nhiều nhất | ví dụ CVE |
|---|---|---|---|---|---|---|
| 21 | 2 | 532 | 1 | C++ 532 (12%) | github.com/tensorflow/tensorflow (532) | CVE-2020-15211 |
| 332 | 4 | 156 | 1 | C# 156 (15%) | github.com/Ulterius/server (156) | CVE-2017-16806 |

#### Bảng fold × ngôn ngữ (số đơn vị)

| fold | C | C++ | C# | Go | Java | JavaScript | Python | tổng |
|---|---|---|---|---|---|---|---|---|
| 0 | 2,909 | 885 | 213 | 908 | 1,551 | 1,381 | 1,436 | 9,283 |
| 1 | 2,908 | 884 | 214 | 909 | 1,551 | 1,380 | 1,436 | 9,282 |
| 2 | 2,908 | 883 | 214 | 909 | 1,551 | 1,381 | 1,436 | 9,282 |
| 3 | 2,909 | 885 | 216 | 904 | 1,551 | 1,381 | 1,436 | 9,282 |
| 4 | 2,909 | 883 | 213 | 908 | 1,551 | 1,380 | 1,438 | 9,282 |

Theo nhãn:

| fold | C t=1 | C t=0 | C++ t=1 | C++ t=0 | C# t=1 | C# t=0 | Go t=1 | Go t=0 | Java t=1 | Java t=0 | JavaScript t=1 | JavaScript t=0 | Python t=1 | Python t=0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 1,235 | 1,674 | 325 | 560 | 81 | 132 | 339 | 569 | 566 | 985 | 503 | 878 | 519 | 917 |
| 1 | 1,234 | 1,674 | 324 | 560 | 82 | 132 | 340 | 569 | 566 | 985 | 503 | 877 | 519 | 917 |
| 2 | 1,234 | 1,674 | 324 | 559 | 82 | 132 | 340 | 569 | 566 | 985 | 503 | 878 | 519 | 917 |
| 3 | 1,235 | 1,674 | 325 | 560 | 84 | 132 | 312 | 592 | 565 | 986 | 503 | 878 | 519 | 917 |
| 4 | 1,235 | 1,674 | 324 | 559 | 81 | 132 | 339 | 569 | 566 | 985 | 503 | 877 | 520 | 918 |

Kích thước train / validation nội bộ / test của từng fold:

| fold | inner_val | train (không gồm inner_val) | test |
|---|---|---|---|
| 0 | 3,624 | 33,504 | 9,283 |
| 1 | 3,621 | 33,508 | 9,282 |
| 2 | 3,665 | 33,464 | 9,282 |
| 3 | 3,619 | 33,510 | 9,282 |
| 4 | 3,640 | 33,489 | 9,282 |

Kiểm tra đủ hai nhãn cho mỗi ngôn ngữ ở train / val / test của mỗi fold (v1): đủ ở mọi nơi.

### 3.4. Bước 7: quy tắc làm sạch v2

`clean_rules.apply_v2_rules` nguyên bản, `path_col="file_path"`. R1: nhóm cùng ngôn ngữ, cùng dãy token (bỏ chú thích/khoảng trắng) mang cả hai nhãn; R2: hàm kiểm thử theo khai báo (4 dòng đầu) hoặc theo đường dẫn; R3: trùng dãy token cùng nhãn, giữ unit_id nhỏ nhất. `reason` ưu tiên R1, rồi R2, rồi R3.

Số đơn vị bị loại theo lý do (theo `reason`), và số đơn vị thỏa từng điều kiện R2 không xét ưu tiên:

| ngôn ngữ | đơn vị v1 | R1 | R2 chỉ khai báo | R2 chỉ đường dẫn | R2 cả hai | R3 | tổng bị loại | % bị loại | R2 (mọi đơn vị thỏa, kể cả trong R1) | R2_decl (mọi đơn vị) | R2_path (mọi đơn vị) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| C | 14,543 | 526 | 5 | 153 | 67 | 30 | 781 | 5.4 | 227 | 74 | 222 |
| C++ | 4,420 | 62 | 0 | 210 | 339 | 2 | 613 | 13.9 | 551 | 341 | 551 |
| C# | 1,070 | 26 | 0 | 49 | 0 | 0 | 75 | 7.0 | 49 | 0 | 49 |
| Go | 4,538 | 40 | 2 | 688 | 671 | 0 | 1,401 | 30.9 | 1,369 | 679 | 1,367 |
| Java | 7,755 | 350 | 0 | 1,543 | 673 | 6 | 2,572 | 33.2 | 2,234 | 673 | 2,234 |
| JavaScript | 6,903 | 757 | 2 | 344 | 15 | 46 | 1,164 | 16.9 | 517 | 19 | 515 |
| Python | 7,182 | 335 | 37 | 420 | 2,261 | 4 | 3,057 | 42.6 | 2,778 | 2,342 | 2,741 |
| Tổng | 46,411 | 2,096 | 46 | 3,407 | 4,026 | 88 | 9,663 | 20.8 | 7,725 | 4,128 | 7,679 |

Theo nhãn:

| ngôn ngữ | R1 t=1 | R1 t=0 | R2 t=1 | R2 t=0 | R3 t=1 | R3 t=0 |
|---|---|---|---|---|---|---|
| C | 263 | 263 | 47 | 178 | 11 | 19 |
| C++ | 31 | 31 | 130 | 419 | 1 | 1 |
| C# | 13 | 13 | 4 | 45 | 0 | 0 |
| Go | 20 | 20 | 513 | 848 | 0 | 0 |
| Java | 175 | 175 | 619 | 1,597 | 0 | 6 |
| JavaScript | 378 | 379 | 89 | 272 | 2 | 44 |
| Python | 168 | 167 | 793 | 1,925 | 2 | 2 |

**v2**: 36,748 đơn vị (bỏ 9,663 trên 46,411).

| ngôn ngữ | target=1 | target=0 | tổng |
|---|---|---|---|
| C | 5,852 | 7,910 | 13,762 |
| C++ | 1,460 | 2,347 | 3,807 |
| C# | 393 | 602 | 995 |
| Go | 1,137 | 2,000 | 3,137 |
| Java | 2,035 | 3,148 | 5,183 |
| JavaScript | 2,046 | 3,693 | 5,739 |
| Python | 1,633 | 2,492 | 4,125 |
| Tổng | 14,556 | 22,192 | 36,748 |

#### Kiểm tra đủ hai nhãn sau khi bỏ (v2)

Mỗi ngôn ngữ trong mỗi fold, ở train (fold ≠ k, không thuộc inner_val_fold{k}), validation (inner_val_fold{k}) và test (fold = k):

Đủ cả hai nhãn ở mọi ngôn ngữ, mọi fold, mọi phần.

15 ô (fold, phần, ngôn ngữ) có nhãn ít nhất:

| fold | phần | ngôn ngữ | target=1 | target=0 |
|---|---|---|---|---|
| 2 | val | C# | 11 | 26 |
| 1 | val | C# | 19 | 48 |
| 0 | val | C# | 20 | 37 |
| 3 | val | C# | 26 | 36 |
| 4 | val | C# | 28 | 48 |
| 0 | test | C# | 73 | 117 |
| 4 | test | C# | 78 | 122 |
| 2 | test | C# | 80 | 123 |
| 3 | test | C# | 80 | 124 |
| 1 | test | C# | 82 | 116 |
| 1 | val | C++ | 93 | 153 |
| 3 | val | Go | 96 | 185 |
| 2 | val | Go | 97 | 153 |
| 1 | val | Go | 98 | 183 |
| 0 | val | C++ | 99 | 159 |

### 3.5. Bước 8: đối chiếu với MVD

`mvd_reference.csv`: 18,694 hàm, 2,533 CVE. `in_mvd_cve` xét CVE của MVD ở mọi ngôn ngữ; cột *cùng ngôn ngữ* chỉ xét CVE của MVD trong đúng ngôn ngữ đó.

#### Trùng CVE

| tập | ngôn ngữ | số CVE (CVEfixes) | có trong MVD (mọi ngôn ngữ) | có trong MVD (cùng ngôn ngữ) | chỉ có ở CVEfixes |
|---|---|---|---|---|---|
| v1 | C | 3,246 | 556 | 554 | 2,690 |
| v1 | C++ | 852 | 355 | 341 | 497 |
| v1 | C# | 88 | 40 | 40 | 48 |
| v1 | Go | 400 | 156 | 156 | 244 |
| v1 | Java | 508 | 207 | 206 | 301 |
| v1 | JavaScript | 866 | 282 | 266 | 584 |
| v1 | Python | 902 | 323 | 284 | 579 |
| v1 | Tổng | 6,613 | 1,820 | 1,820 | 4,793 |
| v2 | C | 3,240 | 554 | 552 | 2,686 |
| v2 | C++ | 843 | 352 | 339 | 491 |
| v2 | C# | 87 | 40 | 40 | 47 |
| v2 | Go | 384 | 150 | 150 | 234 |
| v2 | Java | 457 | 200 | 199 | 257 |
| v2 | JavaScript | 830 | 270 | 263 | 560 |
| v2 | Python | 732 | 258 | 257 | 474 |
| v2 | Tổng | 6,479 | 1,788 | 1,788 | 4,691 |

#### Trùng hàm (unit_id)

| tập | ngôn ngữ | đơn vị | unit_id trùng MVD | % trùng | cùng ngôn ngữ | cùng nhãn | trùng với MVD v2 |
|---|---|---|---|---|---|---|---|
| v1 | C | 14,543 | 749 | 5.2 | 749 | 746 | 735 |
| v1 | C++ | 4,420 | 507 | 11.5 | 507 | 502 | 442 |
| v1 | C# | 1,070 | 114 | 10.7 | 114 | 114 | 108 |
| v1 | Go | 4,538 | 685 | 15.1 | 685 | 684 | 604 |
| v1 | Java | 7,755 | 634 | 8.2 | 634 | 634 | 620 |
| v1 | JavaScript | 6,903 | 242 | 3.5 | 242 | 241 | 221 |
| v1 | Python | 7,182 | 750 | 10.4 | 750 | 750 | 520 |
| v1 | Tổng | 46,411 | 3,681 | 7.9 | 3,681 | 3,671 | 3,250 |
| v2 | C | 13,762 | 733 | 5.3 | 733 | 730 | 731 |
| v2 | C++ | 3,807 | 422 | 11.1 | 422 | 417 | 420 |
| v2 | C# | 995 | 108 | 10.8 | 108 | 108 | 108 |
| v2 | Go | 3,137 | 590 | 18.8 | 590 | 590 | 587 |
| v2 | Java | 5,183 | 589 | 11.4 | 589 | 589 | 587 |
| v2 | JavaScript | 5,739 | 217 | 3.8 | 217 | 216 | 217 |
| v2 | Python | 4,125 | 493 | 11.9 | 493 | 493 | 492 |
| v2 | Tổng | 36,748 | 3,152 | 8.6 | 3,152 | 3,143 | 3,142 |

#### Đơn vị v2 có CVE hoàn toàn mới so với MVD (`in_mvd_cve` sai)

Tập dùng cho thí nghiệm "huấn luyện trên MVD, kiểm tra trên các CVE chỉ có ở CVEfixes".

| ngôn ngữ | đơn vị v2 | in_mvd_cve sai: t=1 | in_mvd_cve sai: t=0 | in_mvd_cve sai: tổng | % đơn vị v2 | trong đó in_mvd_func đúng |
|---|---|---|---|---|---|---|
| C | 13,762 | 4,573 | 6,230 | 10,803 | 78.5 | 3 |
| C++ | 3,807 | 823 | 1,346 | 2,169 | 57.0 | 5 |
| C# | 995 | 276 | 417 | 693 | 69.6 | 0 |
| Go | 3,137 | 822 | 1,238 | 2,060 | 65.7 | 0 |
| Java | 5,183 | 1,206 | 1,907 | 3,113 | 60.1 | 0 |
| JavaScript | 5,739 | 1,359 | 2,816 | 4,175 | 72.7 | 1 |
| Python | 4,125 | 968 | 1,483 | 2,451 | 59.4 | 0 |
| Tổng | 36,748 | 10,027 | 15,437 | 25,464 | 69.3 | 9 |

Ngôn ngữ thiếu một nhãn trong tập này: không có.

Lưu ý: 9 đơn vị v2 có CVE không thuộc MVD nhưng `unit_id` lại có trong MVD (cùng hàm, khác CVE); nên loại thêm các đơn vị này khỏi tập kiểm tra để tránh rò rỉ.

### 3.6. Bước 9: độ dài token (UniXcoder)

Tokenizer `microsoft/unixcoder-base-nine` revision `5f0dc256eb0904af496d427451da5d7f90261676` (transformers 5.23.0, lớp `RobertaTokenizer`). Độ dài = số token của mã + 4 token đặc biệt (`<s> <encoder-only> </s> CODE </s>`); mã hóa trên `func` nguyên bản. Vượt 768: mã dài hơn 764 token sẽ bị cắt. Cột *vượt 512* dùng cùng cách đếm (tham khảo cho CodeBERT, giới hạn 512).

Tập v2:

| ngôn ngữ | số đơn vị | trung vị | p90 | p99 | dài nhất | % vượt 768 | % vượt 512 |
|---|---|---|---|---|---|---|---|
| C | 13,762 | 506.0 | 2,489.0 | 10,958.6 | 65,299 | 35.6 | 49.6 |
| C++ | 3,807 | 383.0 | 1,758.8 | 7,134.7 | 42,614 | 27.8 | 40.4 |
| C# | 995 | 188.0 | 674.0 | 4,142.8 | 9,700 | 8.6 | 15.5 |
| Go | 3,137 | 162.0 | 785.8 | 2,617.2 | 32,925 | 10.4 | 19.4 |
| Java | 5,183 | 139.0 | 603.0 | 2,315.8 | 55,017 | 7.3 | 12.6 |
| JavaScript | 5,739 | 193.0 | 1,188.4 | 6,572.5 | 108,076 | 15.1 | 22.5 |
| Python | 4,125 | 228.0 | 919.2 | 4,548.4 | 80,076 | 13.5 | 22.9 |
| Tổng | 36,748 | 291.0 | 1,578.0 | 7,954.0 | 108,076 | 22.3 | 32.7 |

Tập v1:

| ngôn ngữ | số đơn vị | trung vị | p90 | p99 | dài nhất | % vượt 768 | % vượt 512 |
|---|---|---|---|---|---|---|---|
| C | 14,543 | 502.0 | 2,458.0 | 10,194.0 | 65,299 | 35.2 | 49.2 |
| C++ | 4,420 | 358.5 | 1,651.2 | 7,075.9 | 42,614 | 25.7 | 38.5 |
| C# | 1,070 | 180.0 | 660.1 | 3,899.1 | 9,700 | 8.3 | 14.7 |
| Go | 4,538 | 230.0 | 1,159.3 | 7,480.0 | 56,056 | 17.8 | 29.4 |
| Java | 7,755 | 139.0 | 557.0 | 1,972.0 | 55,017 | 6.5 | 11.4 |
| JavaScript | 6,903 | 172.0 | 1,059.2 | 6,140.5 | 108,076 | 13.6 | 20.3 |
| Python | 7,182 | 193.0 | 743.9 | 3,442.0 | 80,076 | 9.6 | 17.1 |
| Tổng | 46,411 | 261.0 | 1,430.0 | 7,480.0 | 108,076 | 20.0 | 29.8 |

### 3.7. Bước 9b: cột đánh dấu bổ sung, tập v2_len768 và v2_len768_paired

Thêm vào `units_v1.parquet` (chỉ đánh dấu, không lọc): `n_tokens` (bước 9), `is_paired`, `cvefixes_only_eval`. `groups_and_folds_cvefixes_v2_len768.csv` = file fold v2 bỏ 8,177 đơn vị có `n_tokens` > 768 (còn 28,571 / 36,748), giữ nguyên mọi cột và giá trị (đã `assert`).

`is_paired`: đúng nếu ở ít nhất một lần xuất hiện, trong cùng `file_change` có dòng thô mang nhãn ngược lại và cùng `method_name`. Chỉ xét các dòng không bị R0 (cách tính như cột *sau R0* của mục 6.6), áp dụng cho cả nhãn 1 và nhãn 0. Dòng thô của các `unit_id` mâu thuẫn bị bỏ ở bước 5 vẫn được tính làm "bạn ghép".

#### Số đơn vị theo ngôn ngữ và nhãn, tách theo `is_paired`

| tập | ngôn ngữ | t=1 | t=0 | tổng | % t=1 |
|---|---|---|---|---|---|
| v2 | C | 5,852 | 7,910 | 13,762 | 42.5 |
| v2 | C++ | 1,460 | 2,347 | 3,807 | 38.4 |
| v2 | C# | 393 | 602 | 995 | 39.5 |
| v2 | Go | 1,137 | 2,000 | 3,137 | 36.2 |
| v2 | Java | 2,035 | 3,148 | 5,183 | 39.3 |
| v2 | JavaScript | 2,046 | 3,693 | 5,739 | 35.7 |
| v2 | Python | 1,633 | 2,492 | 4,125 | 39.6 |
| v2 | Tổng | 14,556 | 22,192 | 36,748 | 39.6 |
| v2, is_paired đúng | C | 5,377 | 5,445 | 10,822 | 49.7 |
| v2, is_paired đúng | C++ | 1,383 | 1,419 | 2,802 | 49.4 |
| v2, is_paired đúng | C# | 350 | 364 | 714 | 49.0 |
| v2, is_paired đúng | Go | 1,001 | 1,014 | 2,015 | 49.7 |
| v2, is_paired đúng | Java | 1,861 | 1,928 | 3,789 | 49.1 |
| v2, is_paired đúng | JavaScript | 1,711 | 1,738 | 3,449 | 49.6 |
| v2, is_paired đúng | Python | 1,480 | 1,506 | 2,986 | 49.6 |
| v2, is_paired đúng | Tổng | 13,163 | 13,414 | 26,577 | 49.5 |
| v2, is_paired sai | C | 475 | 2,465 | 2,940 | 16.2 |
| v2, is_paired sai | C++ | 77 | 928 | 1,005 | 7.7 |
| v2, is_paired sai | C# | 43 | 238 | 281 | 15.3 |
| v2, is_paired sai | Go | 136 | 986 | 1,122 | 12.1 |
| v2, is_paired sai | Java | 174 | 1,220 | 1,394 | 12.5 |
| v2, is_paired sai | JavaScript | 335 | 1,955 | 2,290 | 14.6 |
| v2, is_paired sai | Python | 153 | 986 | 1,139 | 13.4 |
| v2, is_paired sai | Tổng | 1,393 | 8,778 | 10,171 | 13.7 |
| v2_len768 | C | 3,777 | 5,080 | 8,857 | 42.6 |
| v2_len768 | C++ | 1,064 | 1,685 | 2,749 | 38.7 |
| v2_len768 | C# | 352 | 557 | 909 | 38.7 |
| v2_len768 | Go | 999 | 1,812 | 2,811 | 35.5 |
| v2_len768 | Java | 1,865 | 2,938 | 4,803 | 38.8 |
| v2_len768 | JavaScript | 1,670 | 3,205 | 4,875 | 34.3 |
| v2_len768 | Python | 1,404 | 2,163 | 3,567 | 39.4 |
| v2_len768 | Tổng | 11,131 | 17,440 | 28,571 | 39.0 |
| v2_len768, is_paired đúng | C | 3,399 | 3,381 | 6,780 | 50.1 |
| v2_len768, is_paired đúng | C++ | 998 | 987 | 1,985 | 50.3 |
| v2_len768, is_paired đúng | C# | 309 | 326 | 635 | 48.7 |
| v2_len768, is_paired đúng | Go | 872 | 881 | 1,753 | 49.7 |
| v2_len768, is_paired đúng | Java | 1,697 | 1,759 | 3,456 | 49.1 |
| v2_len768, is_paired đúng | JavaScript | 1,379 | 1,389 | 2,768 | 49.8 |
| v2_len768, is_paired đúng | Python | 1,260 | 1,270 | 2,530 | 49.8 |
| v2_len768, is_paired đúng | Tổng | 9,914 | 9,993 | 19,907 | 49.8 |
| v2_len768, is_paired sai | C | 378 | 1,699 | 2,077 | 18.2 |
| v2_len768, is_paired sai | C++ | 66 | 698 | 764 | 8.6 |
| v2_len768, is_paired sai | C# | 43 | 231 | 274 | 15.7 |
| v2_len768, is_paired sai | Go | 127 | 931 | 1,058 | 12.0 |
| v2_len768, is_paired sai | Java | 168 | 1,179 | 1,347 | 12.5 |
| v2_len768, is_paired sai | JavaScript | 291 | 1,816 | 2,107 | 13.8 |
| v2_len768, is_paired sai | Python | 144 | 893 | 1,037 | 13.9 |
| v2_len768, is_paired sai | Tổng | 1,217 | 7,447 | 8,664 | 14.0 |

#### Đơn vị `cvefixes_only_eval` (in_mvd_cve sai và in_mvd_func sai)

Tập kiểm tra cho thí nghiệm "huấn luyện trên MVD, kiểm tra trên CVEfixes" (đã loại các đơn vị trùng hàm với MVD).

| tập | ngôn ngữ | t=1 | t=0 | tổng | % t=1 |
|---|---|---|---|---|---|
| v2 | C | 4,572 | 6,228 | 10,800 | 42.3 |
| v2 | C++ | 823 | 1,341 | 2,164 | 38.0 |
| v2 | C# | 276 | 417 | 693 | 39.8 |
| v2 | Go | 822 | 1,238 | 2,060 | 39.9 |
| v2 | Java | 1,206 | 1,907 | 3,113 | 38.7 |
| v2 | JavaScript | 1,359 | 2,815 | 4,174 | 32.6 |
| v2 | Python | 968 | 1,483 | 2,451 | 39.5 |
| v2 | Tổng | 10,026 | 15,429 | 25,455 | 39.4 |
| v2_len768 | C | 2,803 | 3,775 | 6,578 | 42.6 |
| v2_len768 | C++ | 552 | 880 | 1,432 | 38.5 |
| v2_len768 | C# | 253 | 390 | 643 | 39.3 |
| v2_len768 | Go | 722 | 1,106 | 1,828 | 39.5 |
| v2_len768 | Java | 1,110 | 1,776 | 2,886 | 38.5 |
| v2_len768 | JavaScript | 1,123 | 2,471 | 3,594 | 31.2 |
| v2_len768 | Python | 803 | 1,244 | 2,047 | 39.2 |
| v2_len768 | Tổng | 7,366 | 11,642 | 19,008 | 38.8 |

Ngôn ngữ thiếu một nhãn trong tập này: không có.

#### Kiểm tra đủ hai nhãn ở v2_len768

Mỗi ngôn ngữ trong mỗi fold đủ hai nhãn ở train, validation và test (`assert` trong script). 15 ô (fold, phần, ngôn ngữ) có nhãn ít nhất:

| fold | phần | ngôn ngữ | target=1 | target=0 |
|---|---|---|---|---|
| 2 | val | C# | 10 | 24 |
| 0 | val | C# | 16 | 31 |
| 1 | val | C# | 18 | 47 |
| 3 | val | C# | 22 | 31 |
| 4 | val | C# | 22 | 40 |
| 3 | val | C++ | 57 | 103 |
| 0 | test | C# | 66 | 110 |
| 4 | val | C++ | 66 | 109 |
| 0 | val | C++ | 68 | 107 |
| 1 | val | C++ | 68 | 104 |
| 4 | test | C# | 69 | 115 |
| 2 | test | C# | 70 | 110 |
| 1 | test | C# | 73 | 106 |
| 3 | test | C# | 74 | 116 |
| 2 | val | C++ | 82 | 121 |

Bảng fold × ngôn ngữ (số đơn vị test của từng fold) của v2_len768:

| fold | C | C++ | C# | Go | Java | JavaScript | Python | tổng |
|---|---|---|---|---|---|---|---|---|
| 0 | 1,594 | 556 | 176 | 618 | 1,133 | 897 | 729 | 5,703 |
| 1 | 1,818 | 510 | 179 | 672 | 785 | 1,023 | 766 | 5,753 |
| 2 | 1,800 | 563 | 180 | 546 | 953 | 951 | 705 | 5,698 |
| 3 | 1,835 | 533 | 190 | 695 | 1,016 | 951 | 746 | 5,966 |
| 4 | 1,810 | 587 | 184 | 280 | 916 | 1,053 | 621 | 5,451 |

#### Tập v2_len768_paired (tập chính khi so sánh với MVD)

`groups_and_folds_cvefixes_v2_len768_paired.csv` = file fold v2_len768 chỉ giữ đơn vị có `is_paired` đúng (19,907 / 28,571 đơn vị), giữ nguyên mọi cột và giá trị, không chia lại fold (đã `assert`). Mỗi ngôn ngữ ở mỗi fold đủ hai nhãn ở train, validation và test.

Số đơn vị theo ngôn ngữ và nhãn:

| tập | ngôn ngữ | t=1 | t=0 | tổng | % t=1 |
|---|---|---|---|---|---|
| v2_len768_paired | C | 3,399 | 3,381 | 6,780 | 50.1 |
| v2_len768_paired | C++ | 998 | 987 | 1,985 | 50.3 |
| v2_len768_paired | C# | 309 | 326 | 635 | 48.7 |
| v2_len768_paired | Go | 872 | 881 | 1,753 | 49.7 |
| v2_len768_paired | Java | 1,697 | 1,759 | 3,456 | 49.1 |
| v2_len768_paired | JavaScript | 1,379 | 1,389 | 2,768 | 49.8 |
| v2_len768_paired | Python | 1,260 | 1,270 | 2,530 | 49.8 |
| v2_len768_paired | Tổng | 9,914 | 9,993 | 19,907 | 49.8 |

Số đơn vị theo fold (fold = k là tập test của fold k), ngôn ngữ và nhãn:

| fold | C t=1 | C t=0 | C++ t=1 | C++ t=0 | C# t=1 | C# t=0 | Go t=1 | Go t=0 | Java t=1 | Java t=0 | JavaScript t=1 | JavaScript t=0 | Python t=1 | Python t=0 | tổng |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 617 | 612 | 170 | 167 | 43 | 54 | 222 | 236 | 431 | 437 | 275 | 282 | 266 | 264 | 4,076 |
| 1 | 708 | 701 | 177 | 176 | 70 | 70 | 236 | 240 | 246 | 258 | 239 | 232 | 302 | 309 | 3,964 |
| 2 | 695 | 686 | 212 | 204 | 64 | 67 | 174 | 172 | 335 | 348 | 276 | 272 | 235 | 235 | 3,975 |
| 3 | 711 | 705 | 213 | 214 | 74 | 75 | 161 | 153 | 361 | 385 | 279 | 285 | 239 | 241 | 4,096 |
| 4 | 668 | 677 | 226 | 226 | 58 | 60 | 79 | 80 | 324 | 331 | 310 | 318 | 218 | 221 | 3,796 |
| Tổng | 3,399 | 3,381 | 998 | 987 | 309 | 326 | 872 | 881 | 1,697 | 1,759 | 1,379 | 1,389 | 1,260 | 1,270 | 19,907 |

Số đơn vị `cvefixes_only_eval` trong tập này:

| tập | ngôn ngữ | t=1 | t=0 | tổng | % t=1 |
|---|---|---|---|---|---|
| v2_len768_paired | C | 2,503 | 2,489 | 4,992 | 50.1 |
| v2_len768_paired | C++ | 518 | 502 | 1,020 | 50.8 |
| v2_len768_paired | C# | 218 | 228 | 446 | 48.9 |
| v2_len768_paired | Go | 626 | 634 | 1,260 | 49.7 |
| v2_len768_paired | Java | 1,012 | 1,049 | 2,061 | 49.1 |
| v2_len768_paired | JavaScript | 887 | 901 | 1,788 | 49.6 |
| v2_len768_paired | Python | 707 | 708 | 1,415 | 50.0 |
| v2_len768_paired | Tổng | 6,471 | 6,511 | 12,982 | 49.8 |

Ngôn ngữ thiếu một nhãn trong tập này: không có.

10 ô (fold, phần, ngôn ngữ) có ít nhãn nhất:

| fold | phần | ngôn ngữ | target=1 | target=0 |
|---|---|---|---|---|
| 2 | val | C# | 8 | 9 |
| 1 | val | C# | 10 | 20 |
| 3 | val | C# | 16 | 15 |
| 0 | val | C# | 16 | 16 |
| 4 | val | C# | 17 | 17 |
| 0 | test | C# | 43 | 54 |
| 3 | val | C++ | 57 | 58 |
| 4 | test | C# | 58 | 60 |
| 4 | val | C++ | 63 | 62 |
| 2 | test | C# | 64 | 67 |

## 4. Đơn vị cần lưu ý cho phân tích độ nhạy (không dùng để lọc)

(a) Đơn vị chỉ đến từ file mới thêm (`change_types` chỉ có `ModificationType.ADD`: không có bản trước/sau để so sánh, thường là mã chép vào hoặc file mới). (b) Đơn vị có ít nhất một lần xuất hiện trong 30 file JavaScript còn nhiều hàm nhất sau R0 (danh sách ở mục 3.1, file `intermediate/top30_js_files_after_r0.csv`).

| tập | ngôn ngữ | đơn vị | (a) chỉ ADD t=1 | (a) chỉ ADD t=0 | (b) 30 file JS t=1 | (b) 30 file JS t=0 |
|---|---|---|---|---|---|---|
| v1 | C | 14,543 | 0 | 232 | 0 | 0 |
| v1 | C++ | 4,420 | 0 | 226 | 0 | 0 |
| v1 | C# | 1,070 | 0 | 113 | 0 | 0 |
| v1 | Go | 4,538 | 0 | 299 | 0 | 0 |
| v1 | Java | 7,755 | 0 | 965 | 0 | 0 |
| v1 | JavaScript | 6,903 | 0 | 1,043 | 489 | 1,159 |
| v1 | Python | 7,182 | 0 | 388 | 0 | 0 |
| v1 | Tổng | 46,411 | 0 | 3,266 | 489 | 1,159 |
| v2 | C | 13,762 | 0 | 151 | 0 | 0 |
| v2 | C++ | 3,807 | 0 | 145 | 0 | 0 |
| v2 | C# | 995 | 0 | 91 | 0 | 0 |
| v2 | Go | 3,137 | 0 | 190 | 0 | 0 |
| v2 | Java | 5,183 | 0 | 491 | 0 | 0 |
| v2 | JavaScript | 5,739 | 0 | 924 | 308 | 934 |
| v2 | Python | 4,125 | 0 | 187 | 0 | 0 |
| v2 | Tổng | 36,748 | 0 | 2,179 | 308 | 934 |

## 5. Bất thường, giả định và sai khác so với đặc tả

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

## 6. SHA-256 của các file đầu ra

| file | kích thước (byte) | SHA-256 |
|---|---|---|
| `raw_functions.parquet` | 332,131,031 | `93f2f92a90a9e80e38c0adf4605bc57ccd29e33d0c49559781486805eaaaa076` |
| `units_v1.parquet` | 32,797,745 | `105fb47c46dbe1be1bc8ae5212e8b5f9223b841a5181b7b466811b4e9952d90c` |
| `units_v1.csv.gz` | 32,802,921 | `5289ac3c79f92f7d2d8f7471c31cdcd7a9608547a571b9b9224272e2e1a4a170` |
| `groups_and_folds_cvefixes_v1.csv` | 5,869,975 | `f5e70ad9d8450e11ea13967516cf540609a1142eb9c2c8621d7a34a1fa7a63a4` |
| `cluster_stats_cvefixes_v1.csv` | 407 | `6e36019e84cc29d2ce449cf322a10d0387fc3125e1746cdd9b6a332b4d433a73` |
| `excluded_units_cvefixes_v2.csv` | 845,775 | `696262756e6d1d5aaf9a9e4be6938c51885d3e9443550a5cd346927cf2beab10` |
| `groups_and_folds_cvefixes_v2.csv` | 4,638,874 | `7b41d114a580b054db807a6f419d6625b9c5c5750ab36c1f11cd40332bd958e4` |
| `groups_and_folds_cvefixes_v2_len768.csv` | 3,615,298 | `eb85736e7f207feabb090a66d346c1033402d248f74091e00fb1ebb086c3bb96` |
| `groups_and_folds_cvefixes_v2_len768_paired.csv` | 2,512,764 | `9938574e4059f0471663b84f177c9671b75be686ee34b098bc44f8e5365b7d9f` |
| `schema.md` | 12,867 | `7a872a3337b5b6988412449c7585333f39c05869a3b276a4b0de7370c70c4b0d` |
| `audit_r2_sample.md` | 30,828 | `dc55d55afa7937a6dcd54bb5564b4a6d4a5bf31eed60cedb5827583b1f61d6db` |
| `environment.txt` | 1,624 | `330ff638985b6d2dfe3735a22fa45a8022bd7f993522433e8f8d9e9ec4a29b5a` |
| `download_info.json` | 364 | `b374f2a6c84303736504d82d7a07d679f250efd4af40433a7295548aa1e5b61f` |
| `zip_listing.txt` | 1,124 | `23f7dd83cac6b4eb7731151d944cd75e4528831897e7f1f057885037e189ce78` |
| `db/build_info.json` | 906 | `2283ddf65eeed7747106de70ac4665ceeb1d02ca13fa2ca2d8dfd6466c7cb5f3` |
| `intermediate/token_lengths.parquet` | 3,073,089 | `68096b5ad045c96c3b9ac0eb11024df0143ae29de8be90d0fc0e05fb91a5498e` |
| `intermediate/unit_flags.parquet` | 2,874,606 | `22a1c034a81f7d49b3d542b8ed8388dfd7bddea9a60f3da831e70bc24490bf34` |
| `intermediate/top30_js_files_after_r0.csv` | 4,313 | `bb699534d678247fbf527c6cf510fd95ff3caedbaeaa4d59e4e7219460ff0631` |
| `scripts/01_environment.py` | 1,837 | `63512d37a7ef6a10452d20048d7aeffcb60c47e5a88567a8b7ad50271412562c` |
| `scripts/02_download.py` | 8,516 | `bf1ffb7ffdf7948b514592c895ad5e90143a686b9599cb6319f7701f3fcb1a62` |
| `scripts/03_build_db.py` | 6,067 | `4f4900141e2499286254f557e35e5923c88f7b9e7147fa3e79acd07c815203ae` |
| `scripts/04_schema.py` | 13,849 | `f967dfa334a8485545f16de1f8202f32acdc4f03c034fc4ee382b76d3124e903` |
| `scripts/05_extract.py` | 27,894 | `7c1da0641a57deb966d01c05b65940aacaa9ce41504042d8e48c0d4569cd9f0f` |
| `scripts/06_units_v1.py` | 11,012 | `9b8202f2666c267df9a7f9a204c670baa3e5b05d64eb1fc815b87340d0f318b0` |
| `scripts/07_folds_v1.py` | 6,138 | `d789aaafe2431dc6d116cc340c034c3beb90fff68e3ea74e47a3a86c914fb9df` |
| `scripts/08_clean_v2.py` | 9,250 | `cdec7ea8af82ca556ce3a6b5b36782e399031186defed8b5c9889863aa93497d` |
| `scripts/09_mvd_compare.py` | 5,710 | `a7e8a120fa06a26cf67bec208ed4be2b085cf5fb8348c9c7d37ec46be7bd2964` |
| `scripts/10_token_length.py` | 4,019 | `eb0a3918f84f3f8bf1d45ecbae4b80db648654ad8ee4f0fc3ca6bba489ed544a` |
| `scripts/10b_flags_len768.py` | 13,380 | `c9205bb7105572307bd0d8b594fb510c7e983cad0ea77068fbaad4789a2f089c` |
| `scripts/11_report.py` | 10,859 | `e28cb4a57bdbf49390b75320a91770a75498f8686c31e9a25818db46a80bacb3` |
| `scripts/12_package.py` | 2,192 | `331c94910719691cdac25c218b7b80b4c67d64b467af0cd6c247b83188c36418` |
| `scripts/common.py` | 5,038 | `862e25fb31924e8f16d3a0ff9893e431f63db97c8f50d9dc39d55de1c8b374b2` |
| `scripts/report_bat_thuong.py` | 12,710 | `9aa5201cca052396266018a4e1fb279f3a4407a304b106b5f6176d5722f89adb` |
| `clean_rules.py` (gói, không sửa) | 5,703 | `63f034b1e79b25c918c41daf0c5634e612a78db86def11aeb5935c27ed87d836` |
| `build_folds.py` (gói, không sửa) | 5,016 | `65704ec488cc670bfd64ec3fed9858b9bfcbdbe3dd5fd28a6fa98d0667054827` |
| `mvd_reference.csv` (gói, không sửa) | 1,736,992 | `35900fcd69b30167d56a084fc51bc3bff37dba590394a219dccaabedbd29730d` |

`data_report.md` không tự chứa SHA-256 của chính nó; SHA-256 của file zip gửi đi ghi ở `package_sha256.txt`.

