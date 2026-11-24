# Phát hiện lỗ hổng trên mã nguồn đa ngôn ngữ dưới cách đánh giá chống rò rỉ theo CVE

Mã nguồn, file chia dữ liệu, kết quả và bản đăng ký trước của đề tài nghiên cứu khoa học sinh viên
**"Nghiên cứu ứng dụng mô hình ngôn ngữ trong phát hiện lỗ hổng bảo mật trên mã nguồn đa ngôn ngữ"**,
mã số **CNTT-2026-50**, Trường Đại học Xây dựng Hà Nội, năm 2026.

**Sinh viên thực hiện:** Đỗ Viết Quang Huy (trưởng nhóm, 69IT3), Mai Trung Đức (69IT3), Nguyễn Văn Cường (69IT3),
Hoàng Thanh Hằng (69IT3), Đỗ Tùng Dương (69IT6).
**Giáo viên hướng dẫn:** ThS. Vũ Thị Ngân, Đào Việt Cường.

## Đề tài trả lời câu hỏi gì

Mô hình ngôn ngữ cho mã nguồn có phát hiện được hàm có lỗ hổng khi đánh giá sao cho tập kiểm tra không chứa CVE nào
đã có trong tập huấn luyện không? Và với cách đánh giá đó:

- **Q1.** Huấn luyện riêng từng ngôn ngữ (**Mono**) đạt AUROC bao nhiêu?
- **Q2.** Gộp bảy ngôn ngữ (**Multi**), hoặc huấn luyện trên sáu ngôn ngữ rồi dùng cho ngôn ngữ thứ bảy chưa thấy
  (**LOLO**, leave-one-language-out), có khác Mono không?
- **Q3.** Cách chia dữ liệu ngẫu nhiên theo hàm, như nhiều nghiên cứu trước, làm sai lệch kết quả đến đâu và vì sao?

Bảy ngôn ngữ: C, C++, C#, Go, Java, JavaScript, Python. Chỉ số chính là AUROC macro 6 ngôn ngữ (không gồm C# vì quá ít
dữ liệu), khoảng tin cậy 95% bằng bootstrap theo cụm CVE.

## Kết quả chính

| | MVD v2, UniXcoder (10 epoch, 1 seed) | CVEfixes, UniXcoder (10 epoch, 3 seed) | MVD v2, CodeBERT | CVEfixes, CodeBERT |
| --- | --- | --- | --- | --- |
| Mono | 0,578 | 0,563 | 0,558 | 0,538 |
| Multi | 0,590 | 0,583 | 0,575 | 0,574 |
| LOLO | 0,588 | 0,585 | 0,577 | 0,574 |
| LOLO − Multi | −0,002 (tương đương) | +0,002 (tương đương) | +0,001 (tương đương) | −0,001 (tương đương) |

- Khi chia theo CVE, mọi cấu hình chỉ hơn ngẫu nhiên một chút (AUROC 0,54–0,59).
- **LOLO tương đương Multi trong cả bốn tổ hợp** (2 bộ dữ liệu × 2 mô hình): mô hình không thấy nhãn nào của ngôn ngữ
  đích vẫn đạt mức của mô hình có nhãn đó.
- Chia ngẫu nhiên theo hàm làm sai lệch kết quả **theo hướng không cố định**. Thí nghiệm can thiệp cho thấy cơ chế:
  khi bản lỗi và bản sửa của cùng một hàm (cặp sinh đôi, ngược nhãn) bị tách ra hai phía, mô hình xếp hạng các cặp đó
  dưới mức ngẫu nhiên (0,378); chỉ cần giữ hai bản cùng một phía, con số lên 0,715.

Toàn bộ bảng kết quả: chạy `python make_tables.py` (xem bên dưới) hoặc đọc báo cáo tổng kết.

## Đăng ký trước

Thiết kế, giả thuyết và tiêu chí kết luận được đăng ký trên OSF **trước khi** chạy. Mỗi lần mở rộng có một bản bổ sung
đăng ký trước khi chạy phần đó. Bản PDF nằm trong `preregistration/`.

| Bản | Nội dung | OSF |
| --- | --- | --- |
| Gốc (12/11/2026) | Mono, Multi, LOLO trên MVD, chia theo cụm CVE | [osf.io/96a2g](https://osf.io/96a2g) |
| Bổ sung lần 1 | So sánh với cách chia ngẫu nhiên theo hàm | [osf.io/qb92v](https://osf.io/qb92v) |
| Bổ sung lần 2 | Dữ liệu sạch v2, 5 và 10 epoch | [osf.io/ng3ty](https://osf.io/ng3ty) |
| Bổ sung lần 3 | Thí nghiệm can thiệp cặp sinh đôi | [osf.io/bqhcy](https://osf.io/bqhcy) |
| Bổ sung lần 4 | Lặp lại trên CVEfixes | [osf.io/dkxrf](https://osf.io/dkxrf) |
| Bổ sung lần 5 | Thêm seed 29 và 43 cho CVEfixes | [osf.io/bm36f](https://osf.io/bm36f) |
| Bổ sung lần 6 | Lặp lại với CodeBERT | [osf.io/79cbe](https://osf.io/79cbe) |

Các bản đăng ký ghi mã SHA-256 của mã và file chia dữ liệu. Kiểm tra repo này khớp với bản đã đăng ký:

```bash
python verify_checksums.py
```

## Cấu trúc repo

```
├── preregistration/      bản đăng ký gốc và 6 bản bổ sung (PDF)
├── configs/              cấu hình mô hình và bộ nạp dữ liệu
├── src/
│   ├── preprocessing/    nạp MVD, bỏ trùng lặp, tách từ
│   ├── training/         chia fold, huấn luyện (run_*.py), phân tích (*_analysis.py)
│   └── data_prep/        dựng tập sạch và file fold cho MVD và CVEfixes
├── data/
│   ├── mvd_v1/           file fold MVD v1 (chia theo CVE, ngẫu nhiên, cặp sinh đôi)
│   ├── mvd_v2/           file fold dữ liệu sạch v2 và danh sách hàm bị loại kèm lý do
│   ├── cvefixes/         file fold CVEfixes, báo cáo dữ liệu (tập hàm units_v1.parquet ở mục Releases)
│   └── manual_labels/    105 hàm "có lỗ hổng" của MVD v2 do nhóm chấm thủ công
├── notebooks/            notebook Kaggle đã dùng, xếp theo thí nghiệm
├── results/              bảng kết quả CSV của từng thí nghiệm
├── make_tables.py        in lại các bảng chính từ results/
├── verify_checksums.py   kiểm tra mã băm so với bản đăng ký
└── CHECKSUMS.sha256
```

## Thí nghiệm, mã và kết quả

| Thí nghiệm | Đăng ký | Notebook | Mã huấn luyện | Mã phân tích | Kết quả | Mục trong báo cáo |
| --- | --- | --- | --- | --- | --- | --- |
| MVD v1, 5 epoch, seed 17, 29, 43 | gốc | `notebooks/01_*` | `run_grouped_cv.py` | `grouped_cv_analysis.py` | `results/01–03_*` | 4.2–4.6 |
| Chia ngẫu nhiên theo hàm | lần 1 | `notebooks/02_*` | `run_grouped_cv.py` | `leak_compare_analysis.py` | `results/04_*` | 4.7 |
| MVD v2, 5 và 10 epoch | lần 2 | `notebooks/03_*` | `run_grouped_cv_v2.py` | `grouped_cv_analysis.py` | `results/05_*`, `06_*` | 4.8 |
| Cặp sinh đôi | lần 3 | `notebooks/04_*` | `run_grouped_cv.py` | `twin_analysis.py` | `results/07_*` | 4.10 |
| CVEfixes, seed 17 | lần 4 | `notebooks/05_*` | `run_cvefixes.py` | `cvf_analysis.py` | `results/08_*` | 4.11 |
| CVEfixes, seed 29 và 43 | lần 5 | `notebooks/06_*` | `run_cvefixes.py` | `cvf_seeds_analysis.py` | `results/09_*` | 4.11 |
| CodeBERT | lần 6 | `notebooks/07_*` | `run_codebert.py` | `codebert_analysis.py` | `results/10_*` | 4.12 |
| Phân tích thăm dò (không đăng ký) | – | – | – | `thamdo_analysis.py` | `results/11_*` | 4.13 |

Mọi file mã nằm trong `src/training/`. Tổng cộng 574 lần huấn luyện, khoảng 668 giờ GPU (Kaggle, T4).

## Cách dùng

### 1. Xem lại các bảng (chỉ cần Python và pandas)

```bash
pip install pandas
python make_tables.py            # mọi bảng
python make_tables.py cvefixes   # chỉ các bảng về CVEfixes
```

### 2. Tái lập phân tích từ file dự đoán (chỉ cần CPU)

File dự đoán của cả 574 lần huấn luyện nằm ở mục **Releases** của repo (8 file zip, tổng khoảng 110 MB), cùng
file `units_v1.parquet` của CVEfixes (đặt vào `data/cvefixes/`). Tải và giải nén,
rồi chạy mã phân tích tương ứng. Ví dụ, phân tích thăm dò:

```bash
pip install -r requirements.txt
python src/training/thamdo_analysis.py \
  --mvd-pred <giải nén predictions_05>/e10 --mvd-folds data/mvd_v2/groups_and_folds_v2.csv \
  --mvd-cwe data/mvd_v2/mvd_v2_cwe.csv \
  --cvf-pred <giải nén predictions_07>/e10 --cvf-folds data/cvefixes/groups_and_folds_cvefixes_v2_len768_paired.csv \
  --cvf-units data/cvefixes/units_v1.parquet --res out/thamdo
```

Phân tích ba seed của CVEfixes:

```bash
python src/training/cvf_seeds_analysis.py <giải nén predictions_07> data/cvefixes/units_v1.parquet \
  data/cvefixes/groups_and_folds_cvefixes_v2_len768_paired.csv out/cvf_3seed 17 29 43
```

Cách gọi các mã phân tích khác ghi ở đầu từng file. Bootstrap dùng seed cố định 20260101, nên kết quả trùng khớp
với file trong `results/`.

### 3. Dựng lại dữ liệu và file fold

**MVD.** Repo này không đăng lại dữ liệu MVD vì bộ dữ liệu gốc không kèm giấy phép. Tải ba file `train_w_line.csv`,
`val_w_line.csv`, `test_w_line.csv` theo hướng dẫn ở repo của nhóm tác giả
([Shu và cs.](https://github.com/SpanShu96/Large-Language-Model-for-Multilingual-Vulnerability-Detection)), đặt vào
`data/raw/`, rồi chạy từ thư mục gốc:

```bash
python src/data_prep/mvd/make_clean_pkl.py                          # tập sạch 18.694 hàm -> work/clean.pkl
python src/data_prep/mvd/build_groups_v1.py work/clean.pkl work/    # cụm CVE và 5 fold -> groups_and_folds_v1.csv
python src/training/build_random_folds.py data/mvd_v1/groups_and_folds_v1.csv work/random_folds_v1.csv
python src/training/build_twin_folds.py data/mvd_v1/random_folds_v1.csv data/mvd_v1/groups_and_folds_v1.csv work/twin_folds_v1.csv
mkdir -p work/v2 && python src/data_prep/mvd/build_v2.py && python src/data_prep/mvd/make_folds_v2.py   # dữ liệu sạch v2
```

Mã định danh `unit_id` của mỗi hàm là SHA-256 của nội dung hàm (sau khi đổi CRLF thành LF và bỏ khoảng trắng hai đầu),
nên file fold ghép được với dữ liệu gốc. Các lệnh trên cho ra đúng từng byte các file fold trong `data/` (cùng mã băm
với bản đăng ký).

**CVEfixes.** Các file fold có sẵn trong `data/cvefixes/`. Tập hàm đã lọc `units_v1.parquet` (33 MB) nằm ở mục
**Releases**: tải về và đặt vào `data/cvefixes/` trước khi chạy các lệnh có `data/cvefixes/units_v1.parquet`. Muốn dựng lại từ
đầu: chạy lần lượt các script trong `src/data_prep/cvefixes/` (tải CVEfixes v1.0.8 từ Zenodo, dựng cơ sở dữ liệu,
trích hàm, lọc, chia fold). Quy tắc lọc và số liệu từng bước ghi trong `data/cvefixes/docs/data_report.md`.

### 4. Huấn luyện lại (cần GPU)

Các notebook trong `notebooks/` chạy trên Kaggle (GPU T4 × 2, phiên 9 giờ). Mỗi notebook cần hai dataset làm Input:
repo này (notebook tự tìm `src/preprocessing/dataset_loader.py`) kèm ba file MVD trong `data/raw/`, và với CVEfixes,
các file trong `data/cvefixes/`. Notebook tự kiểm tra mã băm của mã huấn luyện trước khi chạy, tự nạp lại kết quả của
phiên trước nếu bị ngắt, và nén kết quả thành một file zip ở cuối.

Môi trường ghi trong nhật ký mỗi lần chạy: GPU Tesla T4, PyTorch 2.11.0, Transformers 5.20.2; mô hình
`microsoft/unixcoder-base-nine` (revision `5f0dc256eb0904af496d427451da5d7f90261676`) và `microsoft/codebert-base`
(revision `3b0952feddeffad0063f274080e3c23d75e7eb39`).

## Nhãn chấm thủ công

`data/manual_labels/mvd_v2_105_cap_cham_nhan.csv`: 105 hàm có nhãn "có lỗ hổng" trong MVD v2, chọn ngẫu nhiên 15 hàm
mỗi ngôn ngữ (seed 20261115, mã chọn mẫu ở `src/data_prep/mvd/sample_manual_labels.py`). Với mỗi hàm, nhóm đọc mô tả
CVE trên NVD và commit sửa lỗi, rồi chấm **Đúng** (thay đổi trong hàm sửa đúng lỗ hổng CVE mô tả), **Sai** (thay đổi
không liên quan đến lỗ hổng) hoặc **Không chắc**, kèm lý do. Kết quả: 70 Đúng, 34 Sai, 1 Không chắc. File không chứa
mã nguồn; xem mã qua cột `link_commit`.

## Giấy phép

- Mã nguồn: [MIT](LICENSE).
- Dữ liệu và kết quả do nhóm tạo (file fold, nhãn chấm thủ công, bảng kết quả, file dự đoán): [CC BY 4.0](LICENSE-DATA.md).
- `units_v1.parquet` (mục Releases) là dữ liệu dẫn xuất từ CVEfixes (Bhandari và cs., 2021), giấy phép CC BY 4.0.
- Dữ liệu gốc của MVD không nằm trong repo.

## Trích dẫn

Nếu dùng mã hoặc dữ liệu của repo, vui lòng trích dẫn đề tài (xem `CITATION.cff`):

> Đỗ Viết Quang Huy, Mai Trung Đức, Nguyễn Văn Cường, Hoàng Thanh Hằng, Đỗ Tùng Dương (2026). Nghiên cứu ứng dụng mô
> hình ngôn ngữ trong phát hiện lỗ hổng bảo mật trên mã nguồn đa ngôn ngữ. Đề tài NCKH sinh viên CNTT-2026-50,
> Trường Đại học Xây dựng Hà Nội.
