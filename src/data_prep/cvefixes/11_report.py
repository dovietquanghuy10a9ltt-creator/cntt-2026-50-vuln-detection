"""Viết data_report.md theo mục 12 của đặc tả, ghép từ kết quả của các bước (intermediate/step*.md, *.json)."""
from __future__ import annotations
import datetime as dt
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import pandas as pd  # noqa: E402
import pyarrow.parquet as pq  # noqa: E402

import report_bat_thuong  # noqa: E402

C.check_package_hashes()
INTER = C.WORK / "intermediate"
OUT = C.WORK / "data_report.md"
OUTPUTS = ["raw_functions.parquet", "units_v1.parquet", "units_v1.csv.gz", "groups_and_folds_cvefixes_v1.csv",
           "cluster_stats_cvefixes_v1.csv", "excluded_units_cvefixes_v2.csv", "groups_and_folds_cvefixes_v2.csv",
           "groups_and_folds_cvefixes_v2_len768.csv", "groups_and_folds_cvefixes_v2_len768_paired.csv", "schema.md", "audit_r2_sample.md", "environment.txt", "download_info.json", "zip_listing.txt",
           "db/build_info.json", "intermediate/token_lengths.parquet", "intermediate/unit_flags.parquet",
           "intermediate/top30_js_files_after_r0.csv"]


def jload(name):
    return json.loads((INTER / name).read_text(encoding="utf-8"))


def demote(md: str, by: int = 1) -> str:
    return re.sub(r"(?m)^(#+) ", lambda m: "#" * (len(m.group(1)) + by) + " ", md)


def stage_row(name, d, removed=None, reason=""):
    row = {"bước": name}
    tot = 0
    for l in C.LANGS:
        row[f"{l} t=1"], row[f"{l} t=0"] = d[l]["1"], d[l]["0"]
        tot += d[l]["1"] + d[l]["0"]
    row["tổng"] = tot
    row["bị bỏ"] = removed
    row["lý do"] = reason
    return row


def main():
    info = json.loads((C.WORK / "download_info.json").read_text(encoding="utf-8"))
    build = json.loads((C.DB_DIR / "build_info.json").read_text(encoding="utf-8"))
    s4, s5, s6, s7, s8 = (jload(f"step{i}.json") for i in (4, 5, 6, 7, 8))
    s9b = jload("step9b.json")

    # số dòng qua từng bước
    meta = pd.read_parquet(INTER / "method_meta.parquet", columns=["file_change_id", "before_change"])
    fc = pd.read_parquet(INTER / "file_change_slim.parquet", columns=["file_change_id", "programming_language"])
    meta = meta.merge(fc, on="file_change_id")
    meta["target"] = (meta.before_change == "True").astype(int)
    raw = pq.read_table(C.WORK / "raw_functions.parquet", columns=["language", "target", "r0_reason", "is_empty"]).to_pandas()
    units = pd.read_parquet(C.WORK / "units_v1.parquet", columns=["unit_id", "language", "target", "change_types"])
    v2_ids = set(pd.read_csv(C.WORK / "groups_and_folds_cvefixes_v2.csv", usecols=["unit_id"]).unit_id)
    v2 = units[units.unit_id.isin(v2_ids)]
    flags = pd.read_parquet(INTER / "unit_flags.parquet")
    lang = s4["lang"]
    stages = [
        stage_row("method_change thuộc 7 ngôn ngữ (theo programming_language)", C.count_dict(meta, "programming_language"),
                  None, f"bảng có {len(meta):,} dòng; bước A bỏ {lang['A_dropped']:,} dòng của ngôn ngữ khác"),
        stage_row("sau bước A, B (dòng thô, raw_functions.parquet)", C.count_dict(raw), lang["B_dropped"],
                  "bước B: chuyển ngôn ngữ theo đuôi file, bỏ đuôi của ngôn ngữ/định dạng khác"),
        stage_row("sau bỏ R0", s5["counts"]["after_r0"], s5["removed"]["r0"], "R0 a/b/c/d"),
        stage_row("sau bỏ hàm rỗng", s5["counts"]["after_empty"], s5["removed"]["empty"], "rỗng sau chuẩn hóa"),
        stage_row("sau bỏ unit_id mâu thuẫn", s5["counts"]["after_conflict"], s5["removed"]["conflict_rows"],
                  "cả hai nhãn hoặc nhiều ngôn ngữ"),
        stage_row("units_v1 (đơn vị)", s5["counts"]["units_v1"], None, "gộp dòng cùng unit_id"),
        stage_row("v2 (đơn vị)", C.count_dict(v2), s7["n_excluded"], "R1, R2, R3"),
        stage_row("v2_len768 (đơn vị)", s9b["counts_v2_len768"], s9b["n_removed_len"],
                  "n_tokens > 768 (sai khác có chủ đích, mục 5.1)"),
        stage_row("v2_len768_paired (đơn vị)", s9b["counts_v2_len768_paired"],
                  s9b["n_v2_len768"] - s9b["n_v2_len768_paired"], "is_paired sai (sai khác có chủ đích, mục 5.1)"),
    ]
    st = pd.DataFrame(stages)
    st["bị bỏ"] = pd.Series([None if r["bị bỏ"] is None else int(r["bị bỏ"]) for r in stages], dtype=object)

    md = []
    w = md.append
    w("# Báo cáo dữ liệu CVEfixes v2 (đề tài CNTT-2026-50)\n")
    w(f"Ngày tạo báo cáo: {dt.date.today().isoformat()}. Mọi số liệu do các script trong `scripts/` sinh ra; chạy lại "
      "theo thứ tự `01` → `10`, `10b`, `11`, `12` cho cùng kết quả.\n")

    w("## 1. Nguồn dữ liệu\n")
    w(C.md_table(pd.DataFrame([
        {"mục": "Bộ dữ liệu", "giá trị": f"CVEfixes {info['version']} (công bố {info['publication_date']}), DOI {info['doi']}"},
        {"mục": "Nguồn", "giá trị": info["source"]},
        {"mục": "File tải", "giá trị": f"`{info['file_name']}`, {info['size_bytes']:,} byte ({info['size_bytes'] / 2**30:.2f} GiB)"},
        {"mục": "MD5 (Zenodo / tính lại)", "giá trị": f"`{info['md5_zenodo']}` / `{info['md5_computed']}` (khớp)"},
        {"mục": "Ngày tải", "giá trị": info["download_date"]},
        {"mục": "Bản dump SQL trong zip", "giá trị": f"`{build['dump_entry']}`: {build['dump_gz_bytes']:,} byte nén; "
                                                      f"{build['dump_sql_bytes']:,} byte ({build['dump_sql_bytes'] / 2**30:.2f} GiB) sau giải nén (đọc thẳng từ zip, không ghi ra đĩa)"},
        {"mục": "Cơ sở dữ liệu SQLite", "giá trị": f"`cvefixes_work/{build['db_path']}`, {build['db_size_bytes']:,} byte ({build['db_size_bytes'] / 2**30:.2f} GiB), "
                                                    f"{build['n_statements']:,} câu lệnh SQL, PRAGMA quick_check = ok"},
        {"mục": "Dung lượng đĩa cần", "giá trị": f"khoảng {(info['size_bytes'] + build['db_size_bytes']) / 2**30:.0f} GiB (zip + SQLite), "
                                                  f"cộng `raw_functions.parquet` {(C.WORK / 'raw_functions.parquet').stat().st_size / 2**30:.1f} GiB"},
    ])) + "\n")

    w("## 2. Số lượng qua từng bước\n")
    w("Số dòng (đến `sau bỏ unit_id mâu thuẫn`) hoặc số đơn vị (bốn hàng cuối), theo ngôn ngữ và nhãn:\n")
    w(C.md_table(st) + "\n")
    w(f"Chi tiết lý do loại ở từng bước nằm trong mục 3. Bước 5 loại {s5['removed']['both_labels_units']:,} unit_id mang cả hai nhãn "
      f"({s5['removed']['both_labels_rows']:,} dòng) và {s5['removed']['multi_lang_units']:,} unit_id ở nhiều ngôn ngữ "
      f"({s5['removed']['multi_lang_rows']:,} dòng).\n")

    w("## 3. Chi tiết từng bước\n")
    w("Bao gồm: tỷ lệ ghép cặp (mục 12.3) ở 3.1, phân bố `n_vuln_funcs_in_commit` (mục 12.4) ở 3.2, thống kê cụm và "
      "bảng fold × ngôn ngữ (mục 12.6) ở 3.3, số hàm bị loại theo R1/R2/R3 (mục 12.5) ở 3.4, đối chiếu MVD (mục 12.7) ở 3.5, "
      "độ dài token (mục 12.8) ở 3.6. Mục 3.7 (yêu cầu bổ sung): tập v2_len768, số đơn vị tách theo `is_paired` kèm tỷ lệ "
      "nhãn 1, tập kiểm tra `cvefixes_only_eval`, và tập v2_len768_paired (tập chính khi so sánh với MVD).\n")
    for i, step in enumerate(("4", "5", "6", "7", "8", "9", "9b"), 1):
        body = (INTER / f"step{step}.md").read_text(encoding="utf-8")
        body, n = re.subn(r"(?m)^## (Bước \w+)", lambda m: f"## 3.{i}. {m.group(1)}", body, count=1)
        assert n == 1, f"step{step}.md thiếu tiêu đề '## Bước ...'"
        w(demote(body).rstrip() + "\n")

    w("## 4. Đơn vị cần lưu ý cho phân tích độ nhạy (không dùng để lọc)\n")
    w("(a) Đơn vị chỉ đến từ file mới thêm (`change_types` chỉ có `ModificationType.ADD`: không có bản trước/sau để so sánh, "
      "thường là mã chép vào hoặc file mới). (b) Đơn vị có ít nhất một lần xuất hiện trong 30 file JavaScript còn nhiều hàm nhất "
      "sau R0 (danh sách ở mục 3.1, file `intermediate/top30_js_files_after_r0.csv`).\n")
    f = units.merge(flags, on="unit_id")
    rows = []
    for name, u in (("v1", f), ("v2", f[f.unit_id.isin(v2_ids)])):
        for l in C.LANGS + ["Tổng"]:
            s = u if l == "Tổng" else u[u.language == l]
            rows.append({"tập": name, "ngôn ngữ": l, "đơn vị": len(s),
                         "(a) chỉ ADD t=1": int((s.only_add & (s.target == 1)).sum()),
                         "(a) chỉ ADD t=0": int((s.only_add & (s.target == 0)).sum()),
                         "(b) 30 file JS t=1": int((s.in_top30_js & (s.target == 1)).sum()),
                         "(b) 30 file JS t=0": int((s.in_top30_js & (s.target == 0)).sum())})
    sens = pd.DataFrame(rows)
    w(C.md_table(sens) + "\n")

    w("## 5. Bất thường, giả định và sai khác so với đặc tả\n")
    # Văn bản do người viết (ghi chép các quyết định đã được người dùng duyệt), trong scripts/report_bat_thuong.py.
    w(report_bat_thuong.TEXT.strip() + "\n")

    w("## 6. SHA-256 của các file đầu ra\n")
    rows = []
    for name in OUTPUTS:
        p = C.WORK / name
        if p.exists():
            rows.append({"file": f"`{name}`", "kích thước (byte)": p.stat().st_size, "SHA-256": f"`{C.file_hash(p)}`"})
    for p in sorted(C.SCRIPTS.glob("*.py")):
        rows.append({"file": f"`scripts/{p.name}`", "kích thước (byte)": p.stat().st_size, "SHA-256": f"`{C.file_hash(p)}`"})
    for name, h in C.EXPECTED_SHA256.items():
        rows.append({"file": f"`{name}` (gói, không sửa)", "kích thước (byte)": (C.ROOT / name).stat().st_size, "SHA-256": f"`{h}`"})
    w(C.md_table(pd.DataFrame(rows)) + "\n")
    w("`data_report.md` không tự chứa SHA-256 của chính nó; SHA-256 của file zip gửi đi ghi ở `package_sha256.txt`.\n")

    text = "\n".join(md) + "\n"
    # mỗi tiêu đề mục chỉ xuất hiện một lần, mục 5 nằm trước mục 6
    heads = re.findall(r"(?m)^#{2,3} (\d+(?:\.\d+)*)\.? ", text)
    assert len(heads) == len(set(heads)), f"Tiêu đề bị lặp: {[h for h in heads if heads.count(h) > 1]}"
    assert heads.index("5.4") < heads.index("6") and heads[-1] == "6"
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"Đã ghi {OUT} ({OUT.stat().st_size / 1024:.0f} KiB)")
    pd.set_option("display.width", 250)
    print(st.to_string(index=False))
    print(sens.to_string(index=False))


if __name__ == "__main__":
    main()
