"""Bước 5: tập sạch kiểu MVD (v1) -> units_v1.parquet.

Theo mục 7 của đặc tả, cộng chỉnh sửa đã duyệt: bỏ các dòng có r0_reason TRƯỚC khi tính unit_id.
  1. Bỏ dòng R0; unit_id = clean_rules.unit_id(func); bỏ hàm rỗng sau chuẩn hóa.
  2. Loại mọi unit_id xuất hiện với cả hai nhãn, và mọi unit_id xuất hiện ở nhiều hơn một ngôn ngữ.
  3. Gộp các dòng cùng unit_id: func lấy từ dòng có raw_id nhỏ nhất; all_cves / all_cwes / repos / commits là
     danh sách đã TÁCH các chuỗi ";" của từng dòng thô rồi hợp lại (sắp xếp, không trùng, ngăn bởi ";");
     file_path của dòng đại diện; n_vuln_funcs_in_commit = lớn nhất; n_occurrences = số dòng thô gộp vào.
Cột thêm ngoài đặc tả: n_vuln_funcs_in_commit_raw (lớn nhất, tính trước R0) để đối chiếu.
Máy ít RAM: đọc func theo khối, chỉ giữ func của dòng đại diện.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import pandas as pd  # noqa: E402
import pyarrow.parquet as pq  # noqa: E402

CR, _BF = C.import_package_modules()

RAW = C.WORK / "raw_functions.parquet"
OUT = C.WORK / "units_v1.parquet"
INTER = C.WORK / "intermediate"
REPORT_MD = INTER / "step5.md"
REPORT_JSON = INTER / "step5.json"
META_COLS = ["raw_id", "language", "target", "cve_id", "cwe_id", "repo_url", "commit_hash", "file_path",
             "r0_reason", "is_empty", "unit_id", "n_vuln_funcs_in_commit", "n_vuln_funcs_in_commit_raw",
             "change_type", "file_change_id"]
UNIT_COLS = ["unit_id", "func", "language", "target", "all_cves", "all_cwes", "repos", "commits", "file_path",
             "n_vuln_funcs_in_commit", "n_occurrences", "n_vuln_funcs_in_commit_raw", "change_types"]
TOP_JS = INTER / "top30_js_files_after_r0.csv"
FLAGS = INTER / "unit_flags.parquet"
ONLY_ADD = "ModificationType.ADD"


def union_lists(values) -> str:
    out = set()
    for v in values:
        if isinstance(v, str) and v:
            out.update(x for x in v.split(";") if x)
    return ";".join(sorted(out))


def bucket(n: int) -> str:
    return "0" if n == 0 else "1" if n == 1 else "2–5" if n <= 5 else "6–20" if n <= 20 else ">20"


def main():
    C.check_package_hashes()
    md, js = [], {"counts": {}}
    w = md.append
    raw = pq.read_table(RAW, columns=META_COLS).to_pandas()
    js["counts"]["raw"] = C.count_dict(raw)
    n0 = len(raw)

    # 1. bỏ R0, bỏ hàm rỗng
    r0 = raw.r0_reason.notna()
    d = raw[~r0]
    js["counts"]["after_r0"] = C.count_dict(d)
    empty = d.is_empty.astype(bool)
    d = d[~empty].copy()
    js["counts"]["after_empty"] = C.count_dict(d)
    js["removed"] = {"r0": int(r0.sum()), "empty": int(empty.sum())}

    d = d.sort_values("raw_id").reset_index(drop=True)

    # 2. loại unit_id có cả hai nhãn hoặc nhiều ngôn ngữ
    nlab = d.groupby("unit_id").target.nunique()
    nlang = d.groupby("unit_id").language.nunique()
    both = set(nlab[nlab > 1].index)
    multi = set(nlang[nlang > 1].index)
    bad = both | multi
    js["removed"].update({
        "both_labels_units": len(both), "both_labels_rows": int(d.unit_id.isin(both).sum()),
        "multi_lang_units": len(multi), "multi_lang_rows": int(d.unit_id.isin(multi).sum()),
        "both_and_multi_units": len(both & multi),
        "conflict_rows": int(d.unit_id.isin(bad).sum()),
    })
    conf = d[d.unit_id.isin(bad)]
    d = d[~d.unit_id.isin(bad)]
    js["counts"]["after_conflict"] = C.count_dict(d)

    # 3. gộp thành đơn vị
    g = d.groupby("unit_id", sort=True)
    rep = d.loc[g.raw_id.idxmin()].set_index("unit_id")
    units = pd.DataFrame({
        "unit_id": rep.index,
        "language": rep.language.values,
        "target": rep.target.astype("int64").values,
        "all_cves": g.cve_id.agg(union_lists).reindex(rep.index).values,
        "all_cwes": g.cwe_id.agg(union_lists).reindex(rep.index).values,
        "repos": g.repo_url.agg(union_lists).reindex(rep.index).values,
        "commits": g.commit_hash.agg(union_lists).reindex(rep.index).values,
        "file_path": rep.file_path.values,
        "n_vuln_funcs_in_commit": g.n_vuln_funcs_in_commit.max().reindex(rep.index).astype("int64").values,
        "n_occurrences": g.size().reindex(rep.index).astype("int64").values,
        "n_vuln_funcs_in_commit_raw": g.n_vuln_funcs_in_commit_raw.max().reindex(rep.index).astype("int64").values,
        "change_types": g.change_type.agg(union_lists).reindex(rep.index).values,
        "_rep_raw_id": rep.raw_id.values,
    })
    # cờ cho phân tích độ nhạy (không dùng để lọc): chỉ đến từ file mới thêm; đến từ 30 file JS nhiều hàm nhất sau R0
    top_fc = set(pd.read_csv(TOP_JS, dtype={"file_change_id": str}).file_change_id)
    in_top = d.assign(_t=d.file_change_id.isin(top_fc)).groupby("unit_id")._t.any()
    flags = pd.DataFrame({"unit_id": units.unit_id, "only_add": units.change_types == ONLY_ADD,
                          "in_top30_js": units.unit_id.map(in_top).astype(bool)})
    flags.to_parquet(FLAGS, index=False)
    # Tính lại unit_id = clean_rules.unit_id(func) (mục 7.1) cho MỌI dòng còn lại (kể cả dòng mâu thuẫn) và đối
    # chiếu với giá trị bước 4 đã tính; chỉ giữ func của dòng đại diện trong bộ nhớ.
    check = pd.concat([d, conf])
    stored = dict(zip(check.raw_id, check.unit_id))
    rep_ids = set(units._rep_raw_id)
    funcs, n_checked = {}, 0
    for batch in pq.ParquetFile(RAW).iter_batches(batch_size=256, columns=["raw_id", "func"]):
        ids = batch.column("raw_id").to_pylist()
        if not any(i in stored for i in ids):
            continue
        for rid, f in zip(ids, batch.column("func").to_pylist()):
            if rid in stored:
                assert CR.unit_id(f) == stored[rid], f"unit_id lệch ở raw_id {rid}"
                n_checked += 1
                if rid in rep_ids:
                    funcs[rid] = f
    assert n_checked == len(stored), f"Chỉ kiểm tra được {n_checked:,} / {len(stored):,} dòng"
    units["func"] = units._rep_raw_id.map(funcs)
    units = units[UNIT_COLS].sort_values("unit_id").reset_index(drop=True)

    # kiểm tra bắt buộc (mục 13)
    assert units.unit_id.is_unique, "unit_id không duy nhất"
    assert d.groupby("unit_id").language.nunique().max() == 1 and d.groupby("unit_id").target.nunique().max() == 1
    assert units.func.notna().all() and (units.func.map(CR.normalize_func) != "").all()
    assert (units.unit_id == units.func.map(CR.unit_id)).all()
    assert (units.all_cves != "").all(), "Có đơn vị không có CVE"
    assert int(units.n_occurrences.sum()) == len(d)
    units.to_parquet(OUT, index=False, compression="zstd")
    js["counts"]["units_v1"] = C.count_dict(units)
    js["n_units"] = len(units)

    # ---------------- báo cáo
    w("## Bước 5: tập sạch v1\n")
    steps = pd.DataFrame([
        {"bước": "dòng thô (sau bước A, B)", "còn lại": n0, "bị bỏ": None, "lý do": ""},
        {"bước": "bỏ R0", "còn lại": n0 - js["removed"]["r0"], "bị bỏ": js["removed"]["r0"], "lý do": "R0 a/b/c/d (chỉnh sửa có chủ đích)"},
        {"bước": "bỏ hàm rỗng", "còn lại": len(d) + len(conf), "bị bỏ": js["removed"]["empty"], "lý do": "rỗng sau chuẩn hóa"},
        {"bước": "bỏ unit_id mâu thuẫn", "còn lại": len(d), "bị bỏ": js["removed"]["conflict_rows"],
         "lý do": f"cả hai nhãn: {js['removed']['both_labels_units']:,} unit_id / {js['removed']['both_labels_rows']:,} dòng; "
                  f"nhiều ngôn ngữ: {js['removed']['multi_lang_units']:,} unit_id / {js['removed']['multi_lang_rows']:,} dòng; "
                  f"cả hai lý do: {js['removed']['both_and_multi_units']:,} unit_id"},
        {"bước": "gộp thành đơn vị", "còn lại": len(units), "bị bỏ": len(d) - len(units), "lý do": "dòng trùng unit_id gộp lại"},
    ])
    w(C.md_table(steps) + "\n")
    cl = conf.groupby(["language", "target"]).size().unstack(fill_value=0).reindex(index=C.LANGS, columns=[1, 0], fill_value=0)
    cl.columns = ["target=1", "target=0"]
    w("Dòng bị bỏ vì unit_id mâu thuẫn, theo ngôn ngữ và nhãn:\n")
    w(C.md_table(cl.reset_index().rename(columns={"language": "ngôn ngữ"})) + "\n")
    w(f"**units_v1**: {len(units):,} đơn vị.\n")
    w(C.md_table(C.counts_table(units)) + "\n")
    occ = units.n_occurrences
    w(f"`n_occurrences`: trung vị {occ.median():.0f}, lớn nhất {occ.max():,}; đơn vị xuất hiện nhiều hơn một lần: {(occ > 1).sum():,}. "
      f"Đơn vị có nhiều hơn một CVE: {(units.all_cves.str.contains(';')).sum():,}; nhiều hơn một commit: {(units.commits.str.contains(';')).sum():,}.\n")

    w("### Phân bố `n_vuln_funcs_in_commit` (mục 12.4)\n")
    w("Tỷ lệ đơn vị v1 thuộc commit có 0, 1, 2–5, 6–20, trên 20 hàm có lỗ hổng (giá trị lớn nhất qua các lần xuất hiện). "
      "Bucket 0: đơn vị chỉ thuộc commit không có hàm target=1 nào ngoài R0 (ví dụ commit chỉ thêm hàm mới).\n")
    order = ["0", "1", "2–5", "6–20", ">20"]
    tabs = []
    for col, label in (("n_vuln_funcs_in_commit", "sau R0"), ("n_vuln_funcs_in_commit_raw", "trước R0 (raw)")):
        b = units[col].map(bucket)
        t = pd.crosstab(units.language, b).reindex(index=C.LANGS, columns=order, fill_value=0)
        t.loc["Tổng"] = t.sum()
        pct = (100 * t.div(t.sum(axis=1), axis=0)).round(1)
        pct.columns = [f"{c} (%)" for c in pct.columns]
        pct.insert(0, "số đơn vị", t.sum(axis=1))
        pct = pct.reset_index().rename(columns={"language": "ngôn ngữ"})
        tabs.append((label, pct))
        js[f"nvuln_buckets_{col}"] = pct.to_dict(orient="records")
    for label, pct in tabs:
        w(f"`n_vuln_funcs_in_commit` {label}:\n")
        w(C.md_table(pct) + "\n")

    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    REPORT_JSON.write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")
    pd.set_option("display.width", 250)
    print(steps.to_string(index=False))
    print("\nunits_v1 theo ngôn ngữ và nhãn:\n" + C.counts_table(units).to_string(index=False))
    print(f"\nĐã ghi {OUT} ({OUT.stat().st_size / 2**20:.1f} MiB)")

    # mục 2.4: một bước làm mất hơn 50% số dòng mà không rõ lý do
    for name, before, after in (("hàm rỗng", n0 - js["removed"]["r0"], len(d) + len(conf)),
                                ("unit_id mâu thuẫn", len(d) + len(conf), len(d))):
        assert after >= 0.5 * before, f"DỪNG (mục 2.4): bước '{name}' làm mất hơn 50% số dòng"


if __name__ == "__main__":
    main()
