"""Bước 9b (yêu cầu bổ sung của người dùng, 16/11/2026): thêm cột đánh dấu vào units_v1.parquet, tạo file fold v2_len768,
xuất units_v1.csv.gz. Chạy sau 10_token_length.py, trước 11_report.py. Chỉ đánh dấu, không lọc units_v1.

Cột thêm vào units_v1.parquet:
- n_tokens: độ dài token UniXcoder (lấy từ intermediate/token_lengths.parquet của bước 9).
- is_paired: đúng nếu ở ít nhất một lần xuất hiện (dòng thô không bị R0, không rỗng), trong cùng file_change có một
  dòng thô mang nhãn ngược lại và cùng method_name (cách tính như mục 6.6, cột "sau R0", áp dụng cho cả hai nhãn).
- cvefixes_only_eval: in_mvd_cve sai VÀ in_mvd_func sai.

groups_and_folds_cvefixes_v2_len768.csv = groups_and_folds_cvefixes_v2.csv bỏ các đơn vị có n_tokens > 768, giữ nguyên
mọi cột và giá trị; assert mỗi ngôn ngữ ở mỗi fold đủ hai nhãn ở train, validation và test.
groups_and_folds_cvefixes_v2_len768_paired.csv = file v2_len768 chỉ giữ đơn vị is_paired đúng, giữ nguyên mọi cột;
nếu có ô (fold, phần, ngôn ngữ) thiếu nhãn thì dừng (exit 2), không ghi file, không chia lại fold.
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

C.check_package_hashes()
MAX_LEN = 768
UNITS = C.WORK / "units_v1.parquet"
RAW = C.WORK / "raw_functions.parquet"
FOLDS_V2 = C.WORK / "groups_and_folds_cvefixes_v2.csv"
FOLDS_LEN = C.WORK / "groups_and_folds_cvefixes_v2_len768.csv"
FOLDS_PAIRED = C.WORK / "groups_and_folds_cvefixes_v2_len768_paired.csv"
CSV_GZ = C.WORK / "units_v1.csv.gz"
INTER = C.WORK / "intermediate"
TOK = INTER / "token_lengths.parquet"
REPORT_MD = INTER / "step9b.md"
REPORT_JSON = INTER / "step9b.json"
NEW_COLS = ("n_tokens", "is_paired", "cvefixes_only_eval")


def paired_unit_ids(units: pd.DataFrame) -> set:
    raw = pq.read_table(RAW, columns=["unit_id", "target", "file_change_id", "method_name", "r0_reason", "is_empty"]).to_pandas()
    pool = raw[raw.r0_reason.isna() & ~raw.is_empty.astype(bool)]
    # (file_change_id, method_name) có mặt ở từng nhãn
    keys = {t: set(zip(pool.file_change_id[pool.target == t], pool.method_name[pool.target == t])) for t in (0, 1)}
    occ = pool[pool.unit_id.isin(set(units.unit_id))]
    # mọi lần xuất hiện của đơn vị phải mang đúng nhãn của đơn vị (bước 5 đã bỏ unit_id mâu thuẫn)
    lab = occ.merge(units[["unit_id", "target"]], on="unit_id", suffixes=("", "_u"))
    assert len(lab) == len(occ) and (lab.target == lab.target_u).all()
    assert set(occ.unit_id) == set(units.unit_id), "Có đơn vị không tìm thấy lần xuất hiện nào trong raw_functions"
    has = [(fc, m) in keys[1 - t] for fc, m, t in zip(occ.file_change_id, occ.method_name, occ.target)]
    return set(occ.unit_id[pd.Series(has, index=occ.index)])


def lang_label_table(sets: dict, extra=None) -> pd.DataFrame:
    rows = []
    for name, u in sets.items():
        for l in C.LANGS + ["Tổng"]:
            s = u if l == "Tổng" else u[u.language == l]
            r = {"tập": name, "ngôn ngữ": l}
            n1, n0 = int((s.target == 1).sum()), int((s.target == 0).sum())
            r.update({"t=1": n1, "t=0": n0, "tổng": n1 + n0, "% t=1": round(100 * n1 / max(1, n1 + n0), 1)})
            if extra:
                r.update(extra(s))
            rows.append(r)
    return pd.DataFrame(rows)


def main():
    units = pd.read_parquet(UNITS)
    assert {"in_mvd_cve", "in_mvd_func"} <= set(units.columns), "Chạy 09_mvd_compare.py trước"
    units = units.drop(columns=[c for c in NEW_COLS if c in units.columns])
    n0 = len(units)

    tok = pd.read_parquet(TOK, columns=["unit_id", "n_tokens"])
    assert tok.unit_id.is_unique and set(tok.unit_id) == set(units.unit_id)
    units = units.merge(tok, on="unit_id", how="left", validate="one_to_one")
    assert units.n_tokens.notna().all() and len(units) == n0

    paired = paired_unit_ids(units)
    units["is_paired"] = units.unit_id.isin(paired)
    units["cvefixes_only_eval"] = ~units.in_mvd_cve.astype(bool) & ~units.in_mvd_func.astype(bool)
    assert units.unit_id.is_unique and len(units) == n0

    tmp = UNITS.with_suffix(".parquet.tmp")
    units.to_parquet(tmp, index=False, compression="zstd")
    tmp.replace(UNITS)

    # ---------------- fold v2_len768
    v2r = pd.read_csv(FOLDS_V2)
    ntok = units.set_index("unit_id").n_tokens
    keep = v2r.unit_id.map(ntok)
    assert keep.notna().all()
    lenr = v2r[(keep <= MAX_LEN).values].reset_index(drop=True)
    lenr.to_csv(FOLDS_LEN, index=False)
    back = pd.read_csv(FOLDS_LEN)
    assert list(back.columns) == list(v2r.columns)
    assert set(back.unit_id) <= set(v2r.unit_id) and len(back) == int((keep <= MAX_LEN).sum())
    m = back.merge(v2r, on="unit_id", suffixes=("", "_v2"), how="left", validate="one_to_one")
    for c in v2r.columns:
        if c != "unit_id":
            assert (m[c].astype(str) == m[f"{c}_v2"].astype(str)).all(), f"Cột {c} bị thay đổi ở v2_len768"
    assert (back.unit_id.map(ntok) <= MAX_LEN).all()
    assert back.groupby("group").fold.nunique().max() == 1
    tab_len, missing_len = C.split_label_check(back)
    tab_v2, missing_v2 = C.split_label_check(v2r)
    assert not missing_v2, missing_v2
    assert not missing_len, "v2_len768 thiếu nhãn: " + "; ".join(missing_len)

    # ---------------- fold v2_len768_paired: v2_len768 chỉ giữ đơn vị is_paired đúng
    pr = back[back.unit_id.isin(paired)].reset_index(drop=True)
    tab_pr, missing_pr = C.split_label_check(pr)
    if missing_pr:
        # điều kiện dừng do người dùng đặt: không tự chia lại fold, không ghi file
        print("DỪNG: v2_len768_paired thiếu nhãn ở:\n  " + "\n  ".join(missing_pr))
        sys.exit(2)
    pr.to_csv(FOLDS_PAIRED, index=False)
    backp = pd.read_csv(FOLDS_PAIRED)
    assert list(backp.columns) == list(v2r.columns)
    assert set(backp.unit_id) <= set(back.unit_id) and len(backp) == len(set(back.unit_id) & paired)
    mp = backp.merge(back, on="unit_id", suffixes=("", "_l"), how="left", validate="one_to_one")
    for c in back.columns:
        if c != "unit_id":
            assert (mp[c].astype(str) == mp[f"{c}_l"].astype(str)).all(), f"Cột {c} bị thay đổi ở v2_len768_paired"
    assert backp.unit_id.isin(paired).all() and (backp.unit_id.map(ntok) <= MAX_LEN).all()
    tab_pr, missing_pr = C.split_label_check(backp)
    assert not missing_pr

    # ---------------- xuất CSV
    tmpc = CSV_GZ.with_suffix(".gz.partial")
    units.to_csv(tmpc, index=False, encoding="utf-8", compression={"method": "gzip", "compresslevel": 6, "mtime": 0})
    tmpc.replace(CSV_GZ)
    chk = pd.read_csv(CSV_GZ, encoding="utf-8", usecols=["unit_id", "func"], keep_default_na=False)
    assert len(chk) == n0 and (chk.unit_id.values == units.unit_id.values).all()
    assert (chk.func.values == units.func.values).all(), "func đọc lại từ CSV khác parquet"

    # ---------------- báo cáo
    v2 = units[units.unit_id.isin(set(v2r.unit_id))]
    vl = units[units.unit_id.isin(set(back.unit_id))]
    md, js = [], {}
    w = md.append
    w("## Bước 9b: cột đánh dấu bổ sung, tập v2_len768 và v2_len768_paired\n")
    w(f"Thêm vào `units_v1.parquet` (chỉ đánh dấu, không lọc): `n_tokens` (bước 9), `is_paired`, `cvefixes_only_eval`. "
      f"`groups_and_folds_cvefixes_v2_len768.csv` = file fold v2 bỏ {len(v2r) - len(back):,} đơn vị có `n_tokens` > {MAX_LEN} "
      f"(còn {len(back):,} / {len(v2r):,}), giữ nguyên mọi cột và giá trị (đã `assert`).\n")
    w("`is_paired`: đúng nếu ở ít nhất một lần xuất hiện, trong cùng `file_change` có dòng thô mang nhãn ngược lại và cùng "
      "`method_name`. Chỉ xét các dòng không bị R0 (cách tính như cột *sau R0* của mục 6.6), áp dụng cho cả nhãn 1 và nhãn 0. "
      "Dòng thô của các `unit_id` mâu thuẫn bị bỏ ở bước 5 vẫn được tính làm \"bạn ghép\".\n")

    w("### Số đơn vị theo ngôn ngữ và nhãn, tách theo `is_paired`\n")
    sets = {}
    for nm, u in (("v2", v2), ("v2_len768", vl)):
        sets[nm] = u
        sets[f"{nm}, is_paired đúng"] = u[u.is_paired]
        sets[f"{nm}, is_paired sai"] = u[~u.is_paired]
    pt = lang_label_table(sets)
    w(C.md_table(pt) + "\n")

    w("### Đơn vị `cvefixes_only_eval` (in_mvd_cve sai và in_mvd_func sai)\n")
    w("Tập kiểm tra cho thí nghiệm \"huấn luyện trên MVD, kiểm tra trên CVEfixes\" (đã loại các đơn vị trùng hàm với MVD).\n")
    et = lang_label_table({"v2": v2[v2.cvefixes_only_eval], "v2_len768": vl[vl.cvefixes_only_eval]},
                          extra=None)
    w(C.md_table(et) + "\n")
    lack = [f"{r['tập']}: {r['ngôn ngữ']}" for r in et.to_dict("records")
            if r["ngôn ngữ"] != "Tổng" and (r["t=1"] == 0 or r["t=0"] == 0)]
    w("Ngôn ngữ thiếu một nhãn trong tập này: " + (", ".join(lack) if lack else "không có.") + "\n")

    w("### Kiểm tra đủ hai nhãn ở v2_len768\n")
    w("Mỗi ngôn ngữ trong mỗi fold đủ hai nhãn ở train, validation và test (`assert` trong script). "
      "15 ô (fold, phần, ngôn ngữ) có nhãn ít nhất:\n")
    small = tab_len.assign(min_label=tab_len[["target=1", "target=0"]].min(axis=1)).nsmallest(15, "min_label")
    w(C.md_table(small.drop(columns="min_label")) + "\n")
    w("Bảng fold × ngôn ngữ (số đơn vị test của từng fold) của v2_len768:\n")
    ft = back.pivot_table(index="fold", columns="language", values="unit_id", aggfunc="count", fill_value=0)
    ft = ft.reindex(columns=C.LANGS, fill_value=0)
    ft["tổng"] = ft.sum(axis=1)
    w(C.md_table(ft.reset_index()) + "\n")

    vp = units[units.unit_id.isin(set(backp.unit_id))]
    w("### Tập v2_len768_paired (tập chính khi so sánh với MVD)\n")
    w(f"`groups_and_folds_cvefixes_v2_len768_paired.csv` = file fold v2_len768 chỉ giữ đơn vị có `is_paired` đúng "
      f"({len(backp):,} / {len(back):,} đơn vị), giữ nguyên mọi cột và giá trị, không chia lại fold (đã `assert`). "
      "Mỗi ngôn ngữ ở mỗi fold đủ hai nhãn ở train, validation và test.\n")
    w("Số đơn vị theo ngôn ngữ và nhãn:\n")
    w(C.md_table(lang_label_table({"v2_len768_paired": vp})) + "\n")
    w("Số đơn vị theo fold (fold = k là tập test của fold k), ngôn ngữ và nhãn:\n")
    fp = backp.pivot_table(index="fold", columns=["language", "target"], values="unit_id", aggfunc="count", fill_value=0)
    fp = fp.reindex(columns=pd.MultiIndex.from_product([C.LANGS, [1, 0]]), fill_value=0)
    fp.columns = [f"{l} t={t}" for l, t in fp.columns]
    fp["tổng"] = fp.sum(axis=1)
    fp.loc["Tổng"] = fp.sum()
    w(C.md_table(fp.reset_index().astype({"fold": str})) + "\n")
    w("Số đơn vị `cvefixes_only_eval` trong tập này:\n")
    ep = lang_label_table({"v2_len768_paired": vp[vp.cvefixes_only_eval]})
    w(C.md_table(ep) + "\n")
    lack_p = [r["ngôn ngữ"] for r in ep.to_dict("records")
              if r["ngôn ngữ"] != "Tổng" and (r["t=1"] == 0 or r["t=0"] == 0)]
    w("Ngôn ngữ thiếu một nhãn trong tập này: " + (", ".join(lack_p) if lack_p else "không có.") + "\n")
    w("10 ô (fold, phần, ngôn ngữ) có ít nhãn nhất:\n")
    small_p = tab_pr.assign(min_label=tab_pr[["target=1", "target=0"]].min(axis=1)).nsmallest(10, "min_label")
    w(C.md_table(small_p.drop(columns="min_label")) + "\n")

    js.update({"n_v2_len768_paired": len(backp), "counts_v2_len768_paired": C.count_dict(vp),
               "cvefixes_only_eval_paired": ep.to_dict("records"), "smallest_cells_paired": small_p.to_dict("records"),
               "missing_labels_v2_len768_paired": missing_pr})
    js.update({"n_v2": len(v2r), "n_v2_len768": len(back), "n_removed_len": len(v2r) - len(back),
               "n_paired_v1": int(units.is_paired.sum()), "n_cvefixes_only_eval_v1": int(units.cvefixes_only_eval.sum()),
               "paired": pt.to_dict("records"), "cvefixes_only_eval": et.to_dict("records"),
               "missing_labels_v2_len768": missing_len, "eval_langs_missing_label": lack,
               "counts_v2_len768": C.count_dict(vl)})
    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    REPORT_JSON.write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")

    pd.set_option("display.width", 250)
    print(pt.to_string(index=False))
    print(et.to_string(index=False))
    print(f"v2 {len(v2r):,} -> v2_len768 {len(back):,} -> v2_len768_paired {len(backp):,}; thiếu nhãn: không")
    print(ep.to_string(index=False))
    print(small_p.to_string(index=False))
    print(f"is_paired (v1): {int(units.is_paired.sum()):,} / {n0:,}; cvefixes_only_eval (v1): {int(units.cvefixes_only_eval.sum()):,}")
    print(f"Đã ghi {UNITS.name}, {FOLDS_LEN.name}, {CSV_GZ.name} ({CSV_GZ.stat().st_size / 2**20:.1f} MiB)")


if __name__ == "__main__":
    main()
