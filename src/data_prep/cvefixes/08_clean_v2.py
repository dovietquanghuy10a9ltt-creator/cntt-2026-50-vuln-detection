"""Bước 7: áp dụng quy tắc làm sạch v2 (clean_rules.apply_v2_rules, nguyên bản) lên units_v1.

Đầu ra: excluded_units_cvefixes_v2.csv, groups_and_folds_cvefixes_v2.csv (= file fold v1 bỏ các dòng bị loại,
giữ nguyên mọi cột), audit_r2_sample.md (30 hàm bị loại chỉ vì đường dẫn + 20 nhóm R1 có diff).
"""
from __future__ import annotations
import difflib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import pandas as pd  # noqa: E402

CR, BF = C.import_package_modules()

UNITS = C.WORK / "units_v1.parquet"
FOLDS_V1 = C.WORK / "groups_and_folds_cvefixes_v1.csv"
FOLDS_V2 = C.WORK / "groups_and_folds_cvefixes_v2.csv"
EXCL = C.WORK / "excluded_units_cvefixes_v2.csv"
AUDIT = C.WORK / "audit_r2_sample.md"
INTER = C.WORK / "intermediate"
REPORT_MD = INTER / "step7.md"
REPORT_JSON = INTER / "step7.json"
N_R2, N_R1 = 30, 20


def head3(func: str) -> str:
    return "\n".join(CR.normalize_func(func).split("\n")[:3])


def fence(text: str, lang: str = "") -> str:
    tick = "````" if "```" in text else "```"
    return f"{tick}{lang}\n{text}\n{tick}"


def main():
    C.check_package_hashes()
    units = pd.read_parquet(UNITS, columns=["unit_id", "func", "language", "target", "file_path", "repos"])
    flags = CR.apply_v2_rules(units[["unit_id", "func", "language", "target", "file_path"]], path_col="file_path")
    assert (flags.unit_id.values == units.unit_id.values).all()

    ex = flags[flags.exclude].copy()
    ex["reason"] = ex.R1.map({True: "R1"}).fillna(ex.R2.map({True: "R2"})).fillna(ex.R3.map({True: "R3"}))
    assert ex.reason.notna().all()
    excl = ex[["unit_id", "language", "target", "reason", "R2_decl", "R2_path"]].sort_values("unit_id").reset_index(drop=True)
    excl.to_csv(EXCL, index=False)

    v1 = pd.read_csv(FOLDS_V1)
    v2 = v1[~v1.unit_id.isin(set(excl.unit_id))].reset_index(drop=True)
    v2.to_csv(FOLDS_V2, index=False)

    # ---- kiểm tra bắt buộc (mục 13): v2 là tập con đúng của v1, mọi cột giữ nguyên
    v2r = pd.read_csv(FOLDS_V2)
    v1r = pd.read_csv(FOLDS_V1)
    assert list(v2r.columns) == list(v1r.columns)
    assert len(v2r) == len(v1r) - len(excl) and len(v2r) < len(v1r)
    assert set(v2r.unit_id) <= set(v1r.unit_id)
    merged = v2r.merge(v1r, on="unit_id", suffixes=("", "_v1"), how="left", validate="one_to_one")
    for c in v1r.columns:
        if c != "unit_id":
            assert (merged[c].astype(str) == merged[f"{c}_v1"].astype(str)).all(), f"Cột {c} bị thay đổi ở v2"
    assert set(v2r.unit_id).isdisjoint(set(excl.unit_id))
    assert v2r.groupby("group").fold.nunique().max() == 1

    md, js = [], {}
    w = md.append
    w("## Bước 7: quy tắc làm sạch v2\n")
    w("`clean_rules.apply_v2_rules` nguyên bản, `path_col=\"file_path\"`. R1: nhóm cùng ngôn ngữ, cùng dãy token "
      "(bỏ chú thích/khoảng trắng) mang cả hai nhãn; R2: hàm kiểm thử theo khai báo (4 dòng đầu) hoặc theo đường dẫn; "
      "R3: trùng dãy token cùng nhãn, giữ unit_id nhỏ nhất. `reason` ưu tiên R1, rồi R2, rồi R3.\n")
    rows = []
    for l in C.LANGS + ["Tổng"]:
        f = flags if l == "Tổng" else flags[flags.language == l]
        e = ex if l == "Tổng" else ex[ex.language == l]
        r2 = e[e.reason == "R2"]
        rows.append({"ngôn ngữ": l, "đơn vị v1": len(f),
                     "R1": int((e.reason == "R1").sum()),
                     "R2 chỉ khai báo": int((r2.R2_decl & ~r2.R2_path).sum()),
                     "R2 chỉ đường dẫn": int((~r2.R2_decl & r2.R2_path).sum()),
                     "R2 cả hai": int((r2.R2_decl & r2.R2_path).sum()),
                     "R3": int((e.reason == "R3").sum()),
                     "tổng bị loại": len(e), "% bị loại": round(100 * len(e) / max(1, len(f)), 1),
                     "R2 (mọi đơn vị thỏa, kể cả trong R1)": int(f.R2.sum()),
                     "R2_decl (mọi đơn vị)": int(f.R2_decl.sum()), "R2_path (mọi đơn vị)": int(f.R2_path.sum())})
    rt = pd.DataFrame(rows)
    w("Số đơn vị bị loại theo lý do (theo `reason`), và số đơn vị thỏa từng điều kiện R2 không xét ưu tiên:\n")
    w(C.md_table(rt) + "\n")
    lt = ex.groupby(["language", "reason", "target"]).size().unstack(["reason", "target"], fill_value=0)
    lt = lt.reindex(index=C.LANGS, columns=pd.MultiIndex.from_product([["R1", "R2", "R3"], [1, 0]]), fill_value=0)
    lt.columns = [f"{r} t={t}" for r, t in lt.columns]
    w("Theo nhãn:\n")
    w(C.md_table(lt.reset_index().rename(columns={"language": "ngôn ngữ"})) + "\n")

    units_v2 = units[~units.unit_id.isin(set(excl.unit_id))]
    w(f"**v2**: {len(v2r):,} đơn vị (bỏ {len(excl):,} trên {len(v1r):,}).\n")
    w(C.md_table(C.counts_table(units_v2)) + "\n")

    tab, missing = C.split_label_check(v2r)
    w("### Kiểm tra đủ hai nhãn sau khi bỏ (v2)\n")
    w("Mỗi ngôn ngữ trong mỗi fold, ở train (fold ≠ k, không thuộc inner_val_fold{k}), validation (inner_val_fold{k}) và test (fold = k):\n")
    if missing:
        w(f"**Thiếu {len(missing)} trường hợp:**\n")
        w("\n".join(f"- {m}" for m in missing) + "\n")
    else:
        w("Đủ cả hai nhãn ở mọi ngôn ngữ, mọi fold, mọi phần.\n")
    small = tab.assign(min_label=tab[["target=1", "target=0"]].min(axis=1)).sort_values("min_label").head(15)
    w("15 ô (fold, phần, ngôn ngữ) có nhãn ít nhất:\n")
    w(C.md_table(small.drop(columns="min_label")) + "\n")
    js.update({"n_v2": len(v2r), "n_excluded": len(excl), "missing_labels_v2": missing,
               "excluded_by_reason": excl.reason.value_counts().to_dict()})

    # ---- kiểm tra bằng mắt
    rng = random.Random(C.SAMPLE_SEED)
    a = []
    a.append("# Kiểm tra bằng mắt các quy tắc v2 trên CVEfixes\n")
    a.append(f"Lấy mẫu bằng `random.Random({C.SAMPLE_SEED})` trên danh sách đã sắp xếp theo `unit_id` (chạy lại cho cùng mẫu).\n")
    only_path = ex[(ex.reason == "R2") & ex.R2_path & ~ex.R2_decl].sort_values("unit_id")
    pick = sorted(rng.sample(range(len(only_path)), min(N_R2, len(only_path))))
    sp = only_path.iloc[pick].merge(units[["unit_id", "file_path", "func", "repos"]], on="unit_id", suffixes=("", "_u"))
    a.append(f"## 1. {len(sp)} hàm bị loại chỉ vì đường dẫn (R2_path đúng, R2_decl sai), trên tổng {len(only_path):,}\n")
    a.append("Cột *đánh giá* để trống cho người kiểm tra điền (đúng là mã kiểm thử / không phải).\n")
    for i, r in enumerate(sp.itertuples(), 1):
        a.append(f"### 1.{i}. {r.language}, target={r.target}\n")
        a.append(f"- `file_path`: `{r.file_path}`")
        a.append(f"- repo: {r.repos}")
        a.append(f"- unit_id: `{r.unit_id}`")
        a.append("- đánh giá: \n")
        a.append(fence(head3(r.func)) + "\n")

    r1 = flags[flags.R1].sort_values("unit_id")
    groups = sorted(r1.groupby(["language", "tokkey"]).groups.keys())
    gpick = sorted(rng.sample(range(len(groups)), min(N_R1, len(groups))))
    a.append(f"## 2. {len(gpick)} nhóm R1 (cặp ngược nhãn chỉ khác định dạng/chú thích), trên tổng {len(groups):,} nhóm\n")
    a.append("Mỗi nhóm: lấy đơn vị target=1 và target=0 có unit_id nhỏ nhất, hiện diff (dòng `-` là bản target=1, `+` là bản target=0).\n")
    func_of = dict(zip(units.unit_id, units.func))
    path_of = dict(zip(units.unit_id, units.file_path))
    for i, gi in enumerate(gpick, 1):
        lang, key = groups[gi]
        g = r1[(r1.language == lang) & (r1.tokkey == key)]
        u1 = g[g.target == 1].unit_id.min()
        u0 = g[g.target == 0].unit_id.min()
        diff = "\n".join(difflib.unified_diff(CR.normalize_func(func_of[u1]).split("\n"),
                                              CR.normalize_func(func_of[u0]).split("\n"),
                                              fromfile="target=1", tofile="target=0", lineterm="", n=1))
        if len(diff) > 6000:
            diff = diff[:6000] + "\n... (cắt bớt)"
        a.append(f"### 2.{i}. {lang}: nhóm {len(g)} đơn vị ({int((g.target == 1).sum())} t=1, {int((g.target == 0).sum())} t=0)\n")
        a.append(f"- t=1: `{u1[:16]}…` `{path_of[u1]}`")
        a.append(f"- t=0: `{u0[:16]}…` `{path_of[u0]}`")
        a.append("- đánh giá: \n")
        a.append(fence(diff or "(không khác biệt theo dòng; chỉ khác khoảng trắng đầu/cuối)", "diff") + "\n")
    AUDIT.write_text("\n".join(a) + "\n", encoding="utf-8")

    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    REPORT_JSON.write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")
    pd.set_option("display.width", 250)
    print(rt.to_string(index=False))
    print("\nv2 theo ngôn ngữ và nhãn:\n" + C.counts_table(units_v2).to_string(index=False))
    print("Thiếu nhãn (v2):", missing or "không")
    print(f"Đã ghi {EXCL.name}, {FOLDS_V2.name}, {AUDIT.name}")


if __name__ == "__main__":
    main()
