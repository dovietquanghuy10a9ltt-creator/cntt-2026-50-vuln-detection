"""Bước 6: gom cụm CVE và chia 5 fold trên v1 bằng build_folds.build (nguyên bản, chỉ import).

Đầu ra: groups_and_folds_cvefixes_v1.csv, cluster_stats_cvefixes_v1.csv.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import pandas as pd  # noqa: E402

CR, BF = C.import_package_modules()

UNITS = C.WORK / "units_v1.parquet"
FOLDS = C.WORK / "groups_and_folds_cvefixes_v1.csv"
STATS = C.WORK / "cluster_stats_cvefixes_v1.csv"
INTER = C.WORK / "intermediate"
REPORT_MD = INTER / "step6.md"
REPORT_JSON = INTER / "step6.json"


def check_folds(folds: pd.DataFrame, units: pd.DataFrame):
    """Các kiểm tra bắt buộc của mục 13 liên quan tới file fold."""
    assert len(folds) == len(units), "Số dòng file fold khác units_v1"
    assert folds.unit_id.is_unique
    assert set(folds.unit_id) == set(units.unit_id), "File fold và units_v1 không cùng tập unit_id"
    assert folds.groupby("group").fold.nunique().max() == 1, "Có cụm nằm ở hai fold"
    for k in range(BF.K):
        iv = folds[f"inner_val_fold{k}"].astype(bool)
        assert not (iv & (folds.fold == k)).any(), f"inner_val_fold{k} chứa đơn vị của fold {k}"
        assert not (iv & folds.is_giant.astype(bool)).any(), f"inner_val_fold{k} chứa cụm khổng lồ"
    m = folds.merge(units[["unit_id", "language", "target"]], on="unit_id", suffixes=("", "_u"))
    assert (m.language == m.language_u).all() and (m.target == m.target_u).all()


def main():
    C.check_package_hashes()
    units = pd.read_parquet(UNITS, columns=["unit_id", "language", "target", "all_cves"])
    folds, stats = BF.build(units[["unit_id", "language", "target", "all_cves"]])
    folds2, _ = BF.build(units[["unit_id", "language", "target", "all_cves"]])
    assert folds.equals(folds2), "build_folds cho kết quả khác nhau giữa hai lần chạy"
    check_folds(folds, units)
    folds.to_csv(FOLDS, index=False)
    stats.to_csv(STATS, index=False)
    # đọc lại từ CSV để chắc chắn file ghi ra cũng thỏa các kiểm tra
    check_folds(pd.read_csv(FOLDS), units)

    md, js = [], {}
    w = md.append
    w("## Bước 6: gom cụm CVE và chia fold (v1)\n")
    w("`build_folds.build` nguyên bản: cụm = thành phần liên thông của CVE (toàn cục, xuyên ngôn ngữ); 5 fold greedy "
      "phân tầng ngôn ngữ × nhãn (seed 42); cụm khổng lồ = cụm chiếm hơn 10% số đơn vị của một ngôn ngữ; validation nội bộ "
      "của fold k là bin 9 trong 10 bin (seed 100+k), không chứa cụm khổng lồ.\n")
    w(f"Tổng: {len(folds):,} đơn vị, {folds.group.nunique():,} cụm, {folds[folds.is_giant].group.nunique()} cụm khổng lồ.\n")
    w("### Thống kê cụm (`cluster_stats_cvefixes_v1.csv`)\n")
    w(C.md_table(stats) + "\n")

    units_full = pd.read_parquet(UNITS, columns=["unit_id", "all_cves", "repos"])
    f = folds.merge(units_full, on="unit_id")
    giants = []
    for gid, g in f[f.is_giant].groupby("group"):
        cves = sorted({c for s in g.all_cves for c in s.split(";") if c})
        repos = pd.Series([r for s in g.repos for r in s.split(";") if r]).value_counts()
        share = {l: len(g[g.language == l]) / max(1, (folds.language == l).sum()) for l in C.LANGS}
        giants.append({"cụm": int(gid), "fold": int(g.fold.iloc[0]), "số đơn vị": len(g), "số CVE": len(cves),
                       "theo ngôn ngữ": ", ".join(f"{l} {int((g.language == l).sum()):,} ({100 * share[l]:.0f}%)"
                                                  for l in C.LANGS if (g.language == l).any()),
                       "repo nhiều nhất": ", ".join(f"{r.replace('https://', '')} ({n:,})" for r, n in repos.head(3).items()),
                       "ví dụ CVE": ", ".join(cves[:5]) + (" ..." if len(cves) > 5 else "")})
    gt = pd.DataFrame(giants).sort_values("số đơn vị", ascending=False) if giants else pd.DataFrame()
    w("### Cụm khổng lồ (chiếm hơn 10% số đơn vị của ít nhất một ngôn ngữ)\n")
    w((C.md_table(gt) if len(gt) else "Không có.") + "\n")

    ft = folds.groupby(["fold", "language"]).size().unstack(fill_value=0).reindex(columns=C.LANGS, fill_value=0)
    ft["tổng"] = ft.sum(axis=1)
    w("### Bảng fold × ngôn ngữ (số đơn vị)\n")
    w(C.md_table(ft.reset_index()) + "\n")
    fl = folds.groupby(["fold", "language", "target"]).size().unstack(["language", "target"], fill_value=0)
    fl = fl.reindex(columns=pd.MultiIndex.from_product([C.LANGS, [1, 0]]), fill_value=0)
    fl.columns = [f"{l} t={t}" for l, t in fl.columns]
    w("Theo nhãn:\n")
    w(C.md_table(fl.reset_index()) + "\n")
    iv = pd.DataFrame([{"fold": k, "inner_val": int(folds[f"inner_val_fold{k}"].sum()),
                        "train (không gồm inner_val)": int(((folds.fold != k) & ~folds[f"inner_val_fold{k}"]).sum()),
                        "test": int((folds.fold == k).sum())} for k in range(BF.K)])
    w("Kích thước train / validation nội bộ / test của từng fold:\n")
    w(C.md_table(iv) + "\n")
    _, missing = C.split_label_check(folds)
    w("Kiểm tra đủ hai nhãn cho mỗi ngôn ngữ ở train / val / test của mỗi fold (v1): "
      + ("đủ ở mọi nơi." if not missing else f"thiếu {len(missing)} trường hợp: " + "; ".join(missing)) + "\n")
    js.update({"n_units": len(folds), "n_groups": int(folds.group.nunique()),
               "n_giant_groups": int(folds[folds.is_giant].group.nunique()), "missing_labels_v1": missing})

    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    REPORT_JSON.write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")
    pd.set_option("display.width", 250)
    print(stats.to_string(index=False))
    print(ft.to_string())
    print(gt.to_string(index=False) if len(gt) else "Không có cụm khổng lồ")
    print("Thiếu nhãn (v1):", missing or "không")


if __name__ == "__main__":
    main()
