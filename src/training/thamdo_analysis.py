"""Phân tích thăm dò (KHÔNG có trong các bản đăng ký trước) trên dự đoán đã có của UniXcoder, 10 epoch, seed 17.

1. Theo công sức rà soát. Trong từng ngôn ngữ, xếp các hàm kiểm tra theo xác suất có lỗ hổng giảm dần và giả sử người
   rà soát chỉ đọc k% số hàm đầu danh sách (k = 10, 20, 30%):
   - recall@k: tỷ lệ hàm có lỗ hổng nằm trong k% đó; chọn ngẫu nhiên cho kỳ vọng đúng bằng k; tối đa min(1, k·N/V);
   - phủ CVE@k: tỷ lệ cụm CVE (có ít nhất một hàm nhãn 1 trong ngôn ngữ đó) có ít nhất một hàm nhãn 1 nằm trong k%;
     mức ngẫu nhiên tính đúng bằng phân phối siêu bội.
   Lấy trung bình 6 ngôn ngữ (không gồm C#) như chỉ số chính. Khoảng tin cậy 95%: bootstrap theo cụm CVE, B = 1.000,
   seed 20260101, cho chỉ số và cho hiệu so với ngẫu nhiên.
2. Theo loại lỗ hổng (CWE), dự đoán của Multi (một mô hình cho mọi ngôn ngữ). Với mỗi CWE có ít nhất 300 hàm và 30 cụm
   CVE trong tập đánh giá: AUROC gộp các ngôn ngữ, và AUROC trong cụm (trung bình theo cụm, mỗi cụm có cả hai nhãn trọng
   số như nhau: bản lỗi có được điểm cao hơn bản sửa trong cùng CVE không). Một hàm thuộc mọi CWE mà CVE của nó được
   gán; bỏ "không rõ" (NVD-CWE-noinfo, NVD-CWE-Other). Khoảng tin cậy: bootstrap theo cụm như trên.

Dùng:
  python thamdo_analysis.py --mvd-pred <e10 MVD v2> --mvd-folds groups_and_folds_v2.csv --mvd-cwe mvd_v2_cwe.csv
      --cvf-pred <e10 CVEfixes> --cvf-folds groups_and_folds_cvefixes_v2_len768_paired.csv
      --cvf-units units_v1.(parquet|csv.gz) --res <thư mục kết quả>
"""
import argparse, glob, json
from pathlib import Path
import numpy as np, pandas as pd
from scipy.stats import hypergeom, rankdata

B, BSEED = 1000, 20260101
LANGS = ["C", "C#", "C++", "Go", "Java", "JavaScript", "Python"]
M6 = [l for l in LANGS if l != "C#"]
MODES = ["mono", "multi", "lolo"]
KS = [0.10, 0.20, 0.30]
MIN_UNITS, MIN_GROUPS = 300, 30
UNKNOWN = {"", "NVD-CWE-noinfo", "NVD-CWE-Other", "Không rõ"}


def load_preds(root, mode, seed=17):
    fs = sorted(glob.glob(f"{root}/{mode}/*/*/seed_{seed}/predictions.csv"))
    assert fs, (root, mode)
    p = pd.concat(pd.read_csv(f) for f in fs)
    assert p.unit_id.is_unique
    return p.set_index("unit_id").prob_vulnerable


def build(pred_root, folds_csv, cwe_map):
    f = pd.read_csv(folds_csv)
    w = f[["unit_id", "language", "target", "group"]].copy()
    for m in MODES:
        w[m] = w.unit_id.map(load_preds(pred_root, m))
    assert w[MODES].notna().all().all()
    w["cwes"] = w.unit_id.map(cwe_map).fillna("")
    return w.reset_index(drop=True)


# ---------------- 1. công sức rà soát ----------------
def effort_lang(g, col, k):
    """g: các hàm của một ngôn ngữ. Trả về (recall, recall ngẫu nhiên, phủ CVE, phủ ngẫu nhiên)."""
    N = len(g); n = int(round(k * N))
    y = g.target.to_numpy(); V = int(y.sum())
    if V == 0 or n == 0:
        return (np.nan,) * 4
    order = np.argsort(-g[col].to_numpy(), kind="stable")
    top = np.zeros(N, bool); top[order[:n]] = True
    rec = (top & (y == 1)).sum() / V
    vul = g[y == 1]
    hit = pd.Series(top[y == 1], index=vul.index).groupby(vul.group).any()
    v_per = vul.groupby("group").size()
    cov_rand = float(np.mean(1 - hypergeom.pmf(0, N, v_per.to_numpy(), n)))
    return rec, n / N, float(hit.mean()), cov_rand


def effort_stats(w):
    out = {}
    by = {l: g for l, g in w.groupby("language")}
    for m in MODES:
        for k in KS:
            vals = np.array([effort_lang(by[l], m, k) for l in M6 if l in by])
            r, rr, c, cr = np.nanmean(vals, axis=0)
            key = f"{m}|{int(k * 100)}"
            out[f"{key}|recall"], out[f"{key}|recall_ngau_nhien"] = r, rr
            out[f"{key}|recall_hieu"] = r - rr
            out[f"{key}|phu_cve"], out[f"{key}|phu_cve_ngau_nhien"] = c, cr
            out[f"{key}|phu_cve_hieu"] = c - cr
    return out


# ---------------- 2. theo CWE ----------------
def auc(y, s):
    n1 = int(y.sum()); n0 = len(y) - n1
    if n1 == 0 or n0 == 0:
        return np.nan
    r = rankdata(s)
    return (r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)


def within_cluster(d, col):
    """Trung bình theo cụm của AUROC trong cụm (rank trung bình khi hoà, trùng roc_auc_score)."""
    t = d.target.to_numpy() == 1
    r = d.groupby("group")[col].rank(method="average").to_numpy()
    g = pd.DataFrame({"group": d.group.to_numpy(), "rp": r * t, "n1": t, "n0": ~t}).groupby("group").sum()
    g = g[(g.n1 > 0) & (g.n0 > 0)]
    if not len(g):
        return np.nan
    return float(((g.rp - g.n1 * (g.n1 + 1) / 2) / (g.n1 * g.n0)).mean())


def cwe_stats(w, cwes, col="multi"):
    out = {}
    for c in cwes:
        d = w[w[f"cwe::{c}"]]
        out[f"{c}|auroc"] = auc(d.target.to_numpy(), d[col].to_numpy())
        out[f"{c}|auroc_trong_cum"] = within_cluster(d, col)
    out["Tất cả|auroc"] = auc(w.target.to_numpy(), w[col].to_numpy())
    out["Tất cả|auroc_trong_cum"] = within_cluster(w, col)
    return out


# ---------------- bootstrap ----------------
def bootstrap(w, fn):
    codes, uniq = pd.factorize(w["group"]); order = np.argsort(codes, kind="stable")
    bounds = np.searchsorted(codes[order], np.arange(len(uniq) + 1)); rng = np.random.default_rng(BSEED)
    pt = fn(w); bs = {k: [] for k in pt}
    for _ in range(B):
        draw = rng.integers(0, len(uniq), len(uniq))
        idx = np.concatenate([order[bounds[c]:bounds[c + 1]] for c in draw])
        x = w.iloc[idx].copy()
        # mỗi lần một cụm được rút là một cụm riêng (giữ đúng cấu trúc cụm khi tính phủ CVE và AUROC trong cụm)
        x["group"] = np.repeat(np.arange(len(draw)), bounds[draw + 1] - bounds[draw])
        v = fn(x)
        for k in pt:
            bs[k].append(v.get(k, np.nan))
    rows = []
    for k, val in pt.items():
        lo, hi = np.nanpercentile(bs[k], [2.5, 97.5])
        rows.append(dict(key=k, estimate=val, ci_low=lo, ci_high=hi))
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    for k in ("mvd-pred", "mvd-folds", "mvd-cwe", "cvf-pred", "cvf-folds", "cvf-units", "res"):
        ap.add_argument(f"--{k}", required=True)
    a = ap.parse_args()
    res = Path(a.res); res.mkdir(parents=True, exist_ok=True)
    mvd_cwe = pd.read_csv(a.mvd_cwe, keep_default_na=False).set_index("unit_id").cwes
    cols = ["unit_id", "all_cwes"]
    u = (pd.read_parquet(a.cvf_units, columns=cols) if a.cvf_units.endswith(".parquet")
         else pd.read_csv(a.cvf_units, usecols=cols, keep_default_na=False))
    cvf_cwe = u.set_index("unit_id").all_cwes
    summary = {}
    for ds, pred, folds, cmap in (("mvd", a.mvd_pred, a.mvd_folds, mvd_cwe), ("cvf", a.cvf_pred, a.cvf_folds, cvf_cwe)):
        w = build(pred, folds, cmap)
        w["cwe_set"] = w.cwes.astype(str).str.split(";").apply(lambda s: frozenset(x for x in s if x not in UNKNOWN))
        # ---- 1
        E = bootstrap(w, effort_stats)
        E[["mode", "k", "stat"]] = E.key.str.split("|", expand=True)
        E.to_csv(res / f"effort_{ds}.csv", index=False)
        # theo ngôn ngữ (mô tả)
        by = {l: g for l, g in w.groupby("language")}
        L = pd.DataFrame([dict(language=l, mode=m, k=int(k * 100), **dict(zip(
            ["recall", "recall_ngau_nhien", "phu_cve", "phu_cve_ngau_nhien"], effort_lang(by[l], m, k))))
            for l in LANGS for m in MODES for k in KS])
        L.to_csv(res / f"effort_{ds}_by_language.csv", index=False)
        # ---- 2
        cnt = {}
        for s, g in zip(w.cwe_set, w.group):
            for c in s:
                cnt.setdefault(c, [0, set()]); cnt[c][0] += 1; cnt[c][1].add(g)
        keep = sorted([c for c, (n, gs) in cnt.items() if n >= MIN_UNITS and len(gs) >= MIN_GROUPS],
                      key=lambda c: -cnt[c][0])
        for c in keep:
            w[f"cwe::{c}"] = w.cwe_set.apply(lambda st: c in st)
        C = bootstrap(w, lambda x: cwe_stats(x, keep))
        C[["cwe", "stat"]] = C.key.str.split("|", expand=True)
        meta = {c: dict(n_units=cnt[c][0], n_groups=len(cnt[c][1]),
                        langs=w[w[f"cwe::{c}"]].language.value_counts().to_dict()) for c in keep}
        meta["Tất cả"] = dict(n_units=len(w), n_groups=w.group.nunique(), langs=w.language.value_counts().to_dict())
        C["n_units"] = C.cwe.map(lambda c: meta[c]["n_units"]); C["n_groups"] = C.cwe.map(lambda c: meta[c]["n_groups"])
        C["ngon_ngu_chinh"] = C.cwe.map(lambda c: ", ".join(f"{k} {v / meta[c]['n_units']:.0%}" for k, v in
                                                            list(meta[c]["langs"].items())[:3]))
        C.to_csv(res / f"cwe_{ds}.csv", index=False)
        summary[ds] = dict(n_units=len(w), cwe_kept=keep, unknown_share=float((w.cwe_set.apply(len) == 0).mean()))
        pd.set_option("display.width", 220)
        print(f"\n===== {ds.upper()} ({len(w)} hàm) — công sức rà soát, macro 6 ngôn ngữ")
        print(E.pivot_table(index=["mode", "k"], columns="stat", values="estimate").round(3).to_string())
        print(E[E.stat.str.endswith("hieu")][["mode", "k", "stat", "estimate", "ci_low", "ci_high"]].round(3).to_string(index=False))
        print(f"----- {ds.upper()} — theo CWE (Multi); tỷ lệ hàm không rõ CWE: {summary[ds]['unknown_share']:.1%}")
        print(C.pivot_table(index=["cwe", "n_units", "n_groups", "ngon_ngu_chinh"], columns="stat",
                            values=["estimate", "ci_low", "ci_high"]).round(3).to_string())
    (res / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
