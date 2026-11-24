"""Phân tích thí nghiệm CVEfixes (bản bổ sung lần 4 của osf.io/96a2g).

Dùng: python cvf_analysis.py <thư mục kết quả, chứa e10/...> units_v1.(parquet|csv.gz)
          groups_and_folds_cvefixes_v2_len768_paired.csv groups_and_folds_cvefixes_v2.csv <thư mục ghi kết quả>

1. Chính (H-C1, H-C2): grouped_cv_analysis.run_analysis trên dự đoán test của 47 job CV (10 epoch, seed 17), cụm
   lấy từ file fold tập chính: AUROC macro 6 ngôn ngữ, hiệu LOLO−Mono, LOLO−Multi, Multi−Mono, macro 7 (S3), S1, S2.
   Tiêu chí như bản đăng ký gốc: trên ngẫu nhiên nếu CI nằm trên 0,55; hiệu tương đương nếu CI nằm trong ±0,03.
2. S4 (theo cỡ commit, chỉ lọc khi đánh giá): n_vuln_funcs_in_commit ≤ 20 và ≤ 5.
3. Huấn luyện trên MVD (H-C3): trên các hàm cvefixes_only_eval của tập chính, so xmulti với multi (dự đoán ngoài fold)
   và xmono với mono; macro 6 ngôn ngữ, hiệu ghép cặp, bootstrap theo cụm CVE; tương đương nếu CI trong ±0,03.
4. Mô tả: AUROC trên các hàm v2 ngoài tập chính (extra_predictions.csv của mono/multi): toàn bộ v2, chỉ hàm không ghép
   cặp (≤ 768 token), chỉ hàm dài hơn 768 token; AUROC trong cụm (trung bình theo cụm) và trên cụm hai hàm;
   đường AUROC test theo epoch; phân bố epoch được chọn.
Bootstrap: B = 1.000, seed 20260101, lấy mẫu lại cụm CVE có hoàn lại.
"""
import glob, json, sys
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score
sys.path.insert(0, str(Path(__file__).resolve().parent))
import grouped_cv_analysis as GA

B, SEED, EQ, CH = 1000, 20260101, 0.03, (0.45, 0.55)
M6 = GA.MACRO6


def read_units(p):
    cols = ["unit_id", "language", "target", "n_vuln_funcs_in_commit", "n_tokens", "is_paired", "cvefixes_only_eval"]
    u = pd.read_parquet(p, columns=cols) if str(p).endswith(".parquet") else pd.read_csv(p, usecols=cols)
    for c in ("is_paired", "cvefixes_only_eval"):
        u[c] = u[c].astype(str).isin(["True", "true", "1"])
    return u.set_index("unit_id")


def preds(out, mode, fname="predictions.csv"):
    fs = glob.glob(f"{out}/e10/{mode}/*/*/seed_17/{fname}")
    if not fs:
        return None
    p = pd.concat(pd.read_csv(f) for f in fs)
    assert p.unit_id.is_unique, (mode, fname)
    return p.set_index("unit_id")["prob_vulnerable"]


def macro(w, col, langs=M6):
    v = []
    for l in langs:
        g = w[(w.language == l) & w[col].notna()]
        if g.target.nunique() == 2:
            v.append(roc_auc_score(g.target, g[col]))
    return float(np.mean(v)) if v else np.nan


def boot(w, stats: dict):
    """stats: tên -> hàm(w) -> số. Trả về bảng ước lượng và CI 95% theo cụm."""
    w = w.reset_index(drop=True)
    codes, uniq = pd.factorize(w["group"]); order = np.argsort(codes, kind="stable")
    bounds = np.searchsorted(codes[order], np.arange(len(uniq) + 1)); rng = np.random.default_rng(SEED)
    pt = {k: f(w) for k, f in stats.items()}; bs = {k: [] for k in stats}
    for _ in range(B):
        d = w.iloc[np.concatenate([order[bounds[c]:bounds[c + 1]] for c in rng.integers(0, len(uniq), len(uniq))])]
        for k, f in stats.items():
            bs[k].append(f(d))
    rows = []
    for k in stats:
        lo, hi = np.nanpercentile(bs[k], [2.5, 97.5])
        diff = "−" in k or " - " in k
        verdict = (("tương đương (trong ±0,03)" if lo >= -EQ and hi <= EQ else "dương (CI > 0)" if lo > 0 else
                    "âm (CI < 0)" if hi < 0 else "không phân biệt được") if diff else
                   ("tương đương ngẫu nhiên" if lo >= CH[0] and hi <= CH[1] else "trên ngẫu nhiên" if lo > CH[1] else
                    "dưới ngẫu nhiên" if hi < CH[0] else "không phân biệt được"))
        rows.append(dict(stat=k, estimate=pt[k], ci_low=lo, ci_high=hi, n_units=len(w), n_groups=len(uniq), verdict=verdict))
    return pd.DataFrame(rows)


def within_cluster(w, cols):
    rows = []
    for (l, g), d in w.groupby(["language", "group"]):
        pos, neg = d[d.target == 1], d[d.target == 0]
        if len(pos) == 0 or len(neg) == 0:
            continue
        r = dict(language=l, group=g, size=len(d))
        for c in cols:
            a = pos[c].to_numpy()[:, None]; b = neg[c].to_numpy()[None, :]
            r[c] = float((a > b).mean() + 0.5 * (a == b).mean())
        rows.append(r)
    return pd.DataFrame(rows)


def main(out, units_p, main_csv, v2_csv, res):
    res = Path(res); res.mkdir(parents=True, exist_ok=True)
    u = read_units(units_p); fm = pd.read_csv(main_csv); f2 = pd.read_csv(v2_csv)
    # 1. Chính + S1 + S2 + S3 (mã phân tích đã đăng ký)
    m, s1, s2, w = GA.run_analysis(Path(out) / "e10", Path(main_csv), B=B)
    for name, t in (("main", m), ("s1", s1), ("s2", s2)):
        t.to_csv(res / f"cvf_{name}.csv", index=False)
    show = lambda t: t[t.language.isin(["macro6", "macro7"])][["stat", "language", "estimate", "ci_low", "ci_high", "verdict"]]
    print("===== CHÍNH (tập chính, 10 epoch)"); print(show(m).round(3).to_string(index=False))
    print("===== S1 (bỏ cụm khổng lồ)"); print(show(s1).round(3).to_string(index=False))
    print("===== S2 (tối đa 50 hàm mỗi cụm)"); print(show(s2).round(3).to_string(index=False))
    print("Theo ngôn ngữ:"); print(m[m.stat.isin(["mono", "multi", "lolo"])].pivot(index="language", columns="stat", values="estimate").round(3))
    # 2. S4
    w = w.join(u[["n_vuln_funcs_in_commit"]], on="unit_id")
    st = {f"{a}": (lambda d, a=a: macro(d, f"p_{a}")) for a in ("mono", "multi", "lolo")}
    st.update({"lolo−mono": lambda d: macro(d, "p_lolo") - macro(d, "p_mono"),
               "multi−mono": lambda d: macro(d, "p_multi") - macro(d, "p_mono"),
               "lolo−multi": lambda d: macro(d, "p_lolo") - macro(d, "p_multi")})
    for thr in (20, 5):
        t = boot(w[w.n_vuln_funcs_in_commit <= thr], st); t.to_csv(res / f"cvf_s4_nv{thr}.csv", index=False)
        print(f"===== S4: commit có ≤ {thr} hàm nhãn 1 ({int((w.n_vuln_funcs_in_commit <= thr).sum())} hàm)"); print(t.round(3).to_string(index=False))
    # 3. Huấn luyện trên MVD
    pm = {k: preds(out, k) for k in ("mono", "multi", "xmono", "xmulti")}
    if pm["xmulti"] is not None or pm["xmono"] is not None:
        ev = fm[fm.unit_id.isin(u.index[u.cvefixes_only_eval])][["unit_id", "language", "target", "group"]].copy()
        for k, s in pm.items():
            if s is not None:
                ev[f"p_{k}"] = ev.unit_id.map(s)
        st = {}
        for a, b in (("xmulti", "multi"), ("xmono", "mono")):
            if f"p_{a}" in ev and f"p_{b}" in ev:
                assert ev[f"p_{a}"].notna().all() and ev[f"p_{b}"].notna().all(), (a, b)
                st[a] = lambda d, a=a: macro(d, f"p_{a}"); st[b] = lambda d, b=b: macro(d, f"p_{b}")
                st[f"{a}−{b}"] = lambda d, a=a, b=b: macro(d, f"p_{a}") - macro(d, f"p_{b}")
        t = boot(ev, st); t.to_csv(res / "cvf_cross.csv", index=False)
        print(f"===== Huấn luyện trên MVD, kiểm tra trên {len(ev)} hàm chỉ có ở CVEfixes"); print(t.round(3).to_string(index=False))
        per = {c: {l: (roc_auc_score(g.target, g[c]) if g.target.nunique() == 2 else np.nan) for l, g in ev.groupby("language")}
               for c in ev.columns if c.startswith("p_")}
        print(pd.DataFrame(per).round(3))
    # 4a. Hàm v2 ngoài tập chính (mô tả)
    ex = {k: preds(out, k, "extra_predictions.csv") for k in ("mono", "multi")}
    if ex["mono"] is not None:
        a = f2[["unit_id", "language", "target", "group"]].copy()
        for k in ("mono", "multi"):
            a[f"p_{k}"] = a.unit_id.map(pd.concat([pm[k] if pm[k] is not None else preds(out, k), ex[k]]))
        a = a.join(u[["n_tokens", "is_paired"]], on="unit_id")
        inmain = a.unit_id.isin(fm.unit_id)
        subsets = {"toàn bộ v2": a, "tập chính": a[inmain], "không ghép cặp, ≤768": a[~inmain & (a.n_tokens <= 768)],
                   "dài hơn 768 token": a[a.n_tokens > 768]}
        rows = []
        for name, d in subsets.items():
            t = boot(d, {"mono": lambda x: macro(x, "p_mono"), "multi": lambda x: macro(x, "p_multi")})
            t.insert(0, "tập", name); rows.append(t)
        t = pd.concat(rows); t.to_csv(res / "cvf_extra.csv", index=False)
        print("===== Mô tả: AUROC trên các phần của v2 (mô hình huấn luyện trên tập chính)"); print(t.round(3).to_string(index=False))
    # 4b. Trong cụm
    wc = within_cluster(w, ["p_mono", "p_multi", "p_lolo"]); wc.to_csv(res / "cvf_within_cluster.csv", index=False)
    print("===== Mô tả: AUROC trong cụm (trung bình theo cụm, macro 6):",
          {c: round(float(np.mean([wc[wc.language == l][c].mean() for l in M6])), 3) for c in ("p_mono", "p_multi", "p_lolo")},
          "| cụm hai hàm:", {c: round(float(wc[wc["size"] == 2][c].mean()), 3) for c in ("p_mono", "p_multi", "p_lolo")},
          f"({int((wc['size'] == 2).sum())} cụm)")
    # 4c. Đường học và epoch được chọn
    curves = {}
    for mode in ("mono", "multi", "lolo"):
        fs = glob.glob(f"{out}/e10/{mode}/*/*/seed_17/test_by_epoch.csv")
        if fs:
            T = pd.concat(pd.read_csv(f) for f in fs)
            curves[mode] = [round(float(np.mean([roc_auc_score(T[T.language == l].true_label, T[T.language == l][f"p_e{e}"])
                                                  for l in M6 if T[T.language == l].true_label.nunique() == 2])), 3) for e in range(1, 11)]
        sel = [json.load(open(f))["selected_epoch"] for f in glob.glob(f"{out}/e10/{mode}/*/*/seed_17/log.json")]
        print(f"{mode}: AUROC test macro6 theo epoch {curves.get(mode)} | epoch được chọn {pd.Series(sel).value_counts().sort_index().to_dict()}")
    hours = sum(json.load(open(f))["seconds"] for f in glob.glob(f"{out}/e10/*/*/*/seed_17/log.json")) / 3600
    print(f"Tổng thời gian huấn luyện: {hours:.1f} giờ GPU")
    json.dump(dict(curves=curves, gpu_hours=hours), open(res / "cvf_curves.json", "w"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main(*sys.argv[1:6])
