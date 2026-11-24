"""So sánh AUROC giữa chia ngẫu nhiên theo hàm (R) và chia gom theo CVE (G) trên cùng đơn vị, cùng mô hình.
Hiệu = AUROC_R - AUROC_G cho Mono và Multi; cluster bootstrap theo cụm CVE thật (lấy mẫu chung cho cả hai), 1.000 lần."""
from pathlib import Path
import numpy as np, pandas as pd
import grouped_cv_analysis as A

def load(out_dir, seed=17):
    p = A.load_predictions(Path(out_dir)); p = p[(p["seed"] == seed) & p["mode"].isin(["mono", "multi"])]
    assert not p.duplicated(["mode", "unit_id"]).any()
    return p.pivot(index="unit_id", columns="mode", values="prob_vulnerable")

def stats(w):
    r = {}
    for m in ("mono", "multi"):
        for s in ("G", "R"):
            per = {l: A._auroc(g["target"].to_numpy(), g[f"{m}_{s}"].to_numpy()) for l, g in w.groupby("language")}
            for l in A.LANGUAGES: r[f"{m}_{s}|{l}"] = per.get(l, np.nan)
            r[f"{m}_{s}|macro6"] = np.nanmean([per.get(l, np.nan) for l in A.MACRO6])
            r[f"{m}_{s}|macro7"] = np.nanmean([per.get(l, np.nan) for l in A.LANGUAGES])
        for l in A.LANGUAGES + ["macro6", "macro7"]:
            r[f"{m}_R-G|{l}"] = r[f"{m}_R|{l}"] - r[f"{m}_G|{l}"]
    return r

def run(grouped_dir, random_dir, folds_csv, B=1000, seed=20260101):
    f = pd.read_csv(folds_csv).set_index("unit_id")[["language", "target", "group", "is_giant"]]
    w = f.join(load(grouped_dir).add_suffix("_G")).join(load(random_dir).add_suffix("_R")).reset_index()
    assert len(w) == 18694 and not w[["mono_G", "multi_G", "mono_R", "multi_R"]].isna().any().any()
    res = {}
    for name, d in (("main", w), ("S1", w[~w["is_giant"]]), ("S2", A.cap_per_group(w))):
        d = d.reset_index(drop=True); point = stats(d)
        codes, uniq = pd.factorize(d["group"]); order = np.argsort(codes, kind="stable")
        bounds = np.searchsorted(codes[order], np.arange(len(uniq) + 1)); rng = np.random.default_rng(seed)
        boot = pd.DataFrame([stats(d.iloc[np.concatenate([order[bounds[c]:bounds[c + 1]] for c in rng.integers(0, len(uniq), len(uniq))])]) for _ in range(B)])
        rows = []
        for k, v in point.items():
            lo, hi = np.nanpercentile(boot[k], [2.5, 97.5]); s, l = k.split("|")
            rows.append(dict(stat=s, language=l, estimate=v, ci_low=lo, ci_high=hi))
        res[name] = pd.DataFrame(rows)
    return res
