"""
Phân tích dự đoán Grouped-CV: AUROC theo ngôn ngữ cho Mono (OOF), Multi (OOF) và LOLO,
khoảng tin cậy cluster bootstrap theo cụm CVE (lấy mẫu cụm TOÀN CỤC vì cụm có thể nối nhiều ngôn ngữ),
hiệu LOLO-Mono, LOLO-Multi, Multi-Mono, macro 6 ngôn ngữ (chính) và macro 7 (độ nhạy S3),
độ nhạy S1 (bỏ các cụm khổng lồ khỏi đánh giá), S2 (mỗi cụm tối đa 50 đơn vị khi đánh giá, chọn ngẫu nhiên một lần
với seed cố định; KHÔNG huấn luyện lại), S3 (macro 7 ngôn ngữ, có sẵn trong cột macro7).

Biên tương đương (ĐANG CHỜ ĐÓNG BĂNG, là lựa chọn vận hành chứ không phải ngưỡng khoa học):
  AUROC ~ ngẫu nhiên nếu CI nằm trong [0.45, 0.55]; hiệu coi là không đáng kể nếu CI nằm trong [-0.03, +0.03].
Chỉ dùng pandas / numpy / sklearn.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

LANGUAGES = ["C", "C#", "C++", "Go", "Java", "JavaScript", "Python"]
MACRO6 = [l for l in LANGUAGES if l != "C#"]
CHANCE_BAND = (0.45, 0.55)
DELTA_BAND = (-0.03, 0.03)
S2_CAP = 50
S2_SEED = 20260101


def load_predictions(out_dir: Path) -> pd.DataFrame:
    files = sorted(Path(out_dir).glob("*/*/*/seed_*/predictions.csv"))
    if not files:
        raise FileNotFoundError(f"không có predictions.csv trong {out_dir}")
    frames = []
    for f in files:
        d = pd.read_csv(f)
        d["seed"] = int(f.parent.name.split("_")[1])
        frames.append(d)
    df = pd.concat(frames, ignore_index=True)
    return df[df["mode"].isin(["mono", "multi", "lolo"])]


def wide_table(pred: pd.DataFrame, folds: pd.DataFrame) -> pd.DataFrame:
    """Một dòng mỗi đơn vị; cột p_mono, p_multi, p_lolo = xác suất trung bình qua các seed đã có."""
    avg = (pred.groupby(["mode", "unit_id"], as_index=False)
           .agg(p=("prob_vulnerable", "mean"), n_seeds=("seed", "nunique")))
    wide = avg.pivot(index="unit_id", columns="mode", values="p").add_prefix("p_")
    base = folds.set_index("unit_id")[["language", "target", "group", "is_giant"]]
    out = base.join(wide, how="left").reset_index()
    return out


def _auroc(y, p):
    return roc_auc_score(y, p) if len(np.unique(y)) == 2 else np.nan


def _stats(w: pd.DataFrame, modes: list[str]) -> dict:
    """AUROC theo ngôn ngữ cho từng mode, macro6, macro7, và các hiệu."""
    res = {}
    for m in modes:
        per = {}
        for lang in LANGUAGES:
            g = w[w["language"] == lang]
            g = g[g[f"p_{m}"].notna()]
            per[lang] = _auroc(g["target"].to_numpy(), g[f"p_{m}"].to_numpy()) if len(g) else np.nan
        for lang, v in per.items():
            res[f"{m}|{lang}"] = v
        res[f"{m}|macro6"] = np.nanmean([per[l] for l in MACRO6])
        res[f"{m}|macro7"] = np.nanmean(list(per.values()))
    pairs = [("lolo", "mono"), ("lolo", "multi"), ("multi", "mono")]
    for a, b in pairs:
        if a in modes and b in modes:
            for lang in LANGUAGES + ["macro6", "macro7"]:
                res[f"{a}-{b}|{lang}"] = res[f"{a}|{lang}"] - res[f"{b}|{lang}"]
    return res


def cluster_bootstrap(w: pd.DataFrame, modes: list[str], B: int = 1000, seed: int = 20260101) -> pd.DataFrame:
    """Lấy mẫu lại các cụm (có hoàn lại) trên TOÀN BỘ đơn vị, tính lại mọi thống kê, trả về CI 95% phân vị."""
    w = w.dropna(subset=[f"p_{m}" for m in modes]).reset_index(drop=True)
    point = _stats(w, modes)
    codes, uniq = pd.factorize(w["group"])
    order = np.argsort(codes, kind="stable")
    bounds = np.searchsorted(codes[order], np.arange(len(uniq) + 1))
    rng = np.random.default_rng(seed)
    draws = []
    for _ in range(B):
        pick = rng.integers(0, len(uniq), len(uniq))
        idx = np.concatenate([order[bounds[c]:bounds[c + 1]] for c in pick])
        draws.append(_stats(w.iloc[idx], modes))
    boot = pd.DataFrame(draws)
    rows = []
    for name, val in point.items():
        lo, hi = np.nanpercentile(boot[name], [2.5, 97.5])
        mode_or_pair, lang = name.split("|")
        sub = w if lang in ("macro6", "macro7") else w[w["language"] == lang]
        rows.append(dict(stat=mode_or_pair, language=lang, estimate=val, ci_low=lo, ci_high=hi,
                         n_units=len(sub), n_groups=sub["group"].nunique()))
    t = pd.DataFrame(rows)
    is_diff = t["stat"].str.contains("-")
    t["verdict"] = np.where(
        is_diff,
        np.where((t.ci_low >= DELTA_BAND[0]) & (t.ci_high <= DELTA_BAND[1]), "tương đương (trong ±0.03)",
                 np.where(t.ci_low > 0, "dương (CI > 0)", np.where(t.ci_high < 0, "âm (CI < 0)", "không phân biệt được"))),
        np.where((t.ci_low >= CHANCE_BAND[0]) & (t.ci_high <= CHANCE_BAND[1]), "tương đương ngẫu nhiên (trong [0.45,0.55])",
                 np.where(t.ci_low > CHANCE_BAND[1], "trên ngẫu nhiên",
                          np.where(t.ci_high < CHANCE_BAND[0], "dưới ngẫu nhiên", "không phân biệt được"))))
    return t


def cap_per_group(w: pd.DataFrame, cap: int = S2_CAP, seed: int = S2_SEED) -> pd.DataFrame:
    """S2: mỗi cụm giữ tối đa `cap` đơn vị (lấy ngẫu nhiên một lần, seed cố định); cụm nhỏ hơn giữ nguyên."""
    rng = np.random.default_rng(seed)
    keep = []
    for _, idx in w.groupby("group", sort=True).groups.items():
        idx = np.asarray(sorted(idx))
        keep.append(idx if len(idx) <= cap else np.sort(rng.choice(idx, cap, replace=False)))
    return w.loc[np.concatenate(keep)].reset_index(drop=True)


def run_analysis(out_dir: Path, folds_csv: Path, B: int = 1000):
    pred = load_predictions(out_dir)
    folds = pd.read_csv(folds_csv)
    w = wide_table(pred, folds)
    modes = [m for m in ("mono", "multi", "lolo") if f"p_{m}" in w.columns and w[f"p_{m}"].notna().any()]
    coverage = {m: int(w[f"p_{m}"].notna().sum()) for m in modes}
    print("Số đơn vị có dự đoán:", coverage, "/", len(w))
    print("Số seed:", pred.groupby("mode")["seed"].nunique().to_dict())
    main = cluster_bootstrap(w, modes, B=B)
    s1 = cluster_bootstrap(w[~w["is_giant"]], modes, B=B)  # S1: bỏ cụm khổng lồ khỏi đánh giá
    s2 = cluster_bootstrap(cap_per_group(w), modes, B=B)    # S2: mỗi cụm tối đa 50 đơn vị khi đánh giá
    return main, s1, s2, w
