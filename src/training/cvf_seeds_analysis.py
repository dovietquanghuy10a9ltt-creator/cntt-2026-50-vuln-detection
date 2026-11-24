"""Phân tích nhiều seed cho thí nghiệm CVEfixes (bản bổ sung lần 5 của osf.io/96a2g).

Dùng: python cvf_seeds_analysis.py <thư mục kết quả, chứa e10/<mode>/<key>/<fold>/seed_<s>/> units_v1.(parquet|csv.gz)
          groups_and_folds_cvefixes_v2_len768_paired.csv <thư mục ghi kết quả> [seed ...]   (mặc định 17 29 43)

Với mỗi tập đánh giá (chính; S1 bỏ cụm khổng lồ; S2 tối đa 50 hàm mỗi cụm; S4 commit có ≤ 20 và ≤ 5 hàm nhãn 1;
tập "chỉ có ở CVEfixes" cho job huấn luyện trên MVD), tính AUROC macro 6 ngôn ngữ (và macro 7 cho tập chính) của
từng cấu hình ở từng seed, rồi:
  (a) ƯỚC LƯỢNG CHÍNH: trung bình qua các seed của AUROC từng seed (và của các hiệu). Khoảng tin cậy 95% bằng bootstrap
      theo cụm CVE: mỗi lần lấy mẫu lại cụm dùng chung cho mọi seed, tính thống kê cho từng seed rồi lấy trung bình.
      B = 1.000, seed bootstrap 20260101.
  (b) Phụ: kết quả và kết luận của từng seed (cùng các lần lấy mẫu lại), độ lệch chuẩn giữa các seed.
Tiêu chí như bản đăng ký gốc: trên ngẫu nhiên nếu CI nằm trên 0,55; hiệu tương đương nếu CI nằm trong ±0,03; dương/âm
nếu CI nằm hẳn một phía của 0 mà không nằm trong biên; còn lại là không phân biệt được.
Không trộn xác suất giữa các seed (không lấy trung bình dự đoán), để con số so sánh được với từng seed.
"""
import glob, sys
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score

B, BSEED, EQ, CH = 1000, 20260101, 0.03, 0.55
LANGS = ["C", "C#", "C++", "Go", "Java", "JavaScript", "Python"]
M6 = [l for l in LANGS if l != "C#"]
S2_CAP, S2_SEED = 50, 20260101


def preds(out, mode, seed):
    fs = glob.glob(f"{out}/e10/{mode}/*/*/seed_{seed}/predictions.csv")
    if not fs:
        return None
    p = pd.concat(pd.read_csv(f) for f in fs)
    assert p.unit_id.is_unique, (mode, seed)
    return p.set_index("unit_id")["prob_vulnerable"]


def verdict(lo, hi, diff):
    if diff:
        if lo >= -EQ and hi <= EQ:
            return "tương đương (trong ±0,03)"
        return "dương (CI > 0)" if lo > 0 else "âm (CI < 0)" if hi < 0 else "không phân biệt được"
    if lo >= 0.45 and hi <= CH:
        return "tương đương ngẫu nhiên"
    return "trên ngẫu nhiên" if lo > CH else "dưới ngẫu nhiên" if hi < 0.45 else "không phân biệt được"


def lang_auroc(d, col):
    out = {}
    for l, g in d.groupby("language"):
        if g.target.nunique() == 2:
            out[l] = roc_auc_score(g.target, g[col])
    return out


def stats(d, cfgs, seeds, pairs, langs):
    """Trả về dict tên -> giá trị cho từng seed và trung bình."""
    per = {(c, s): lang_auroc(d, f"p_{c}_s{s}") for c in cfgs for s in seeds}
    mac = {(c, s): float(np.mean([per[(c, s)][l] for l in langs if l in per[(c, s)]])) for c in cfgs for s in seeds}
    r = {}
    for c in cfgs:
        for s in seeds:
            r[f"{c}|s{s}"] = mac[(c, s)]
        r[f"{c}|mean"] = float(np.mean([mac[(c, s)] for s in seeds]))
    for a, b in pairs:
        for s in seeds:
            r[f"{a}−{b}|s{s}"] = mac[(a, s)] - mac[(b, s)]
        r[f"{a}−{b}|mean"] = float(np.mean([mac[(a, s)] - mac[(b, s)] for s in seeds]))
    return r


def boot_table(d, cfgs, seeds, pairs, langs, label):
    d = d.reset_index(drop=True)
    codes, uniq = pd.factorize(d["group"]); order = np.argsort(codes, kind="stable")
    bounds = np.searchsorted(codes[order], np.arange(len(uniq) + 1)); rng = np.random.default_rng(BSEED)
    pt = stats(d, cfgs, seeds, pairs, langs); bs = {k: [] for k in pt}
    for _ in range(B):
        x = d.iloc[np.concatenate([order[bounds[c]:bounds[c + 1]] for c in rng.integers(0, len(uniq), len(uniq))])]
        v = stats(x, cfgs, seeds, pairs, langs)
        for k in pt:
            bs[k].append(v[k])
    rows = []
    for k, val in pt.items():
        name, which = k.split("|")
        lo, hi = np.nanpercentile(bs[k], [2.5, 97.5])
        rows.append(dict(tap=label, stat=name, seed=which, estimate=val, ci_low=lo, ci_high=hi,
                         verdict=verdict(lo, hi, "−" in name), n_units=len(d), n_groups=len(uniq)))
    t = pd.DataFrame(rows)
    sd = t[t.seed != "mean"].groupby("stat").estimate.std(ddof=1).rename("sd_giua_seed")
    return t.join(sd, on="stat")


def cap_per_group(w):
    rng = np.random.default_rng(S2_SEED); keep = []
    for _, idx in w.groupby("group", sort=True).groups.items():
        idx = np.asarray(sorted(idx))
        keep.append(idx if len(idx) <= S2_CAP else np.sort(rng.choice(idx, S2_CAP, replace=False)))
    return w.loc[np.concatenate(keep)].reset_index(drop=True)


def main(out, units_p, main_csv, res, seeds):
    res = Path(res); res.mkdir(parents=True, exist_ok=True)
    cols = ["unit_id", "n_vuln_funcs_in_commit", "cvefixes_only_eval"]
    u = pd.read_parquet(units_p, columns=cols) if str(units_p).endswith(".parquet") else pd.read_csv(units_p, usecols=cols)
    u["cvefixes_only_eval"] = u["cvefixes_only_eval"].astype(str).isin(["True", "true", "1"])
    u = u.set_index("unit_id")
    fm = pd.read_csv(main_csv)
    w = fm[["unit_id", "language", "target", "group", "is_giant"]].join(u, on="unit_id")
    for s in seeds:
        for c in ("mono", "multi", "lolo", "xmono", "xmulti"):
            p = preds(out, c, s)
            assert p is not None, f"thiếu dự đoán {c} seed {s}"
            w[f"p_{c}_s{s}"] = w.unit_id.map(p)
        for c in ("mono", "multi", "lolo"):
            assert w[f"p_{c}_s{s}"].notna().all(), f"{c} seed {s} thiếu hàm"
    cv, pairs = ("mono", "multi", "lolo"), [("lolo", "mono"), ("multi", "mono"), ("lolo", "multi")]
    tabs = [boot_table(w, cv, seeds, pairs, M6, "chính, macro 6"),
            boot_table(w, cv, seeds, pairs, LANGS, "chính, macro 7 (S3)"),
            boot_table(w[~w.is_giant], cv, seeds, pairs, M6, "S1 bỏ cụm khổng lồ"),
            boot_table(cap_per_group(w), cv, seeds, pairs, M6, "S2 tối đa 50 hàm mỗi cụm"),
            boot_table(w[w.n_vuln_funcs_in_commit <= 20], cv, seeds, pairs, M6, "S4 commit ≤ 20 hàm nhãn 1"),
            boot_table(w[w.n_vuln_funcs_in_commit <= 5], cv, seeds, pairs, M6, "S4 commit ≤ 5 hàm nhãn 1")]
    ev = w[w.cvefixes_only_eval].copy()
    for s in seeds:
        for c in ("xmono", "xmulti"):
            assert ev[f"p_{c}_s{s}"].notna().all(), f"{c} seed {s} thiếu hàm"
    tabs.append(boot_table(ev, ("xmulti", "multi", "xmono", "mono"), seeds, [("xmulti", "multi"), ("xmono", "mono")],
                           M6, "huấn luyện trên MVD, hàm chỉ có ở CVEfixes"))
    T = pd.concat(tabs, ignore_index=True); T.to_csv(res / "cvf_seeds_all.csv", index=False)
    pd.set_option("display.width", 220)
    M = T[T.seed == "mean"][["tap", "stat", "estimate", "ci_low", "ci_high", "verdict", "sd_giua_seed"]]
    print("===== ƯỚC LƯỢNG CHÍNH: trung bình qua seed", seeds); print(M.round(3).to_string(index=False))
    P = T[T.seed != "mean"].assign(v=lambda d: d.estimate.round(3).astype(str) + " " + d.verdict.str.split(" ").str[0])
    print("===== Từng seed"); print(P.pivot_table(index=["tap", "stat"], columns="seed", values="v", aggfunc="first").to_string())
    # theo ngôn ngữ, trung bình qua seed (mô tả)
    rows = {}
    for c in ("mono", "multi", "lolo"):
        rows[c] = {l: np.mean([roc_auc_score(w[w.language == l].target, w[w.language == l][f"p_{c}_s{s}"]) for s in seeds]) for l in LANGS}
    print("===== Theo ngôn ngữ (trung bình qua seed, mô tả)"); print(pd.DataFrame(rows).round(3))
    pd.DataFrame(rows).to_csv(res / "cvf_seeds_by_language.csv")


if __name__ == "__main__":
    a = sys.argv[1:]
    main(a[0], a[1], a[2], a[3], [int(x) for x in a[4:]] or [17, 29, 43])
