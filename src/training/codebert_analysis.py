"""Phân tích thí nghiệm CodeBERT (bản bổ sung lần 6 của osf.io/96a2g).

Dùng:
  python codebert_analysis.py --cb <thư mục codebert_results, chứa mvd/e10/... và cvf/e10/...>
      --ux-mvd <thư mục e10 của UniXcoder trên MVD v2, chứa <mode>/<key>/<fold>/seed_17/predictions.csv>
      --ux-cvf <thư mục e10 của UniXcoder trên CVEfixes seed 17>
      --mvd-folds groups_and_folds_v2.csv --mvd-commit mvd_v2_commit_size.csv
      --cvf-units units_v1.(parquet|csv.gz) --cvf-folds groups_and_folds_cvefixes_v2_len768_paired.csv
      --res <thư mục ghi kết quả> [--datasets mvd cvf]

Với mỗi bộ dữ liệu (MVD v2 là chính, CVEfixes là lặp lại), seed 17, 10 epoch, trên cùng các hàm kiểm tra:
  - AUROC macro 6 ngôn ngữ (không gồm C#) của CodeBERT và UniXcoder với Mono, Multi, LOLO;
  - hiệu giữa các cấu hình trong cùng mô hình: LOLO − Mono, Multi − Mono, LOLO − Multi;
  - hiệu giữa hai mô hình với cùng cấu hình: CodeBERT − UniXcoder (ghép cặp trên cùng hàm);
  - hiệu kép (H-CB4): trung bình (CodeBERT − UniXcoder) trên C, C++ (không có trong dữ liệu tiền huấn luyện của
    CodeBERT) trừ trung bình trên Go, Java, JavaScript, Python (có trong dữ liệu tiền huấn luyện của CodeBERT).
Khoảng tin cậy 95%: bootstrap theo cụm CVE, B = 1.000, seed 20260101 (cùng cách lấy mẫu lại như các phân tích
trước, nên các con số của UniXcoder trùng với số đã báo cáo). Tập đánh giá: chính (macro 6); S3 macro 7; S1 bỏ cụm
khổng lồ; S2 tối đa 50 hàm mỗi cụm; S4 commit có ≤ 20 và ≤ 5 hàm nhãn 1; S5 chỉ hàm có ≤ 510 token mã theo tokenizer
CodeBERT (CodeBERT thấy trọn hàm). Mọi tập con chỉ lọc khi đánh giá.
Tiêu chí: AUROC trên ngẫu nhiên nếu CI nằm trên 0,55; hiệu tương đương nếu CI nằm trong ±0,03; dương/âm nếu CI nằm
hẳn một phía của 0 mà không nằm trong biên; còn lại là không phân biệt được.
Mô tả (không suy luận): AUROC và hiệu theo ngôn ngữ, tỷ lệ hàm bị cắt, AUROC trong cụm (trung bình theo cụm),
đường AUROC test theo epoch, phân bố epoch được chọn, tổng giờ GPU.
"""
import argparse, glob, hashlib, json
from pathlib import Path
import numpy as np, pandas as pd
from scipy.stats import rankdata
from sklearn.metrics import roc_auc_score

B, BSEED, EQ, CH = 1000, 20260101, 0.03, 0.55
LANGS = ["C", "C#", "C++", "Go", "Java", "JavaScript", "Python"]
M6 = [l for l in LANGS if l != "C#"]
NOT_PRE, PRE = ["C", "C++"], ["Go", "Java", "JavaScript", "Python"]   # theo dữ liệu tiền huấn luyện của CodeBERT
MODES = ["mono", "multi", "lolo"]
MODELS = {"cb": "CodeBERT", "ux": "UniXcoder"}
MNAME = {"mono": "Mono", "multi": "Multi", "lolo": "LOLO"}
COLS = [f"{m}_{c}" for m in MODELS for c in MODES]
S2_CAP, S2_SEED = 50, 20260101


def load(root, mode, need_len=False):
    fs = sorted(glob.glob(f"{root}/{mode}/*/*/seed_17/predictions.csv"))
    assert fs, f"không có dự đoán {mode} trong {root}"
    p = pd.concat(pd.read_csv(f) for f in fs)
    assert p.unit_id.is_unique, (root, mode)
    cols = ["unit_id", "prob_vulnerable"] + (["n_code_tokens", "truncated"] if need_len else [])
    return p[cols].set_index("unit_id")


def build(ds, a):
    """Một dòng mỗi hàm, theo đúng thứ tự file fold (để S2 lấy cùng tập con như các phân tích trước)."""
    if ds == "mvd":
        f = pd.read_csv(a.mvd_folds)
        w = f[["unit_id", "language", "target", "group", "is_giant"]].merge(
            pd.read_csv(a.mvd_commit), on="unit_id", how="left", validate="one_to_one")
        ux_root = a.ux_mvd
    else:
        f = pd.read_csv(a.cvf_folds)
        cols = ["unit_id", "n_vuln_funcs_in_commit"]
        u = (pd.read_parquet(a.cvf_units, columns=cols) if str(a.cvf_units).endswith(".parquet")
             else pd.read_csv(a.cvf_units, usecols=cols))
        w = f[["unit_id", "language", "target", "group", "is_giant"]].merge(u, on="unit_id", how="left",
                                                                            validate="one_to_one")
        ux_root = a.ux_cvf
    cb_root = f"{a.cb}/{ds}/e10"
    lens, canon = [], []
    for c in MODES:
        canon += [f"{c},{u},{v:.8f}" for u, v in load(ux_root, c).prob_vulnerable.items()]
    w.attrs["ux_hash"] = hashlib.sha256("\n".join(sorted(canon)).encode()).hexdigest()
    for c in MODES:
        p = load(cb_root, c, need_len=True)
        w[f"cb_{c}"] = w.unit_id.map(p.prob_vulnerable)
        lens.append(p[["n_code_tokens", "truncated"]].add_suffix(f"_{c}"))
        w[f"ux_{c}"] = w.unit_id.map(load(ux_root, c).prob_vulnerable)
    L = pd.concat(lens, axis=1).reindex(w.unit_id)
    assert (L.n_code_tokens_mono.values == L.n_code_tokens_multi.values).all() and \
           (L.n_code_tokens_mono.values == L.n_code_tokens_lolo.values).all(), "số token lệch giữa các cấu hình"
    w["n_code_tokens"] = L.n_code_tokens_mono.values.astype(int)
    w["truncated"] = L.truncated_mono.astype(str).isin(["True", "true", "1"]).values
    assert (w.truncated == (w.n_code_tokens > 510)).all()
    assert w[COLS + ["n_vuln_funcs_in_commit"]].notna().all().all(), f"{ds}: thiếu dự đoán hoặc cỡ commit"
    w["is_giant"] = w.is_giant.astype(str).isin(["True", "true", "1"])
    return w.reset_index(drop=True)


def lang_auroc(d):
    """AUROC theo ngôn ngữ cho mọi cột (rank trung bình khi hoà, trùng roc_auc_score)."""
    out = {}
    y_all, P_all, lang = d.target.to_numpy(), d[COLS].to_numpy(), d.language.to_numpy()
    for l in LANGS:
        m = lang == l
        y = y_all[m]
        n1 = int(y.sum()); n0 = len(y) - n1
        if n1 == 0 or n0 == 0:
            continue
        r = rankdata(P_all[m], axis=0, method="average")
        auc = (r[y == 1].sum(0) - n1 * (n1 + 1) / 2) / (n1 * n0)
        out[l] = dict(zip(COLS, auc))
    return out


def stats(d, langs):
    per = lang_auroc(d)
    r = {}
    mac = {c: float(np.mean([per[l][c] for l in langs if l in per])) for c in COLS}
    for m, mn in MODELS.items():
        for c in MODES:
            r[f"{mn} {MNAME[c]}|macro"] = mac[f"{m}_{c}"]
        for a, b in (("lolo", "mono"), ("multi", "mono"), ("lolo", "multi")):
            r[f"{mn} {MNAME[a]} − {MNAME[b]}|macro"] = mac[f"{m}_{a}"] - mac[f"{m}_{b}"]
    for c in MODES:
        r[f"CodeBERT − UniXcoder ({MNAME[c]})|macro"] = mac[f"cb_{c}"] - mac[f"ux_{c}"]
        if all(l in per for l in NOT_PRE + PRE):
            dd = {l: per[l][f"cb_{c}"] - per[l][f"ux_{c}"] for l in NOT_PRE + PRE}
            r[f"Hiệu kép ({MNAME[c]})|macro"] = np.mean([dd[l] for l in NOT_PRE]) - np.mean([dd[l] for l in PRE])
    for l in per:  # theo ngôn ngữ (mô tả)
        for m, mn in MODELS.items():
            for c in MODES:
                r[f"{mn} {MNAME[c]}|{l}"] = per[l][f"{m}_{c}"]
        for c in MODES:
            r[f"CodeBERT − UniXcoder ({MNAME[c]})|{l}"] = per[l][f"cb_{c}"] - per[l][f"ux_{c}"]
    return r


def verdict(lo, hi, diff):
    if diff:
        if lo >= -EQ and hi <= EQ:
            return "tương đương (trong ±0,03)"
        return "dương (CI > 0)" if lo > 0 else "âm (CI < 0)" if hi < 0 else "không phân biệt được"
    if lo >= 0.45 and hi <= CH:
        return "tương đương ngẫu nhiên"
    return "trên ngẫu nhiên" if lo > CH else "dưới ngẫu nhiên" if hi < 0.45 else "không phân biệt được"


def boot_table(d, langs, label):
    d = d.reset_index(drop=True)
    codes, uniq = pd.factorize(d["group"]); order = np.argsort(codes, kind="stable")
    bounds = np.searchsorted(codes[order], np.arange(len(uniq) + 1)); rng = np.random.default_rng(BSEED)
    pt = stats(d, langs); bs = {k: [] for k in pt}
    for _ in range(B):
        x = d.iloc[np.concatenate([order[bounds[c]:bounds[c + 1]] for c in rng.integers(0, len(uniq), len(uniq))])]
        v = stats(x, langs)
        for k in pt:
            bs[k].append(v.get(k, np.nan))
    rows = []
    for k, val in pt.items():
        name, lang = k.split("|")
        lo, hi = np.nanpercentile(bs[k], [2.5, 97.5])
        diff = ("−" in name) or name.startswith("Hiệu kép")
        sub = d if lang == "macro" else d[d.language == lang]
        rows.append(dict(tap=label, stat=name, language=lang, estimate=val, ci_low=lo, ci_high=hi,
                         verdict=verdict(lo, hi, diff), n_units=len(sub), n_groups=sub.group.nunique()))
    return pd.DataFrame(rows)


def cap_per_group(w):
    rng = np.random.default_rng(S2_SEED); keep = []
    for _, idx in w.groupby("group", sort=True).groups.items():
        idx = np.asarray(sorted(idx))
        keep.append(idx if len(idx) <= S2_CAP else np.sort(rng.choice(idx, S2_CAP, replace=False)))
    return w.loc[np.concatenate(keep)].reset_index(drop=True)


def within_cluster(w):
    """AUROC trong cụm, trung bình theo cụm (mỗi cụm có cả hai nhãn trọng số như nhau), macro 6 (mô tả)."""
    res = {}
    for c in COLS:
        per = []
        for l in M6:
            g = w[w.language == l]
            vals = []
            for _, h in g.groupby("group"):
                if h.target.nunique() == 2:
                    r = rankdata(h[c].to_numpy()); y = h.target.to_numpy(); n1 = y.sum(); n0 = len(y) - n1
                    vals.append((r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))
            per.append(np.mean(vals))
        res[c] = float(np.mean(per))
    return res


def curves(root):
    """AUROC macro 6 trên test theo epoch (ghép mọi job của một cấu hình) và epoch được chọn."""
    out = {}
    for c in MODES:
        fs = sorted(glob.glob(f"{root}/{c}/*/*/seed_17/test_by_epoch.csv"))
        if not fs:
            continue
        t = pd.concat(pd.read_csv(f) for f in fs)
        ep = sorted(int(x[3:]) for x in t.columns if x.startswith("p_e"))
        out[c] = {"auroc_macro6_by_epoch": [float(np.mean([roc_auc_score(t[t.language == l].true_label,
                                                                    t[t.language == l][f"p_e{e}"]) for l in M6]))
                                            for e in ep]}
        logs = [json.load(open(Path(f).with_name("log.json"))) for f in fs]
        out[c]["selected_epoch"] = pd.Series([lg["selected_epoch"] for lg in logs]).value_counts().sort_index().to_dict()
        out[c]["gpu_hours"] = round(sum(lg["seconds"] for lg in logs) / 3600, 2)
    return out


def main():
    ap = argparse.ArgumentParser()
    for k in ("cb", "ux-mvd", "ux-cvf", "mvd-folds", "mvd-commit", "cvf-units", "cvf-folds", "res"):
        ap.add_argument(f"--{k}", required=True)
    ap.add_argument("--datasets", nargs="*", default=["mvd", "cvf"])
    a = ap.parse_args()
    res = Path(a.res); res.mkdir(parents=True, exist_ok=True)
    pd.set_option("display.width", 250); pd.set_option("display.max_rows", 500)
    summary = {}
    for ds in a.datasets:
        w = build(ds, a)
        ux_hash = w.attrs["ux_hash"]
        tabs = [boot_table(w, M6, "chính, macro 6"),
                boot_table(w, LANGS, "S3 macro 7"),
                boot_table(w[~w.is_giant], M6, "S1 bỏ cụm khổng lồ"),
                boot_table(cap_per_group(w), M6, "S2 tối đa 50 hàm mỗi cụm"),
                boot_table(w[w.n_vuln_funcs_in_commit <= 20], M6, "S4 commit ≤ 20 hàm nhãn 1"),
                boot_table(w[w.n_vuln_funcs_in_commit <= 5], M6, "S4 commit ≤ 5 hàm nhãn 1"),
                boot_table(w[w.n_code_tokens <= 510], M6, "S5 hàm ≤ 510 token (CodeBERT thấy trọn hàm)")]
        T = pd.concat(tabs, ignore_index=True); T.to_csv(res / f"cb_{ds}_all.csv", index=False)
        M = T[T.language == "macro"]
        print(f"\n===================== {ds.upper()} ({len(w)} hàm) =====================")
        print("Mã băm chuẩn dự đoán UniXcoder (mode,unit_id,xác suất 8 chữ số; sắp xếp):", ux_hash)
        for tap, g in M.groupby("tap", sort=False):
            print(f"--- {tap}: {g.n_units.iloc[0]} hàm, {g.n_groups.iloc[0]} cụm")
            print(g[["stat", "estimate", "ci_low", "ci_high", "verdict"]].round(3).to_string(index=False))
        bl = T[(T.tap == "chính, macro 6") & (T.language != "macro")].pivot(index="language", columns="stat", values="estimate")
        bl.to_csv(res / f"cb_{ds}_by_language.csv")
        tr = w.groupby("language").agg(n=("unit_id", "size"), ty_le_bi_cat=("truncated", "mean"),
                                       trung_vi_token=("n_code_tokens", "median"))
        tr.loc["Tổng"] = [len(w), w.truncated.mean(), w.n_code_tokens.median()]
        tr.to_csv(res / f"cb_{ds}_truncation.csv")
        print("--- Tỷ lệ hàm bị cắt ở 510 token mã (CodeBERT)"); print(tr.round(3).to_string())
        wc = within_cluster(w); print("--- AUROC trong cụm, trung bình theo cụm, macro 6 (mô tả)")
        print({k: round(v, 3) for k, v in wc.items()})
        cv = {"CodeBERT": curves(f"{a.cb}/{ds}/e10"), "UniXcoder": curves(a.ux_mvd if ds == "mvd" else a.ux_cvf)}
        print("--- Đường AUROC test macro 6 theo epoch, epoch được chọn, giờ GPU (mô tả)")
        for mn, d in cv.items():
            for c, v in d.items():
                print(f"  {mn:9s} {c:5s} {[round(x, 3) for x in v['auroc_macro6_by_epoch']]}  chọn: {v['selected_epoch']}  "
                      f"{v['gpu_hours']} giờ")
        summary[ds] = dict(n_units=len(w), ux_predictions_hash=ux_hash, within_cluster=wc, curves=cv)
    (res / "cb_summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
