"""Phân tích thí nghiệm can thiệp "cặp sinh đôi" (bản bổ sung lần 3 của osf.io/96a2g).

Dùng: python twin_analysis.py <thư mục kết quả RS-twin> <thư mục RS (bổ sung lần 1)> <thư mục CVE seed 17>
                                twin_folds_v1_pairs.csv groups_and_folds_v1.csv random_folds_v1.csv twin_folds_v1.csv
Mỗi thư mục chứa */*/*/seed_17/predictions.csv như các lần trước.

Đơn vị phân tích: 1.157 cặp sinh đôi (khối ngôn ngữ × cụm CVE có đúng 2 hàm, ngược nhãn).
c_i = 1 nếu xác suất lỗi của hàm nhãn 1 > hàm nhãn 0, 0,5 nếu bằng, 0 nếu nhỏ hơn. "AUROC cặp" = trung bình c_i,
gộp cả 7 ngôn ngữ, mỗi cặp trọng số bằng nhau. CI 95% bootstrap theo cặp, B = 1.000, seed 20260101.
  H1 (chính, Mono): trên 930 cặp bị tách trong RS: mean c(RS-twin) − mean c(RS) > 0  (khẳng định nếu cận dưới CI > 0).
  H2 (phụ, Mono): trên 930 cặp đó: mean c(RS-twin) − mean c(CVE) nằm trong [−0,05; +0,05] → tương đương.
  C1 (đối chứng, Mono): trên 227 cặp vốn cùng fold trong RS (phân công không đổi): mean c(RS-twin) − mean c(RS),
     kỳ vọng CI chứa 0.
  Multi: H1, H2, C1 như trên (phụ).
  Mô tả: AUROC macro 6 ngôn ngữ RS-twin, RS, CVE (bootstrap theo cụm CVE, mã phân tích đã đăng ký), hiệu RS-twin − RS
  ghép cặp; AUROC trong cụm trung bình theo cụm, chia theo cỡ cụm.
"""
import glob, sys
import numpy as np, pandas as pd

B, SEED, EQ = 1000, 20260101, 0.05


def preds(d):
    p = pd.concat(pd.read_csv(x) for x in glob.glob(f"{d}/*/*/*/seed_17/predictions.csv"))
    p = p[p["mode"].isin(["mono", "multi"])]
    assert p.groupby("mode").unit_id.nunique().eq(18694).all(), d
    return p.pivot(index="unit_id", columns="mode", values="prob_vulnerable")


def conc(pairs, P, col):
    a = P.loc[pairs.u_pos, col].values; b = P.loc[pairs.u_neg, col].values
    return np.where(a > b, 1.0, np.where(a == b, 0.5, 0.0))


def boot_diff(x, y, rng):
    n = len(x); bs = []
    for _ in range(B):
        i = rng.integers(0, n, n); bs.append(x[i].mean() - y[i].mean())
    return x.mean() - y.mean(), np.percentile(bs, 2.5), np.percentile(bs, 97.5)


def boot_mean(x, rng):
    n = len(x); bs = [x[rng.integers(0, n, n)].mean() for _ in range(B)]
    return x.mean(), np.percentile(bs, 2.5), np.percentile(bs, 97.5)


def main(d_tw, d_rs, d_cve, pairs_csv, v1_csv, rf_csv, tf_csv):
    pairs = pd.read_csv(pairs_csv)
    assert len(pairs) == 1157 and pairs.split_in_random.sum() == 930
    rf = pd.read_csv(rf_csv).set_index("unit_id").fold; tf = pd.read_csv(tf_csv).set_index("unit_id").fold
    assert (rf.loc[pairs.u_pos].values != rf.loc[pairs.u_neg].values).sum() == 930
    assert (tf.loc[pairs.u_pos].values == tf.loc[pairs.u_neg].values).all()
    TW, RS, CV = preds(d_tw), preds(d_rs), preds(d_cve)
    split = pairs.split_in_random.values
    rows = []
    for m in ("mono", "multi"):
        rng = np.random.default_rng(SEED)
        ct, cr, cc = conc(pairs, TW, m), conc(pairs, RS, m), conc(pairs, CV, m)
        for name, sel in (("930 cặp bị tách trong RS", split), ("227 cặp vốn cùng fold", ~split), ("tất cả 1.157 cặp", np.ones_like(split))):
            for arm, x in (("RS-twin", ct), ("RS", cr), ("CVE", cc)):
                e, lo, hi = boot_mean(x[sel], rng); rows.append(dict(mode=m, pairs=name, stat=f"AUROC cặp {arm}", est=e, lo=lo, hi=hi))
        e, lo, hi = boot_diff(ct[split], cr[split], rng)
        rows.append(dict(mode=m, pairs="930 cặp bị tách trong RS", stat="H1: RS-twin − RS", est=e, lo=lo, hi=hi,
                         verdict="khẳng định (CI > 0)" if lo > 0 else "không khẳng định"))
        e, lo, hi = boot_diff(ct[split], cc[split], rng)
        rows.append(dict(mode=m, pairs="930 cặp bị tách trong RS", stat="H2: RS-twin − CVE", est=e, lo=lo, hi=hi,
                         verdict="tương đương (trong ±0,05)" if (lo >= -EQ and hi <= EQ) else "không kết luận tương đương"))
        e, lo, hi = boot_diff(ct[~split], cr[~split], rng)
        rows.append(dict(mode=m, pairs="227 cặp vốn cùng fold", stat="C1: RS-twin − RS (đối chứng)", est=e, lo=lo, hi=hi,
                         verdict="CI chứa 0 (như kỳ vọng)" if lo <= 0 <= hi else "CI không chứa 0"))
    R = pd.DataFrame(rows)
    pd.set_option("display.width", 220)
    print(R.round(3).to_string(index=False))
    return R, TW, RS, CV


if __name__ == "__main__":
    R, TW, RS, CV = main(*sys.argv[1:8])
    R.to_csv("twin_results.csv", index=False)
    # Mô tả: AUROC tổng thể bằng mã phân tích đã đăng ký (bootstrap theo cụm CVE, cụm lấy từ groups_and_folds_v1.csv)
    sys.path.insert(0, ".")
    from grouped_cv_analysis import _stats, MACRO6
    v1 = pd.read_csv(sys.argv[5])[["unit_id", "language", "target", "group", "is_giant"]].set_index("unit_id")
    w = v1.join(TW.add_prefix("tw_")).join(RS.add_prefix("rs_")).join(CV.add_prefix("cv_")).reset_index()
    cols = ["tw_mono", "tw_multi", "rs_mono", "rs_multi", "cv_mono", "cv_multi"]
    from sklearn.metrics import roc_auc_score
    def macro(d, c): return np.mean([roc_auc_score(d[d.language == l].target, d[d.language == l][c]) for l in MACRO6])
    codes, uniq = pd.factorize(w.group); order = np.argsort(codes, kind="stable")
    bounds = np.searchsorted(codes[order], np.arange(len(uniq) + 1)); rng = np.random.default_rng(SEED)
    pt = {c: macro(w, c) for c in cols}; bs = {c: [] for c in cols + ["d_mono", "d_multi"]}
    for _ in range(B):
        idx = np.concatenate([order[bounds[c]:bounds[c + 1]] for c in rng.integers(0, len(uniq), len(uniq))])
        d = w.iloc[idx]; v = {c: macro(d, c) for c in cols}
        for c in cols: bs[c].append(v[c])
        bs["d_mono"].append(v["tw_mono"] - v["rs_mono"]); bs["d_multi"].append(v["tw_multi"] - v["rs_multi"])
    pt["d_mono"] = pt["tw_mono"] - pt["rs_mono"]; pt["d_multi"] = pt["tw_multi"] - pt["rs_multi"]
    print("AUROC macro6 (mô tả):")
    for c in cols + ["d_mono", "d_multi"]:
        print(f"  {c:9s} {pt[c]:+.3f} [{np.percentile(bs[c], 2.5):+.3f}, {np.percentile(bs[c], 97.5):+.3f}]")
