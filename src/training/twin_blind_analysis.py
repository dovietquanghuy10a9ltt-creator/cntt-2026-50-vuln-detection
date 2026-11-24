"""Phân tích thí nghiệm "RS-blind" (bản bổ sung lần 7 của osf.io/96a2g).

Dùng: python twin_blind_analysis.py <RS-blind> <RS-twin> <RS> <CVE seed 17> \
                                   twin_folds_v1_pairs.csv random_folds_v1.csv groups_and_folds_v1.csv
Mỗi thư mục chứa */*/*/seed_17/predictions.csv (mono và multi) như các lần trước.

Đơn vị phân tích và chỉ số giống hệt bản bổ sung lần 3: 1.157 cặp sinh đôi; c_i = 1 nếu xác suất lỗi của hàm nhãn 1 lớn hơn
hàm nhãn 0, 0,5 nếu bằng, 0 nếu nhỏ hơn; "AUROC cặp" = trung bình c_i, gộp 7 ngôn ngữ, mỗi cặp trọng số bằng nhau.
Khoảng tin cậy 95%: bootstrap theo cặp, B = 1.000, seed 20260101, mọi nhánh dùng chung chỉ số lấy mẫu (so sánh ghép cặp).

Bốn nhánh trên cùng các cặp:
  RS       : chia ngẫu nhiên (bổ sung lần 1) — cặp bị tách, mô hình chấm một hàm đã học hàm kia, hai mô hình khác nhau.
  RS-blind : như RS nhưng mô hình chấm một hàm không thấy hàm kia (bổ sung lần 7) — hai mô hình khác nhau.
  RS-twin  : hai hàm cùng fold, cờ validation đồng bộ (bổ sung lần 3) — cùng một mô hình.
  CVE      : chia theo cụm CVE, seed 17 (bản gốc) — cùng một mô hình.

  H1 (chính, Mono, 930 cặp): RS-blind − RS > 0; khẳng định nếu cận dưới > 0.
  H2 (chính, Mono, 930 cặp): RS-twin − RS-blind. Trong [−0,05; +0,05] → tương đương; cận dưới > 0 → RS-twin cao hơn;
      cận trên < 0 → RS-blind cao hơn; còn lại → không kết luận.
  H3 (phụ, Mono, 930 cặp): RS-blind − CVE trong [−0,05; +0,05] → tương đương.
  C1 (đối chứng, Mono, 227 cặp vốn cùng fold): RS-blind − RS, kỳ vọng khoảng tin cậy chứa 0.
  Multi: H1, H2, H3, C1 như trên (phụ).
  Mô tả: tỷ lệ (RS-blind − RS) / (RS-twin − RS); AUROC cặp của RS theo số phía bị phơi nhiễm trong chính lần chạy RS
      (phía bị phơi nhiễm = hàm đối ứng nằm trong tập huấn luyện của mô hình chấm hàm đó); AUROC macro 6 ngôn ngữ của
      RS-blind và RS (bootstrap theo cụm CVE), hiệu ghép cặp.
"""
import glob
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

B, SEED, EQ = 1000, 20260101, 0.05
MACRO6 = ["C", "C++", "Go", "Java", "JavaScript", "Python"]
FLAGS = [f"inner_val_fold{k}" for k in range(5)]


def preds(d):
    p = pd.concat(pd.read_csv(x) for x in glob.glob(f"{d}/*/*/*/seed_17/predictions.csv"))
    p = p[p["mode"].isin(["mono", "multi"])]
    assert p.groupby("mode").unit_id.nunique().eq(18694).all(), d
    assert not p.duplicated(["mode", "unit_id"]).any(), d
    return p.pivot(index="unit_id", columns="mode", values="prob_vulnerable")


def conc(pairs, P, col):
    a = P.loc[pairs.u_pos, col].values
    b = P.loc[pairs.u_neg, col].values
    return np.where(a > b, 1.0, np.where(a == b, 0.5, 0.0))


def ci(bs):
    return np.percentile(bs, 2.5), np.percentile(bs, 97.5)


def verdict_eq(lo, hi):
    return "tương đương (trong ±0,05)" if (lo >= -EQ and hi <= EQ) else "không kết luận tương đương"


def verdict_h2(lo, hi):
    if lo >= -EQ and hi <= EQ:
        return "tương đương (trong ±0,05)"
    if lo > 0:
        return "RS-twin cao hơn (CI > 0)"
    if hi < 0:
        return "RS-blind cao hơn (CI < 0)"
    return "không kết luận"


def exposure_sides(pairs, rf):
    """Số phía bị phơi nhiễm trong lần chạy RS (0, 1, 2) cho mỗi cặp bị tách."""
    f = rf.fold
    def exposed(scored, twin):
        k = f.loc[scored].values
        flag = np.array([rf.at[t, FLAGS[i]] for t, i in zip(twin, k)], dtype=bool)
        return ~flag  # hàm đối ứng không thuộc validation của mô hình fold k → nằm trong tập huấn luyện
    return exposed(pairs.u_pos.values, pairs.u_neg.values).astype(int) + exposed(pairs.u_neg.values, pairs.u_pos.values).astype(int)


def main(d_bl, d_tw, d_rs, d_cve, pairs_csv, rf_csv, v1_csv):
    pairs = pd.read_csv(pairs_csv)
    assert len(pairs) == 1157 and pairs.split_in_random.sum() == 930
    rf = pd.read_csv(rf_csv).set_index("unit_id")
    assert (rf.fold.loc[pairs.u_pos].values != rf.fold.loc[pairs.u_neg].values).sum() == 930
    BL, TW, RS, CV = preds(d_bl), preds(d_tw), preds(d_rs), preds(d_cve)
    split = pairs.split_in_random.values
    sp, ct = np.flatnonzero(split), np.flatnonzero(~split)
    expo = exposure_sides(pairs[split], rf)
    rows = []
    for m in ("mono", "multi"):
        rng = np.random.default_rng(SEED)
        c = {"RS-blind": conc(pairs, BL, m), "RS-twin": conc(pairs, TW, m), "RS": conc(pairs, RS, m), "CVE": conc(pairs, CV, m)}
        for name, sel in (("930 cặp bị tách trong RS", sp), ("227 cặp vốn cùng fold", ct)):
            idx = [sel[rng.integers(0, len(sel), len(sel))] for _ in range(B)]
            bs = {a: np.array([x[i].mean() for i in idx]) for a, x in c.items()}
            for a, x in c.items():
                lo, hi = ci(bs[a])
                rows.append(dict(mode=m, pairs=name, stat=f"AUROC cặp {a}", est=x[sel].mean(), lo=lo, hi=hi))
            def diff(a, b):
                return c[a][sel].mean() - c[b][sel].mean(), *ci(bs[a] - bs[b])
            if name.startswith("930"):
                e, lo, hi = diff("RS-blind", "RS")
                rows.append(dict(mode=m, pairs=name, stat="H1: RS-blind − RS", est=e, lo=lo, hi=hi,
                                 verdict="khẳng định (CI > 0)" if lo > 0 else "không khẳng định"))
                e, lo, hi = diff("RS-twin", "RS-blind")
                rows.append(dict(mode=m, pairs=name, stat="H2: RS-twin − RS-blind", est=e, lo=lo, hi=hi, verdict=verdict_h2(lo, hi)))
                e, lo, hi = diff("RS-blind", "CVE")
                rows.append(dict(mode=m, pairs=name, stat="H3: RS-blind − CVE", est=e, lo=lo, hi=hi, verdict=verdict_eq(lo, hi)))
                num, den = bs["RS-blind"] - bs["RS"], bs["RS-twin"] - bs["RS"]
                ok = den > 0
                pt = (c["RS-blind"][sel].mean() - c["RS"][sel].mean()) / (c["RS-twin"][sel].mean() - c["RS"][sel].mean())
                lo, hi = ci(num[ok] / den[ok])
                rows.append(dict(mode=m, pairs=name, stat="Mô tả: (RS-blind − RS) / (RS-twin − RS)", est=pt, lo=lo, hi=hi))
            else:
                e, lo, hi = diff("RS-blind", "RS")
                rows.append(dict(mode=m, pairs=name, stat="C1: RS-blind − RS (đối chứng)", est=e, lo=lo, hi=hi,
                                 verdict="CI chứa 0 (như kỳ vọng)" if lo <= 0 <= hi else "CI không chứa 0"))
        # mô tả: phơi nhiễm tự nhiên trong RS
        x = c["RS"][sp]
        for s in (2, 1, 0):
            sel = np.flatnonzero(expo == s)
            if len(sel) == 0:
                continue
            bs = [x[sel[rng.integers(0, len(sel), len(sel))]].mean() for _ in range(B)]
            lo, hi = ci(bs)
            rows.append(dict(mode=m, pairs=f"RS, cặp bị tách có {s} phía bị phơi nhiễm (n = {len(sel)})",
                             stat="Mô tả: AUROC cặp RS", est=x[sel].mean(), lo=lo, hi=hi))
    R = pd.DataFrame(rows)

    # mô tả: AUROC macro 6 ngôn ngữ, bootstrap theo cụm CVE (cụm lấy từ groups_and_folds_v1.csv)
    v1 = pd.read_csv(v1_csv)[["unit_id", "language", "target", "group"]].set_index("unit_id")
    w = v1.join(BL.add_prefix("bl_")).join(RS.add_prefix("rs_")).reset_index()
    cols = ["bl_mono", "rs_mono", "bl_multi", "rs_multi"]
    def macro(d, col):
        return np.mean([roc_auc_score(d[d.language == l].target, d[d.language == l][col]) for l in MACRO6])
    codes, uniq = pd.factorize(w.group)
    order = np.argsort(codes, kind="stable")
    bounds = np.searchsorted(codes[order], np.arange(len(uniq) + 1))
    rng = np.random.default_rng(SEED)
    pt = {col: macro(w, col) for col in cols}
    bs = {col: [] for col in cols}
    for _ in range(B):
        idx = np.concatenate([order[bounds[g]:bounds[g + 1]] for g in rng.integers(0, len(uniq), len(uniq))])
        d = w.iloc[idx]
        for col in cols:
            bs[col].append(macro(d, col))
    for m in ("mono", "multi"):
        for arm in ("bl", "rs"):
            lo, hi = ci(bs[f"{arm}_{m}"])
            R.loc[len(R)] = dict(mode=m, pairs="toàn bộ, macro 6 ngôn ngữ", stat=f"Mô tả: AUROC macro {'RS-blind' if arm == 'bl' else 'RS'}",
                                 est=pt[f"{arm}_{m}"], lo=lo, hi=hi)
        dd = np.array(bs[f"bl_{m}"]) - np.array(bs[f"rs_{m}"])
        lo, hi = ci(dd)
        R.loc[len(R)] = dict(mode=m, pairs="toàn bộ, macro 6 ngôn ngữ", stat="Mô tả: AUROC macro RS-blind − RS",
                             est=pt[f"bl_{m}"] - pt[f"rs_{m}"], lo=lo, hi=hi)
    pd.set_option("display.width", 240)
    pd.set_option("display.max_colwidth", 60)
    print(R.round(3).to_string(index=False))
    return R


if __name__ == "__main__":
    R = main(*sys.argv[1:8])
    R.to_csv("twin_blind_results.csv", index=False)
