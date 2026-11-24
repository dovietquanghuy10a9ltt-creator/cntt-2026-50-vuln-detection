"""
Phân tích độ nhạy (EXPLORATORY): AUROC của Mono / Multi / LOLO từ 105 file dự đoán sẵn có,
khi loại các CVE lớn nhất của từng ngôn ngữ, kèm cluster bootstrap theo CVE (1 CVE = 1 cụm).
Không huấn luyện lại mô hình. Cần unit_map.csv (unit_id -> cve_id) tạo từ dữ liệu thô + hàm băm của protocol.
"""
import sys, json, glob, numpy as np, pandas as pd
from scipy.stats import rankdata

REPO = sys.argv[1]; UMAP = sys.argv[2]; OUT = sys.argv[3]
LANG = {'c':'C','cplusplus':'C++','csharp':'C#','go':'Go','java':'Java','javascript':'JavaScript','python':'Python'}
SEEDS = [17, 29, 43, 71, 101]; B = 1000; rng = np.random.default_rng(12345)

um = pd.read_csv(UMAP)
raw_n = um.groupby(['language', 'cve_id']).size()               # cỡ cụm trên dữ liệu thô
te = um[um.orig_split == 'test'].drop_duplicates('unit_id')
cve_of = dict(zip(te.unit_id, te.cve_id))
amb = um[um.orig_split=='test'].groupby('unit_id').cve_id.nunique()
print("unit_id test có >1 CVE (mơ hồ):", int((amb > 1).sum()))

def load(path):
    d = {}
    for l in open(path):
        r = json.loads(l); d[r['unit_id']] = (r['true_label'], r['prob_vulnerable'])
    return d

def auroc(y, p):
    n1 = y.sum(); n0 = len(y) - n1
    if n1 == 0 or n0 == 0: return np.nan
    r = rankdata(p)
    return (r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)

# preds[model][lang] = (unit_ids, y, P[seed, n])
preds = {m: {} for m in ['Mono', 'Multi', 'LOLO']}
for k, L in LANG.items():
    for m in ['Mono', 'Multi', 'LOLO']:
        per_seed = []
        for s in SEEDS:
            if m == 'Mono':  f = f"{REPO}/results/rq1_mono/{k}/seed_{s}/test_predictions.jsonl"
            if m == 'LOLO':  f = f"{REPO}/results/rq3_lolo/{k}/seed_{s}/test_predictions.jsonl"
            if m == 'Multi': f = f"{REPO}/results/rq2_multi/seed_{s}/test_{k}_predictions.jsonl"
            per_seed.append(load(f))
        ids = sorted(per_seed[0])
        y = np.array([per_seed[0][u][0] for u in ids])
        P = np.array([[ps[u][1] for u in ids] for ps in per_seed])
        preds[m][L] = (ids, y, P)

def seed_mean_auroc(y, P, idx):
    return np.nanmean([auroc(y[idx], P[s, idx]) for s in range(P.shape[0])])

rows = []
for L in LANG.values():
    ids, y, _ = preds['Mono'][L]
    cve = np.array([cve_of[u] for u in ids])
    ranked = raw_n[L].sort_values(ascending=False)
    conds = {'all': [], 'excl_top1': list(ranked.index[:1]), 'excl_top3': list(ranked.index[:3])}
    for cname, excl in conds.items():
        keep = np.where(~np.isin(cve, excl))[0]
        cl = pd.Series(cve[keep]).groupby(cve[keep]).apply(lambda s: s.index.values)   # chỉ số vị trí theo cụm
        groups = [keep[np.array([np.where(keep == i)[0][0] for i in g])] for g in cl.values] if False else \
                 [keep[np.where(cve[keep] == c)[0]] for c in np.unique(cve[keep])]
        pt = {m: seed_mean_auroc(y, preds[m][L][2], keep) for m in preds}
        boot = {m: [] for m in preds}
        for _ in range(B):
            pick = rng.integers(0, len(groups), len(groups))
            idx = np.concatenate([groups[i] for i in pick])
            for m in preds:
                boot[m].append(seed_mean_auroc(y, preds[m][L][2], idx))
        ci = lambda a: tuple(np.nanpercentile(a, [2.5, 97.5]))
        d_lm = np.array(boot['LOLO']) - np.array(boot['Mono'])
        rows.append(dict(language=L, condition=cname, n_test=len(keep), n_cve_clusters=len(groups),
                         excluded=";".join(excl),
                         **{f"auroc_{m}": round(pt[m], 4) for m in pt},
                         **{f"ci_{m}": f"[{ci(boot[m])[0]:.3f},{ci(boot[m])[1]:.3f}]" for m in pt},
                         d_LOLO_minus_Mono=round(pt['LOLO'] - pt['Mono'], 4),
                         ci_d=f"[{ci(d_lm)[0]:.3f},{ci(d_lm)[1]:.3f}]"))
res = pd.DataFrame(rows); res.to_csv(OUT + "auroc_by_cve_sensitivity.csv", index=False)
pd.set_option('display.width', 250); pd.set_option('display.max_columns', 30)
print(res[['language','condition','n_test','n_cve_clusters','auroc_Mono','auroc_Multi','auroc_LOLO','d_LOLO_minus_Mono','ci_d']].to_string(index=False))
print()
print(res[['language','condition','ci_Mono','ci_Multi','ci_LOLO']].to_string(index=False))
