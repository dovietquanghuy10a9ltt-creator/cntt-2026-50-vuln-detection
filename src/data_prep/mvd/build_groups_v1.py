"""
Phân fold chính thức (v1) trên TẬP SẠCH 18.694 đơn vị (clean_exact_hash của MVDDatasetLoader).

- Nhóm: thành phần liên thông của các CVE (một đơn vị có thể mang nhiều CVE -> nối chúng lại), TOÀN CỤC xuyên ngôn ngữ.
- Fold ngoài: 5 fold, greedy phân tầng ngôn ngữ x nhãn, seed 42.
- Validation nội bộ (để chọn checkpoint): với mỗi fold ngoài k, từ các cụm còn lại (loại cụm khổng lồ >10% ngôn ngữ),
  chia greedy phân tầng thành 10 bin (seed 100+k) và lấy bin 9 làm validation (~10%). Cụm khổng lồ luôn ở train.
"""
import sys, random, pickle
import numpy as np, pandas as pd

PKL = sys.argv[1]; OUT = sys.argv[2]
K, SEED, GIANT = 5, 42, 0.10
df = pd.read_pickle(PKL).reset_index(drop=True)
print("đơn vị:", len(df), "| split hiệu lực:", df.split.value_counts().to_dict(),
      "| đơn vị không có CVE:", int((df.all_cves.map(len) == 0).sum()),
      "| đơn vị mang >1 CVE:", int((df.all_cves.map(len) > 1).sum()))

# ---- thành phần liên thông trên các CVE ----
parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]; x = parent[x]
    return x
for cves in df.all_cves:
    cs = list(cves)
    for c in cs[1:]:
        ra, rb = find(cs[0]), find(c)
        if ra != rb: parent[rb] = ra
root = [find(c[0]) if len(c) else f"nocve:{i}" for i, c in enumerate(df.all_cves)]
df["group"] = pd.factorize(pd.Series(root))[0]

# ---- thống kê cụm theo ngôn ngữ ----
rows = []
size = df.groupby("group").size()
df["group_size"] = df.group.map(size)
for L, g in df.groupby("language"):
    sz = g.groupby("group").size().sort_values(ascending=False)
    span = df[df.group.isin(sz.index)].groupby("group").language.nunique()
    rows.append(dict(language=L, n_units=len(g), n_clusters=len(sz), median_cluster=float(sz.median()),
                     max_cluster=int(sz.iloc[0]), top1_share=round(sz.iloc[0]/len(g), 3),
                     effective_clusters=round(len(g)**2/(sz**2).sum(), 1),
                     giant_clusters_gt10pct=int((sz/len(g) > GIANT).sum()),
                     clusters_spanning_langs=int((span > 1).sum())))
stat = pd.DataFrame(rows); stat.to_csv(OUT + "cluster_stats_clean_v1.csv", index=False)

# rò rỉ ở mức cụm theo split hiệu lực gốc
spl = df.groupby("group").split.agg(set)
df["_sp"] = df.group.map(spl)
leak = (df[df.split == "test"].assign(in_train=lambda d: d._sp.map(lambda s: "train" in s))
        .groupby("language").in_train.mean().mul(100).round(1))

# ---- greedy phân tầng ----
df["_stratum"] = df.language + "|" + df.target.astype(str)
strata = sorted(df._stratum.unique())
def greedy(groups, k, seed):
    rng = random.Random(seed)
    sub = df[df.group.isin(groups)]
    tgt_cnt = sub._stratum.value_counts() / k
    comp = sub.groupby("group")._stratum.value_counts().unstack(fill_value=0).reindex(columns=strata, fill_value=0)
    order = list(comp.sum(axis=1).items()); rng.shuffle(order); order.sort(key=lambda t: -t[1])
    tgt = np.array([tgt_cnt.get(s, 0.0) for s in strata]); load = np.zeros((k, len(strata))); out = {}
    for gid, _ in order:
        v = comp.loc[gid].values
        costs = [((load[i] + v - tgt)**2 - (load[i] - tgt)**2).sum() for i in range(k)]
        mn = min(costs)
        # hòa chi phí -> chọn fold đang có tổng tải nhỏ nhất (rồi mới tới chỉ số nhỏ nhất), để các cụm khổng lồ
        # thuộc các nhóm (ngôn ngữ x nhãn) khác nhau không bị dồn vào cùng fold 0
        f = min((i for i in range(k) if costs[i] <= mn + 1e-9), key=lambda i: (load[i].sum(), i))
        load[f] += v; out[gid] = f
    return out

fold_of = greedy(df.group.unique(), K, SEED)
df["fold"] = df.group.map(fold_of)

# giant cluster: >10% số đơn vị của ngôn ngữ chứa nó
lang_n = df.groupby("language").size()
grp_lang_max = df.groupby(["group", "language"]).size().reset_index(name="n")
grp_lang_max["share"] = grp_lang_max.n / grp_lang_max.language.map(lang_n)
giant = set(grp_lang_max[grp_lang_max.share > GIANT].group)
df["is_giant"] = df.group.isin(giant)

for k in range(K):
    train_groups = [g for g in df[df.fold != k].group.unique() if g not in giant]
    m = greedy(train_groups, 10, 100 + k)
    val_groups = {g for g, b in m.items() if b == 9}
    df[f"inner_val_fold{k}"] = df.group.isin(val_groups) & (df.fold != k)

keep = ["unit_id", "representative_id", "language", "target", "split", "group", "group_size", "is_giant", "fold"] \
       + [f"inner_val_fold{k}" for k in range(K)]
df[keep].rename(columns={"split": "effective_split_v1"}).to_csv(OUT + "groups_and_folds_v1.csv", index=False)

pd.set_option("display.width", 220)
print("\n=== Cụm trên tập sạch ===\n", stat.to_string(index=False))
print("\n% đơn vị test có cụm CVE xuất hiện trong train (split hiệu lực):\n", leak.to_dict())
print("\nCụm khổng lồ (>10% ngôn ngữ):")
for gid in sorted(giant):
    s = df[df.group == gid]
    print(f"  group {gid}: {len(s)} đơn vị, ngôn ngữ {sorted(s.language.unique())}, CVE ví dụ {s.all_cves.iloc[0][:1]}, fold {sorted(s.fold.unique())}")
t = df.groupby(["fold", "language"]).size().unstack(fill_value=0)
print("\nSố đơn vị mỗi fold x ngôn ngữ:\n", t.to_string())
print("\nTỷ lệ nhãn dương mỗi fold:", df.groupby("fold").target.mean().round(3).to_dict())
for k in range(K):
    tr = df[df.fold != k]; v = tr[tr[f"inner_val_fold{k}"]]
    print(f"fold {k}: test={int((df.fold==k).sum())} | train={len(tr)-len(v)} | val_nội_bộ={len(v)} ({100*len(v)/len(tr):.1f}% của phần huấn luyện) | ngôn ngữ nhỏ nhất trong val: {v.language.value_counts().idxmin()}={v.language.value_counts().min()}")
