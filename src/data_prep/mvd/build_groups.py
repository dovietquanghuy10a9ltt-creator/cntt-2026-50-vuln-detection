"""
Gom cụm liên thông (connected components) cho MVD và tạo fold cho grouped k-fold.

Đầu vào : train_w_line.csv, val_w_line.csv, test_w_line.csv (dữ liệu thô, 20.165 hàm)
Đầu ra  : groups_and_folds.csv      - mỗi hàm: nhóm theo 3 cách gom + fold (k=5)
          cluster_size_by_language.csv - thống kê cỡ cụm theo ngôn ngữ và cách gom
          leakage_by_original_split.csv - tỷ lệ hàm test có cụm xuất hiện ở train/val

Ba cách gom (đồ thị với nút là giá trị cve_id / url / project):
  V1: chỉ cve_id
  V2: cve_id + url commit
  V3: cve_id + url commit + project
Gom TOÀN CỤC (xuyên ngôn ngữ), vì mô hình Multi huấn luyện chung các ngôn ngữ:
một CVE nằm ở C và C++ phải rơi vào cùng một fold.
"""
import sys, random
import pandas as pd, numpy as np

SRC = sys.argv[1] if len(sys.argv) > 1 else "data/raw/"
OUT = sys.argv[2] if len(sys.argv) > 2 else "work/"
K, SEED = 5, 42

frames = []
for name in ["train", "val", "test"]:
    d = pd.read_csv(f"{SRC}{name}_w_line.csv", usecols=["id","language","cve_id","url","project","target"])
    d["orig_split"] = name
    frames.append(d)
df = pd.concat(frames, ignore_index=True)
for c in ["cve_id", "url", "project"]:
    df[c] = df[c].astype(str).str.strip()
df["cve_id"] = df["cve_id"].str.upper()
df["project"] = df["project"].str.lower()
missing = {c: int(df[c].isin(["", "nan", "None"]).sum()) for c in ["cve_id","url","project"]}
print("Giá trị thiếu:", missing, "| tổng hàm:", len(df))

class DSU:
    def __init__(s): s.p = {}
    def find(s, x):
        s.p.setdefault(x, x)
        while s.p[x] != x:
            s.p[x] = s.p[s.p[x]]; x = s.p[x]
        return x
    def union(s, a, b):
        ra, rb = s.find(a), s.find(b)
        if ra != rb: s.p[rb] = ra

def components(cols):
    dsu = DSU()
    valid = lambda v: v not in ("", "nan", "None")
    for row in df[cols].itertuples(index=False):
        nodes = [f"{c}:{v}" for c, v in zip(cols, row) if valid(v)]
        for n in nodes[1:]: dsu.union(nodes[0], n)
    ids = []
    for i, row in enumerate(df[cols].itertuples(index=False)):
        nodes = [f"{c}:{v}" for c, v in zip(cols, row) if valid(v)]
        ids.append(dsu.find(nodes[0]) if nodes else f"singleton:{i}")
    return pd.factorize(pd.Series(ids))[0]

variants = {"V1_cve": ["cve_id"],
            "V2_cve_url": ["cve_id", "url"],
            "V3_cve_url_project": ["cve_id", "url", "project"]}
for v, cols in variants.items():
    df[v] = components(cols)

# ---------- thống kê cỡ cụm theo ngôn ngữ ----------
rows = []
for v in variants:
    csize = df.groupby(v).size()
    df[v + "_size"] = df[v].map(csize)
    glob_max = csize.max()
    for L, g in df.groupby("language"):
        sz = g.groupby(v).size().sort_values(ascending=False)
        n = len(g)
        # cụm xuyên ngôn ngữ
        span = df[df[v].isin(sz.index)].groupby(v).language.nunique()
        rows.append(dict(variant=v, language=L, n_funcs=n, n_clusters=len(sz),
                         funcs_per_cluster=round(n/len(sz), 2), median_cluster=float(sz.median()),
                         max_cluster=int(sz.iloc[0]), top1_share=round(sz.iloc[0]/n, 3),
                         top4_share=round(sz.iloc[:4].sum()/n, 3),
                         clusters_spanning_langs=int((span > 1).sum()),
                         global_max_component=int(glob_max)))
stat = pd.DataFrame(rows)
stat.to_csv(OUT + "cluster_size_by_language.csv", index=False)

# ---------- rò rỉ ở mức cụm theo split gốc ----------
rows = []
for v in variants:
    sp = df.groupby(v).orig_split.agg(lambda s: set(s))
    df[v + "_splits"] = df[v].map(sp)
    for L, g in df[df.orig_split == "test"].groupby("language"):
        in_train = g[v + "_splits"].map(lambda s: "train" in s)
        in_trval = g[v + "_splits"].map(lambda s: ("train" in s) or ("val" in s))
        rows.append(dict(variant=v, language=L, test_n=len(g),
                         pct_test_cluster_in_train=round(100*in_train.mean(), 1),
                         pct_test_cluster_in_train_or_val=round(100*in_trval.mean(), 1)))
leak = pd.DataFrame(rows)
leak.to_csv(OUT + "leakage_by_original_split.csv", index=False)

# ---------- gán fold (greedy, phân tầng theo ngôn ngữ x nhãn) ----------
def assign_folds(v, k=K, seed=SEED):
    rng = random.Random(seed)
    df["_stratum"] = df.language + "|" + df.target.astype(str)
    strata = sorted(df._stratum.unique())
    target_cnt = df._stratum.value_counts() / k
    comp = df.groupby(v)._stratum.value_counts().unstack(fill_value=0).reindex(columns=strata, fill_value=0)
    order = comp.sum(axis=1).sort_values(ascending=False)
    order = [(i, s) for i, s in order.items()]
    # cụm bằng cỡ: xáo trộn có seed để tie-break ổn định
    rng.shuffle(order); order.sort(key=lambda t: -t[1])
    load = np.zeros((k, len(strata)))
    tgt = np.array([target_cnt[s] for s in strata])
    fold_of = {}
    for cid, _ in order:
        vec = comp.loc[cid].values
        costs = [((load[f] + vec - tgt)**2 - (load[f] - tgt)**2).sum() for f in range(k)]
        f = int(np.argmin(costs)); load[f] += vec; fold_of[cid] = f
    return df[v].map(fold_of)

for v in ["V2_cve_url", "V3_cve_url_project"]:
    df["fold_" + v] = assign_folds(v)

keep = ["id","language","target","cve_id","url","project","orig_split"] + list(variants) \
       + ["fold_V2_cve_url", "fold_V3_cve_url_project"]
df[keep].to_csv(OUT + "groups_and_folds.csv", index=False)

# ---------- báo cáo ----------
pd.set_option("display.width", 220); pd.set_option("display.max_columns", 30)
for v in variants:
    print(f"\n=== {v} : cụm lớn nhất toàn cục = {int(stat[stat.variant==v].global_max_component.iloc[0])} hàm ===")
    print(stat[stat.variant == v].drop(columns=["variant", "global_max_component"]).to_string(index=False))
print("\n=== % hàm test có cụm xuất hiện ở train (split gốc) ===")
print(leak.pivot(index="language", columns="variant", values="pct_test_cluster_in_train").to_string())
for v in ["V2_cve_url", "V3_cve_url_project"]:
    t = df.groupby(["fold_" + v, "language"]).size().unstack(fill_value=0)
    p = df.groupby(["fold_" + v, "language"]).target.mean().unstack()
    print(f"\n=== {v}: số hàm mỗi fold theo ngôn ngữ ===\n{t.to_string()}")
    print(f"--- tỷ lệ nhãn dương mỗi fold ---\n{p.round(2).to_string()}")
