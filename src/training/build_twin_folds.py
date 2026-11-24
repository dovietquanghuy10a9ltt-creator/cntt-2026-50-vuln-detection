"""Tạo twin_folds_v1.csv cho thí nghiệm can thiệp "cặp sinh đôi" (bản bổ sung lần 3).

Cặp sinh đôi = một khối (ngôn ngữ, cụm CVE) có đúng 2 hàm và mang cả hai nhãn (thường là phiên bản trước và sau
một commit sửa lỗi). Xuất phát từ random_folds_v1.csv (cách chia ngẫu nhiên theo hàm của bản bổ sung lần 1) và chỉ
thay đổi tối thiểu:
  1. Với mỗi cặp, chọn ngẫu nhiên một hàm làm "neo" (xác suất 1/2 mỗi hàm).
  2. Nếu hai hàm đang ở hai fold khác nhau: chuyển hàm còn lại sang fold của hàm neo.
  3. Hàm còn lại nhận nguyên các cờ inner_val_fold0..4 của hàm neo (để hai hàm luôn cùng train hoặc cùng validation).
  4. Cột group của hai hàm = "twin:<ngôn ngữ>:<cụm>" để mã huấn luyện tự kiểm tra không cặp nào bị tách.
Mọi hàm khác giữ nguyên fold, cờ validation và group như random_folds_v1.csv.

Dùng: python build_twin_folds.py random_folds_v1.csv groups_and_folds_v1.csv twin_folds_v1.csv
"""
import hashlib, sys
import numpy as np, pandas as pd

SEED = 20261115
K = 5
FLAGS = [f"inner_val_fold{k}" for k in range(K)]


def twin_pairs(v1: pd.DataFrame) -> pd.DataFrame:
    g = v1.groupby(["language", "group"])
    blk = g.agg(n=("unit_id", "size"), nt=("target", "nunique")).reset_index()
    blk = blk[(blk.n == 2) & (blk.nt == 2)].sort_values(["language", "group"]).reset_index(drop=True)
    d = v1.merge(blk[["language", "group"]], on=["language", "group"])
    pos = d[d.target == 1].set_index(["language", "group"]).unit_id.rename("u_pos")
    neg = d[d.target == 0].set_index(["language", "group"]).unit_id.rename("u_neg")
    return blk[["language", "group"]].join(pos, on=["language", "group"]).join(neg, on=["language", "group"])


def canonical_hash(df: pd.DataFrame) -> str:
    d = df.sort_values("unit_id")
    lines = (d.unit_id + "," + d.fold.astype(str) + "," +
             d[FLAGS].astype(int).astype(str).agg("".join, axis=1) + "," + d.group.astype(str))
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def build(rf: pd.DataFrame, v1: pd.DataFrame):
    assert len(rf) == len(v1) == 18694 and set(rf.unit_id) == set(v1.unit_id)
    tw = twin_pairs(v1)
    rng = np.random.default_rng(SEED)
    out = rf.set_index("unit_id").copy()
    out["twin_moved"] = False
    moved, logs = 0, []
    for r in tw.itertuples():
        anchor, other = (r.u_pos, r.u_neg) if rng.random() < 0.5 else (r.u_neg, r.u_pos)
        split_before = out.at[r.u_pos, "fold"] != out.at[r.u_neg, "fold"]
        if split_before:
            out.at[other, "fold"] = out.at[anchor, "fold"]; out.at[other, "twin_moved"] = True; moved += 1
        for c in FLAGS:
            out.at[other, c] = out.at[anchor, c]
        gid = f"twin:{r.language}:{r.group}"
        out.at[r.u_pos, "group"] = gid; out.at[r.u_neg, "group"] = gid
        logs.append(dict(language=r.language, cve_group=r.group, u_pos=r.u_pos, u_neg=r.u_neg,
                         split_in_random=bool(split_before), fold=int(out.at[anchor, "fold"])))
    out = out.reset_index()
    # kiểm tra
    t = out[out.group.str.startswith("twin:")]
    assert t.groupby("group").fold.nunique().eq(1).all()
    for c in FLAGS:
        assert t.groupby("group")[c].nunique().eq(1).all()
    for k in range(K):
        assert not out.loc[out.fold == k, f"inner_val_fold{k}"].any()
    same = out.set_index("unit_id").drop(columns="twin_moved")
    base = rf.set_index("unit_id")
    nontwin = ~same.group.str.startswith("twin:")
    assert (same.loc[nontwin, ["fold"] + FLAGS] == base.loc[nontwin, ["fold"] + FLAGS]).all().all()
    return out.drop(columns="twin_moved"), pd.DataFrame(logs), moved


if __name__ == "__main__":
    rf = pd.read_csv(sys.argv[1]); v1 = pd.read_csv(sys.argv[2])
    out, logs, moved = build(rf, v1)
    out.to_csv(sys.argv[3], index=False)
    logs.to_csv(sys.argv[3].replace(".csv", "_pairs.csv"), index=False)
    print("cặp sinh đôi:", len(logs), "| bị tách trong random_folds_v1:", int(logs.split_in_random.sum()),
          "| đã chuyển:", moved)
    print("số hàm mỗi fold:", out.fold.value_counts().sort_index().to_dict())
    print("số hàm validation mỗi fold:", {k: int(out[f'inner_val_fold{k}'].sum()) for k in range(K)})
    print("mã băm chuẩn:", canonical_hash(out))
