"""Tạo random_folds_v1.csv: chia 5 fold NGẪU NHIÊN theo hàm (bỏ qua CVE), phân tầng ngôn ngữ x nhãn.
Cùng 18.694 đơn vị với groups_and_folds_v1.csv. Cột `group` = unit_id (mỗi đơn vị một nhóm) để mã huấn luyện
đã đăng ký chạy nguyên vẹn; cụm CVE thật chỉ dùng lại ở bước phân tích."""
import sys, numpy as np, pandas as pd
SEED = 20261113
src = pd.read_csv(sys.argv[1])
rng = np.random.default_rng(SEED)
out = src[["unit_id", "language", "target"]].copy()
out["group"] = out["unit_id"]; out["is_giant"] = False
out["fold"] = -1
for _, idx in out.groupby(["language", "target"], sort=True).groups.items():
    idx = rng.permutation(np.asarray(sorted(idx)))
    out.loc[idx, "fold"] = np.arange(len(idx)) % 5
for k in range(5):
    flag = pd.Series(False, index=out.index)
    rest = out[out["fold"] != k]
    for _, idx in rest.groupby(["language", "target"], sort=True).groups.items():
        idx = rng.permutation(np.asarray(sorted(idx)))
        flag.loc[idx[np.arange(len(idx)) % 10 == 9]] = True
    out[f"inner_val_fold{k}"] = flag
out.to_csv(sys.argv[2], index=False)
