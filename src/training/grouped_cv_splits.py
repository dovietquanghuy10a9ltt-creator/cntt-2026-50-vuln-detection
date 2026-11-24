"""
Chọn dữ liệu cho Grouped 5-fold CV (v1). Chỉ dùng pandas, không cần GPU.

Đầu vào:
  clean  : DataFrame từ MVDDatasetLoader().clean_exact_hash() (18.694 đơn vị) có cột unit_id, func, language, target.
  folds  : groups_and_folds_v1.csv (cột unit_id, group, is_giant, fold, inner_val_fold0..4).

Quy tắc (mọi phép chia đều theo CỤM `group` = thành phần liên thông của CVE, xuyên ngôn ngữ):
  mono(L, k)  : test = đơn vị của L ở fold k; val = đơn vị của L ở cụm có cờ inner_val_fold{k};
                train = đơn vị của L ở fold != k và không phải val.
  multi(k)    : như mono nhưng gộp cả 7 ngôn ngữ.
  lolo(T)     : test = TOÀN BỘ đơn vị của ngôn ngữ T (không cần chia). Nguồn = 6 ngôn ngữ còn lại,
                bỏ mọi đơn vị nguồn cùng cụm với một đơn vị của T (khử nhiễm theo CVE);
                val = đơn vị nguồn có cờ inner_val_fold0 (các cụm ngoài fold 0, ~9%); train = phần còn lại.
Mọi hàm đều kiểm tra: không cụm nào xuất hiện ở hai tập khác nhau.
"""
from __future__ import annotations

import pandas as pd

LANGUAGES = ["C", "C#", "C++", "Go", "Java", "JavaScript", "Python"]
N_FOLDS = 5


def attach_folds(clean: pd.DataFrame, folds: pd.DataFrame) -> pd.DataFrame:
    need_clean = {"unit_id", "func", "language", "target"}
    need_folds = {"unit_id", "group", "is_giant", "fold"} | {f"inner_val_fold{k}" for k in range(N_FOLDS)}
    if need_clean - set(clean.columns):
        raise ValueError(f"clean thiếu cột: {sorted(need_clean - set(clean.columns))}")
    if need_folds - set(folds.columns):
        raise ValueError(f"folds thiếu cột: {sorted(need_folds - set(folds.columns))}")
    if clean["unit_id"].duplicated().any() or folds["unit_id"].duplicated().any():
        raise ValueError("unit_id bị trùng")
    cols = ["unit_id", "group", "is_giant", "fold"] + [f"inner_val_fold{k}" for k in range(N_FOLDS)]
    df = clean.merge(folds[cols], on="unit_id", how="inner", validate="one_to_one")
    if len(df) != len(clean) or len(df) != len(folds):
        raise ValueError(f"unit_id không khớp: clean={len(clean)}, folds={len(folds)}, merged={len(df)}")
    # nhãn và ngôn ngữ trong file fold phải khớp với dữ liệu sạch
    chk = folds.set_index("unit_id")
    for col in ("language", "target"):
        if col in chk.columns:
            a = df.set_index("unit_id")[col]
            b = chk[col].reindex(a.index)
            if not (a.astype(str) == b.astype(str)).all():
                raise ValueError(f"cột {col} lệch giữa clean và folds")
    for k in range(N_FOLDS):
        df[f"inner_val_fold{k}"] = df[f"inner_val_fold{k}"].astype(bool)
    df["is_giant"] = df["is_giant"].astype(bool)
    return df.reset_index(drop=True)


def _assert_disjoint_groups(**parts: pd.DataFrame) -> None:
    names = list(parts)
    groups = {n: set(parts[n]["group"]) for n in names}
    units = {n: set(parts[n]["unit_id"]) for n in names}
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            inter = groups[a] & groups[b]
            if inter:
                raise AssertionError(f"RÒ RỈ: {len(inter)} cụm xuất hiện ở cả {a} và {b}")
            if units[a] & units[b]:
                raise AssertionError(f"RÒ RỈ: unit_id xuất hiện ở cả {a} và {b}")


def split_mono(df: pd.DataFrame, language: str, k: int):
    d = df[df["language"] == language]
    val_flag = d[f"inner_val_fold{k}"]
    test = d[d["fold"] == k]
    val = d[(d["fold"] != k) & val_flag]
    train = d[(d["fold"] != k) & ~val_flag]
    _assert_disjoint_groups(train=train, val=val, test=test)
    return train.copy(), val.copy(), test.copy()


def split_multi(df: pd.DataFrame, k: int):
    val_flag = df[f"inner_val_fold{k}"]
    test = df[df["fold"] == k]
    val = df[(df["fold"] != k) & val_flag]
    train = df[(df["fold"] != k) & ~val_flag]
    _assert_disjoint_groups(train=train, val=val, test=test)
    return train.copy(), val.copy(), test.copy()


def split_lolo(df: pd.DataFrame, target_language: str):
    tgt = df[df["language"] == target_language]
    src = df[df["language"] != target_language]
    contaminated = src["group"].isin(set(tgt["group"]))
    n_removed = int(contaminated.sum())
    src = src[~contaminated]
    val_flag = src["inner_val_fold0"]
    val = src[val_flag]
    train = src[~val_flag]
    _assert_disjoint_groups(train=train, val=val, test=tgt)
    assert (train["language"] != target_language).all() and (val["language"] != target_language).all()
    return train.copy(), val.copy(), tgt.copy(), n_removed


def build_jobs(df: pd.DataFrame, modes=("mono", "multi", "lolo"), languages=None, folds=None):
    """Danh sách job (mode, key, fold) theo thứ tự chạy: multi/mono theo fold rồi ngôn ngữ, lolo theo ngôn ngữ."""
    languages = list(languages or LANGUAGES)
    folds = list(range(N_FOLDS)) if folds is None else list(folds)
    jobs = []
    if "mono" in modes:
        for k in folds:
            for lang in languages:
                jobs.append(("mono", lang, k))
    if "multi" in modes:
        for k in folds:
            jobs.append(("multi", "ALL", k))
    if "lolo" in modes:
        for lang in languages:
            jobs.append(("lolo", lang, -1))
    return jobs


def select_jobs(all_jobs, specs):
    """Chọn job theo danh sách chuỗi 'mode:key:fold' (vd 'mono:C#:0', 'multi:ALL:2', 'lolo:Java:-1'), giữ thứ tự đã cho."""
    index = {(m, key, k) for m, key, k in all_jobs}
    out = []
    for s in specs:
        parts = s.split(":")
        if len(parts) != 3:
            raise ValueError(f"job sai định dạng (cần mode:key:fold): {s!r}")
        job = (parts[0], parts[1], int(parts[2]))
        if job not in index:
            raise ValueError(f"job không tồn tại: {s!r}")
        if job in out:
            raise ValueError(f"job bị lặp: {s!r}")
        out.append(job)
    return out


def get_split(df: pd.DataFrame, mode: str, key: str, k: int):
    if mode == "mono":
        return (*split_mono(df, key, k), 0)
    if mode == "multi":
        return (*split_multi(df, k), 0)
    if mode == "lolo":
        return split_lolo(df, key)
    raise ValueError(mode)


def plan_table(df: pd.DataFrame, epochs: int = 5, jobs=None) -> pd.DataFrame:
    rows = []
    for mode, key, k in (jobs or build_jobs(df)):
        tr, va, te, removed = get_split(df, mode, key, k)
        rows.append(dict(mode=mode, key=key, fold=k, n_train=len(tr), n_val=len(va), n_test=len(te),
                         pos_train=float(tr["target"].mean()), removed_for_decontamination=removed,
                         sample_passes=len(tr) * epochs))
    return pd.DataFrame(rows)
