"""Hằng số và hàm dùng chung cho các script dựng CVEfixes v2 (đề tài CNTT-2026-50).

Mọi script đều chạy được bằng:  .venv\\Scripts\\python.exe -I scripts\\NN_ten.py
"""
from __future__ import annotations
import hashlib
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
WORK = SCRIPTS.parent                      # cvefixes_work/
ROOT = WORK.parent                         # thư mục gói (chứa clean_rules.py, build_folds.py)
DOWNLOAD = WORK / "download"               # file tải về (dữ liệu không tin cậy, để riêng)
DB_DIR = WORK / "db"                       # cơ sở dữ liệu SQLite dựng lại từ bản dump

ZENODO_RECORD = "13118970"
SAMPLE_SEED = 20261115                     # seed duy nhất cho mọi lần lấy mẫu kiểm tra (mục 2.3)
LANGS = ["C", "C++", "C#", "Go", "Java", "JavaScript", "Python"]

EXPECTED_SHA256 = {
    "clean_rules.py": "63f034b1e79b25c918c41daf0c5634e612a78db86def11aeb5935c27ed87d836",
    "build_folds.py": "65704ec488cc670bfd64ec3fed9858b9bfcbdbe3dd5fd28a6fa98d0667054827",
    "mvd_reference.csv": "35900fcd69b30167d56a084fc51bc3bff37dba590394a219dccaabedbd29730d",
}


def file_hash(path: Path, algo: str = "sha256", chunk: int = 8 << 20) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def check_package_hashes() -> dict:
    """Mục 13: clean_rules.py và build_folds.py (và mvd_reference.csv) phải đúng SHA-256 ở mục 1."""
    got = {}
    for name, want in EXPECTED_SHA256.items():
        got[name] = file_hash(ROOT / name)
        assert got[name] == want, f"SHA-256 của {name} không khớp: {got[name]} != {want}"
    return got


def import_package_modules():
    """Import nguyên bản clean_rules và build_folds từ thư mục gói (không sửa, không sao chép)."""
    check_package_hashes()
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import clean_rules as CR  # noqa: E402
    import build_folds as BF  # noqa: E402
    return CR, BF


def md_table(df) -> str:
    """Bảng Markdown từ DataFrame (giữ nguyên thứ tự cột, chỉ số bị bỏ: hãy reset_index trước nếu cần)."""
    cols = [str(c) for c in df.columns]
    out = ["| " + " | ".join(cols) + " |", "|" + "|".join(["---"] * len(cols)) + "|"]
    for row in df.itertuples(index=False):
        cells = []
        for v in row:
            if v is None or (isinstance(v, float) and v != v):
                cells.append("")
            elif isinstance(v, float):
                cells.append(f"{v:,.4g}" if abs(v) < 1 else f"{v:,.1f}")
            elif isinstance(v, (int,)) and not isinstance(v, bool):
                cells.append(f"{v:,}")
            else:
                cells.append(str(v).replace("|", "\\|").replace("\n", " ⏎ "))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def count_dict(df, lang: str = "language", target: str = "target") -> dict:
    """{ngôn ngữ: {"1": số dòng target=1, "0": số dòng target=0}} cho 7 ngôn ngữ."""
    g = df.groupby([lang, target]).size()
    return {l: {"1": int(g.get((l, 1), 0)), "0": int(g.get((l, 0), 0))} for l in LANGS}


def counts_table(df, lang: str = "language", target: str = "target"):
    """Bảng số dòng theo ngôn ngữ và nhãn (kèm dòng Tổng), dạng DataFrame để in hoặc md_table."""
    import pandas as pd
    rows = []
    for l, d in count_dict(df, lang, target).items():
        rows.append({"ngôn ngữ": l, "target=1": d["1"], "target=0": d["0"], "tổng": d["1"] + d["0"]})
    t = pd.DataFrame(rows)
    tot = t.drop(columns="ngôn ngữ").sum()
    tot["ngôn ngữ"] = "Tổng"
    return pd.concat([t, tot.to_frame().T], ignore_index=True)


def split_label_check(folds, n_folds: int = 5):
    """Mỗi ngôn ngữ trong mỗi fold phải còn đủ hai nhãn ở train, validation (inner_val) và test.
    Trả về (bảng đếm, danh sách thiếu)."""
    import pandas as pd
    rows, missing = [], []
    for k in range(n_folds):
        test = folds.fold == k
        val = folds[f"inner_val_fold{k}"].astype(bool)
        train = ~test & ~val
        for part, m in (("train", train), ("val", val), ("test", test)):
            sub = folds[m]
            for l in LANGS:
                s = sub[sub.language == l]
                n1, n0 = int((s.target == 1).sum()), int((s.target == 0).sum())
                rows.append({"fold": k, "phần": part, "ngôn ngữ": l, "target=1": n1, "target=0": n0})
                if n1 == 0 or n0 == 0:
                    missing.append(f"fold {k}, {part}, {l}: target=1 {n1}, target=0 {n0}")
    return pd.DataFrame(rows), missing


def utf8_stdout():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
