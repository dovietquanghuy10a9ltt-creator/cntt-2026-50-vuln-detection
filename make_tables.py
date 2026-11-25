"""In lại các bảng kết quả chính của báo cáo từ các file CSV trong results/ (không cần GPU, chạy vài giây).

Dùng:  python make_tables.py            # in mọi bảng
       python make_tables.py cvefixes   # chỉ in các bảng có tên chứa "cvefixes"

Mỗi bảng ghi rõ file nguồn. Số liệu là AUROC (hoặc hiệu AUROC) macro 6 ngôn ngữ, kèm khoảng tin cậy 95%
bootstrap theo cụm CVE (B = 1.000). Muốn tính lại chính các file CSV này từ file dự đoán, xem mục
"Tái lập phân tích" trong README.
"""
import sys
from pathlib import Path

import pandas as pd

R = Path(__file__).resolve().parent / "results"
STATS = ["mono", "multi", "lolo", "lolo-mono", "multi-mono", "lolo-multi"]
NAME = {"mono": "Mono", "multi": "Multi", "lolo": "LOLO", "lolo-mono": "LOLO − Mono",
        "multi-mono": "Multi − Mono", "lolo-multi": "LOLO − Multi"}


def fmt(x, diff=False):
    s = f"{x:+.3f}" if diff else f"{x:.3f}"
    return s.replace("-", "−")


def row(name, est, lo, hi, verdict="", diff=False):
    v = f"  {verdict}" if isinstance(verdict, str) and verdict else ""
    return f"  {name:<32s} {fmt(est, diff)}  ({fmt(lo, diff)} đến {fmt(hi, diff)}){v}"


def show(title, path, lines):
    print(f"\n=== {title}\n    nguồn: {path.relative_to(R.parent)}")
    for ln in lines:
        print(ln)


def grouped(title, f, prefix=""):
    d = pd.read_csv(f)
    d = d[d.language == "macro6"].set_index("stat")
    out = []
    for s in STATS:
        k = prefix + s
        if k in d.index:
            r = d.loc[k]
            out.append(row(NAME[s], r.estimate, r.ci_low, r.ci_high, r.get("verdict", ""), "-" in s))
    show(title, f, out)


def leak(f):
    d = pd.read_csv(f)
    d = d[d.language == "macro6"].set_index("stat")
    name = {"mono_G": "Mono, chia theo CVE", "mono_R": "Mono, chia ngẫu nhiên", "mono_R-G": "Mono: ngẫu nhiên − CVE",
            "multi_G": "Multi, chia theo CVE", "multi_R": "Multi, chia ngẫu nhiên", "multi_R-G": "Multi: ngẫu nhiên − CVE"}
    show("MVD v1, seed 17: chia ngẫu nhiên theo hàm so với chia theo CVE (bổ sung lần 1)", f,
         [row(name[k], d.loc[k].estimate, d.loc[k].ci_low, d.loc[k].ci_high, diff="R-G" in k) for k in name if k in d.index])


def twin(f):
    d = pd.read_csv(f)
    lines = []
    for (m, p), g in d.groupby(["mode", "pairs"], sort=False):
        lines.append(f"  [{m}, {p}]")
        lines += [row(r.stat, r.est, r.lo, r.hi, r.verdict, "−" in r.stat) for _, r in g.iterrows()]
    show("Thí nghiệm cặp sinh đôi (bổ sung lần 3): AUROC trong cặp (bản lỗi có điểm cao hơn bản sửa)", f, lines)


def blind(f):
    d = pd.read_csv(f)
    lines = []
    for (m, p), g in d.groupby(["mode", "pairs"], sort=False):
        lines.append(f"  [{m}, {p}]")
        lines += [row(r.stat, r.est, r.lo, r.hi, r.verdict, "−" in r.stat and "AUROC cặp" not in r.stat) for _, r in g.iterrows()]
    show("Thí nghiệm RS-blind (bổ sung lần 7): tách cơ chế cặp sinh đôi", f, lines)


def cvf_seeds(f):
    d = pd.read_csv(f)
    d = d[(d.tap == "chính, macro 6") & (d.seed == "mean")].set_index("stat")
    show("CVEfixes, 10 epoch, trung bình ba seed 17, 29, 43 (bổ sung lần 4 và 5)", f,
         [row(NAME[s.replace("−", "-")], d.loc[s].estimate, d.loc[s].ci_low, d.loc[s].ci_high, d.loc[s].verdict, "−" in s)
          for s in ["mono", "multi", "lolo", "lolo−mono", "multi−mono", "lolo−multi"] if s in d.index])


def codebert(f, ds):
    d = pd.read_csv(f)
    d = d[(d.tap == "chính, macro 6") & (d.language == "macro") & ~d.stat.str.startswith("UniXcoder")]
    show(f"CodeBERT trên {ds}, 10 epoch, seed 17 (bổ sung lần 6); so sánh ghép cặp với UniXcoder seed 17", f,
         [row(r.stat, r.estimate, r.ci_low, r.ci_high, r.verdict, "−" in r.stat or "Hiệu" in r.stat) for _, r in d.iterrows()])


def effort(f, ds):
    d = pd.read_csv(f)
    d = d[d.stat.isin(["recall", "phu_cve", "phu_cve_ngau_nhien"]) & (d["k"] == 20)]
    show(f"Thăm dò, {ds}: đọc 20% hàm điểm cao nhất (recall và phủ CVE, macro 6 ngôn ngữ)", f,
         [row(f"{r['mode']} {r.stat}", r.estimate, r.ci_low, r.ci_high) for _, r in d.iterrows()])


TABLES = [
    ("mvd_v1 seed17", lambda: grouped("MVD v1, 5 epoch, seed 17 (đăng ký chính)", R / "01_mvd_v1_seed17/grouped_cv_auroc_main.csv")),
    ("mvd_v1 seed29", lambda: grouped("MVD v1, 5 epoch, seed 29", R / "02_mvd_v1_seed29/s29_main.csv")),
    ("mvd_v1 seed43", lambda: grouped("MVD v1, 5 epoch, seed 43", R / "03_mvd_v1_seed43/seed43_auroc_main.csv")),
    ("mvd_v1 random", lambda: leak(R / "04_mvd_v1_chia_ngau_nhien/leak_main.csv")),
    ("mvd_v2 5epoch", lambda: grouped("MVD v2 (dữ liệu sạch), 5 epoch, seed 17 (bổ sung lần 2)", R / "05_mvd_v2_5epoch/v2e5_main.csv")),
    ("mvd_v2 10epoch", lambda: grouped("MVD v2 (dữ liệu sạch), 10 epoch, seed 17 (bổ sung lần 2)", R / "06_mvd_v2_10epoch/v2e10_main.csv")),
    ("twin", lambda: twin(R / "07_cap_sinh_doi/twin_results.csv")),
    ("twin rs_blind", lambda: blind(R / "12_rs_blind/twin_blind_results.csv")),
    ("cvefixes seed17", lambda: grouped("CVEfixes, 10 epoch, seed 17 (bổ sung lần 4)", R / "08_cvefixes_seed17/cvf_main.csv")),
    ("cvefixes 3seed", lambda: cvf_seeds(R / "09_cvefixes_ba_seed/cvf_seeds_all.csv")),
    ("codebert mvd", lambda: codebert(R / "10_codebert/cb_mvd_all.csv", "MVD v2")),
    ("codebert cvefixes", lambda: codebert(R / "10_codebert/cb_cvf_all.csv", "CVEfixes")),
    ("thamdo mvd", lambda: effort(R / "11_tham_do/effort_mvd.csv", "MVD v2")),
    ("thamdo cvefixes", lambda: effort(R / "11_tham_do/effort_cvf.csv", "CVEfixes")),
]

if __name__ == "__main__":
    key = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    for name, fn in TABLES:
        if key in name:
            fn()
