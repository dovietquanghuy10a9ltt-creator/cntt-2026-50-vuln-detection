"""Bước 3: khảo sát cấu trúc cơ sở dữ liệu CVEfixes, ghi schema.md.

Không đọc nguyên bảng lớn vào bộ nhớ: bảng file_change (chứa mã nguồn cả file) chỉ được quét MỘT lần,
lấy các cột nhỏ và ghi ra intermediate/file_change_slim.parquet để các bước sau nối bảng mà không phải
quét lại hàng chục GB. Các phép đếm trên method_change làm ngay trong SQL.
"""
from __future__ import annotations
import json
import random
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import pandas as pd  # noqa: E402

DB = C.DB_DIR / "CVEfixes.db"
INTER = C.WORK / "intermediate"
BIG_COLS = {"diff", "diff_parsed", "code_after", "code_before"}       # cột lớn của file_change, không đọc hàng loạt
EXPECTED = {   # mô tả ở mục 5 của đặc tả
    "fixes": ["cve_id", "hash", "repo_url"],
    "commits": ["hash", "repo_url"],
    "file_change": ["file_change_id", "hash", "filename", "old_path", "new_path", "programming_language"],
    "method_change": ["method_change_id", "file_change_id", "name", "signature", "code", "before_change"],
    "cwe_classification": ["cve_id", "cwe_id"],
}
EXT = {
    "C": {".c", ".h"}, "C++": {".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".h", ".inl", ".ipp", ".tcc"},
    "C#": {".cs"}, "Go": {".go"}, "Java": {".java"}, "JavaScript": {".js", ".jsx", ".mjs", ".cjs"}, "Python": {".py", ".pyw"},
}


def md_table(df: pd.DataFrame) -> str:
    cols = [str(c) for c in df.columns]
    out = ["| " + " | ".join(cols) + " |", "|" + "|".join(["---"] * len(cols)) + "|"]
    for row in df.itertuples(index=False):
        out.append("| " + " | ".join("" if v is None else str(v).replace("|", "\\|").replace("\n", "⏎") for v in row) + " |")
    return "\n".join(out)


def q(con, sql, params=()):
    return pd.read_sql_query(sql, con, params=params)


def main():
    C.check_package_hashes()
    assert DB.exists(), "Chưa có db/CVEfixes.db; chạy 03_build_db.py trước"
    INTER.mkdir(exist_ok=True)
    con = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)
    L = []
    w = L.append
    build = json.loads((C.DB_DIR / "build_info.json").read_text(encoding="utf-8"))

    w("# Cấu trúc cơ sở dữ liệu CVEfixes v1.0.8\n")
    w(f"- File: `cvefixes_work/{build['db_path']}`, {build['db_size_bytes']:,} byte ({build['db_size_bytes'] / 2**30:.2f} GiB), "
      f"dựng từ `{build['dump_entry']}` ({build['n_statements']:,} câu lệnh SQL, {build['dump_sql_bytes'] / 2**30:.2f} GiB văn bản SQL).")
    w(f"- Số câu lệnh có byte không phải UTF-8 hợp lệ (đã thay bằng U+FFFD): {build['n_statements_invalid_utf8']:,}.\n")

    # ---- 1. bảng, cột, số dòng
    objs = q(con, "SELECT type, name, tbl_name FROM sqlite_master ORDER BY type, name")
    tables = objs[objs.type == "table"].name.tolist()
    w("## 1. Các bảng\n")
    cols_by_table, rows = {}, []
    for t in tables:
        info = q(con, f'PRAGMA table_info("{t}")')
        cols_by_table[t] = info.name.tolist()
        n = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        rows.append({"bảng": t, "số dòng": f"{n:,}", "số cột": len(info)})
        print(f"{t}: {n:,} dòng, {len(info)} cột", flush=True)
    w(md_table(pd.DataFrame(rows)) + "\n")
    idx = objs[objs.type != "table"]
    w("Chỉ mục / view / trigger: " + ("không có." if idx.empty else ", ".join(f"{r.type} `{r.name}` trên `{r.tbl_name}`" for r in idx.itertuples())) + "\n")
    for t in tables:
        info = q(con, f'PRAGMA table_info("{t}")')[["cid", "name", "type", "notnull", "pk"]]
        w(f"### `{t}`\n")
        w(md_table(info.rename(columns={"cid": "#", "name": "cột", "type": "kiểu khai báo", "notnull": "NOT NULL", "pk": "khóa chính"})) + "\n")

    # ---- 2. so với mô tả ở mục 5
    w("## 2. So với mô tả ở mục 5 của đặc tả\n")
    diffs = []
    for t, need in EXPECTED.items():
        if t not in cols_by_table:
            diffs.append(f"- **Thiếu bảng `{t}`.**")
            continue
        miss = [c for c in need if c not in cols_by_table[t]]
        if miss:
            diffs.append(f"- Bảng `{t}` thiếu cột: {', '.join(miss)}.")
    extra = [t for t in tables if t not in EXPECTED]
    w("\n".join(diffs) if diffs else "Mọi bảng và cột nêu ở mục 5 đều có, đúng tên.")
    w(f"\nBảng có thêm ngoài mục 5: {', '.join('`' + t + '`' for t in extra) or 'không'}.\n")
    assert not diffs, "Cấu trúc khác mô tả ở mục 5 (mục 2.4 của đặc tả): " + " ".join(diffs)

    # ---- 3. file_change: quét một lần, bỏ cột lớn
    slim_cols = [c for c in cols_by_table["file_change"] if c not in BIG_COLS]
    print("Quét file_change (một lần, bỏ cột lớn) ...", flush=True)
    parts = []
    sel = ", ".join(f'"{c}"' for c in slim_cols)
    for ch in pd.read_sql_query(f"SELECT rowid AS fc_rowid, {sel} FROM file_change", con, chunksize=20000):
        parts.append(ch)
    fc = pd.concat(parts, ignore_index=True)
    fc.to_parquet(INTER / "file_change_slim.parquet", index=False)
    print(f"  file_change_slim: {len(fc):,} dòng", flush=True)

    fixes = q(con, "SELECT cve_id, hash, repo_url FROM fixes")
    commits = q(con, "SELECT hash, repo_url FROM commits")
    cwec = q(con, "SELECT cve_id, cwe_id FROM cwe_classification")

    # ---- 4. before_change
    w("## 3. Giá trị của `method_change.before_change`\n")
    bc = q(con, "SELECT before_change AS giá_trị, typeof(before_change) AS kiểu_lưu, COUNT(*) AS số_dòng FROM method_change GROUP BY 1, 2 ORDER BY 3 DESC")
    w(md_table(bc) + "\n")
    print(bc.to_string(index=False), flush=True)

    # ---- 5. khóa nối
    w("## 4. Khóa nối giữa các bảng\n")
    kt = q(con, "SELECT typeof(file_change_id) AS kiểu, COUNT(*) AS n, COUNT(DISTINCT file_change_id) AS n_khác_nhau FROM method_change GROUP BY 1")
    w("`method_change.file_change_id`:\n\n" + md_table(kt) + "\n")
    w(f"`file_change.file_change_id`: kiểu pandas `{fc.file_change_id.dtype}`, {len(fc):,} dòng, {fc.file_change_id.nunique():,} giá trị khác nhau "
      f"({'duy nhất' if fc.file_change_id.is_unique else 'CÓ TRÙNG'}).\n")
    mm = q(con, "SELECT COUNT(*) AS n, COUNT(DISTINCT method_change_id) AS n_id FROM method_change")
    w(f"`method_change.method_change_id`: {int(mm.n[0]):,} dòng, {int(mm.n_id[0]):,} giá trị khác nhau.\n")
    mfc = q(con, "SELECT file_change_id, before_change, COUNT(*) AS n FROM method_change GROUP BY 1, 2")
    fc_ids = set(fc.file_change_id.astype(str))
    orphan = mfc[~mfc.file_change_id.astype(str).isin(fc_ids)]
    w(f"- Dòng `method_change` không tìm thấy `file_change_id` trong `file_change`: {int(orphan.n.sum()):,} / {int(mfc.n.sum()):,}.")
    fx_hash, cm_hash, fc_hash = set(fixes.hash), set(commits.hash), set(fc.hash)
    w(f"- `fixes`: {len(fixes):,} dòng; {fixes.drop_duplicates().shape[0]:,} bộ (cve_id, hash, repo_url) khác nhau; {fixes.cve_id.nunique():,} CVE; {fixes.hash.nunique():,} hash; {fixes.repo_url.nunique():,} repo.")
    per_hash = fixes.drop_duplicates(["hash", "repo_url"]).groupby("hash").repo_url.nunique()
    w(f"- Hash trong `fixes` xuất hiện ở **nhiều hơn một `repo_url`**: {(per_hash > 1).sum():,} hash (tối đa {int(per_hash.max())} repo cho một hash).")
    cve_per_hash = fixes.drop_duplicates(["hash", "cve_id"]).groupby("hash").cve_id.nunique()
    w(f"- Hash gắn với nhiều hơn một CVE: {(cve_per_hash > 1).sum():,} (tối đa {int(cve_per_hash.max())} CVE cho một hash).")
    w(f"- `commits`: {len(commits):,} dòng; {commits.hash.nunique():,} hash khác nhau; {commits.drop_duplicates().shape[0]:,} cặp (hash, repo_url) khác nhau.")
    w(f"- `file_change`: {len(fc):,} dòng; {fc.hash.nunique():,} hash khác nhau; hash không có trong `commits`: {len(fc_hash - cm_hash):,}; hash không có trong `fixes`: {len(fc_hash - fx_hash):,}.")
    w(f"- `file_change` {'CÓ' if 'repo_url' in fc.columns else '**không có**'} cột `repo_url`"
      + ("." if "repo_url" in fc.columns else ", nên từ `file_change` chỉ nối được sang `fixes`/`commits` theo `hash`.") )
    w(f"- Hash trong `fixes` không có `file_change` nào: {len(fx_hash - fc_hash):,} / {len(fx_hash):,}.")
    ncwe = cwec.groupby("cve_id").cwe_id.nunique()
    w(f"- `cwe_classification`: {len(cwec):,} dòng; {cwec.cve_id.nunique():,} CVE; CVE có nhiều hơn một CWE: {(ncwe > 1).sum():,}; CVE của `fixes` không có dòng CWE: {len(set(fixes.cve_id) - set(cwec.cve_id)):,}.")
    top_cwe = cwec.cwe_id.value_counts().head(8)
    w("- Giá trị `cwe_id` hay gặp: " + ", ".join(f"`{k}` ({v:,})" for k, v in top_cwe.items()) + ".\n")

    # ---- 6. ngôn ngữ
    w("## 5. Ngôn ngữ (`file_change.programming_language`)\n")
    fc["_fcid"] = fc.file_change_id.astype(str)
    mfc["_fcid"] = mfc.file_change_id.astype(str)
    m = mfc.merge(fc[["_fcid", "programming_language"]], on="_fcid", how="left")
    piv = m.pivot_table(index="programming_language", columns="before_change", values="n", aggfunc="sum", fill_value=0, dropna=False)
    piv.columns = [f"hàm before_change={c}" for c in piv.columns]
    files = fc.programming_language.value_counts(dropna=False).rename("số file_change")
    lang = pd.concat([files, piv], axis=1).fillna(0).astype(int).sort_values("số file_change", ascending=False)
    lang.insert(0, "giữ (7 ngôn ngữ MVD)", ["có" if i in C.LANGS else "" for i in lang.index])
    lang = lang.reset_index().rename(columns={"index": "programming_language"})
    lang["programming_language"] = lang["programming_language"].map(lambda v: "(NULL)" if pd.isna(v) else repr(v) if v == "" else v)
    w(md_table(lang) + "\n")
    print(lang.to_string(index=False), flush=True)

    w("### Đối chiếu với đuôi file (7 ngôn ngữ được giữ)\n")
    path = fc.new_path.where(~fc.new_path.isin(["None", ""]) & fc.new_path.notna(), fc.old_path)
    path = path.where(~path.isin(["None", ""]) & path.notna(), fc.filename)
    fc["_ext"] = path.astype(str).str.extract(r"(\.[A-Za-z0-9_+]+)$", expand=False).str.lower().fillna("(không đuôi)")
    rows = []
    for lg in C.LANGS:
        s = fc[fc.programming_language == lg]
        vc = s._ext.value_counts()
        bad = vc[~vc.index.isin(EXT[lg])]
        rows.append({"ngôn ngữ": lg, "số file_change": f"{len(s):,}", "đuôi file (số file)": ", ".join(f"{k} ({v:,})" for k, v in vc.items()),
                     "file có đuôi không khớp": f"{int(bad.sum()):,}"})
    w(md_table(pd.DataFrame(rows)) + "\n")
    other = fc[~fc.programming_language.isin(C.LANGS)]
    hit = {lg: int(other._ext.isin(EXT[lg] - ({".h"} if lg == "C++" else set())).sum()) for lg in C.LANGS}
    w("File **không** được gán một trong 7 ngôn ngữ nhưng có đuôi của ngôn ngữ đó: " + ", ".join(f"{k}: {v:,}" for k, v in hit.items()) + ".\n")

    # ---- 7. đường dẫn và loại thay đổi
    w("## 6. Đường dẫn và loại thay đổi trong `file_change`\n")
    def empties(col):
        s = fc[col]
        return f"NULL {int(s.isna().sum()):,}, chuỗi `'None'` {int((s == 'None').sum()):,}, rỗng {int((s == '').sum()):,}"
    for c in ("new_path", "old_path", "filename"):
        w(f"- `{c}`: {empties(c)}.")
    if "change_type" in fc.columns:
        w("- `change_type`: " + ", ".join(f"`{k}` {v:,}" for k, v in fc.change_type.value_counts(dropna=False).items()) + ".\n")

    # ---- 8. kiểm tra ý nghĩa before_change bằng mẫu
    w("## 7. Kiểm tra ý nghĩa của `before_change` trên mẫu\n")
    w(f"Lấy ngẫu nhiên (seed {C.SAMPLE_SEED}) 300 hàm mỗi giá trị `before_change` trong 7 ngôn ngữ, rồi kiểm tra `code` của hàm "
      "(đã chuẩn hóa xuống dòng, bỏ khoảng trắng hai đầu từng dòng) có nằm trong `code_before` hay `code_after` của file tương ứng.\n")
    keep_ids = set(fc[fc.programming_language.isin(C.LANGS)]._fcid)
    rowid_of = dict(zip(fc._fcid, fc.fc_rowid))
    ids = q(con, "SELECT method_change_id, file_change_id, before_change FROM method_change")
    ids = ids[ids.file_change_id.astype(str).isin(keep_ids)].sort_values("method_change_id", kind="stable").reset_index(drop=True)
    rng = random.Random(C.SAMPLE_SEED)
    norm = lambda s: "\n".join(x.strip() for x in str(s).replace("\r\n", "\n").replace("\r", "\n").split("\n") if x.strip())
    rows = []
    for val, g in ids.groupby("before_change", sort=True):
        pick = g.iloc[sorted(rng.sample(range(len(g)), min(300, len(g))))]
        res = {"chỉ trong code_before": 0, "chỉ trong code_after": 0, "trong cả hai": 0, "không thấy ở bản nào": 0}
        for r in pick.itertuples():
            code = con.execute("SELECT code FROM method_change WHERE method_change_id = ?", (r.method_change_id,)).fetchone()[0]
            cb, ca = con.execute("SELECT code_before, code_after FROM file_change WHERE rowid = ?", (int(rowid_of[str(r.file_change_id)]),)).fetchone()
            c, inb, ina = norm(code), False, False
            if c:
                inb, ina = c in norm(cb), c in norm(ca)
            res["trong cả hai" if inb and ina else "chỉ trong code_before" if inb else "chỉ trong code_after" if ina else "không thấy ở bản nào"] += 1
        rows.append({"before_change": val, "số mẫu": len(pick), **res})
    chk = pd.DataFrame(rows)
    w(md_table(chk) + "\n")
    print(chk.to_string(index=False), flush=True)

    (C.WORK / "schema.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"Đã ghi {C.WORK / 'schema.md'}")


if __name__ == "__main__":
    main()
