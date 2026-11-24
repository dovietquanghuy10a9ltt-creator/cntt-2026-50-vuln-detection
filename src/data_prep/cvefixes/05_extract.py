"""Bước 4: trích xuất hàm thô từ CVEfixes -> raw_functions.parquet.

Theo mục 6 của đặc tả, với ba chỉnh sửa người dùng đã duyệt (ghi trong mục "Bất thường" của báo cáo):
  1. Ngôn ngữ: (A) chỉ giữ programming_language thuộc 7 ngôn ngữ; (B) nếu đuôi file rõ ràng thì lấy theo đuôi,
     đuôi rõ ràng của ngôn ngữ/định dạng khác thì bỏ dòng, đuôi không rõ thì giữ theo programming_language.
  2. R0 (mã sinh tự động / đóng gói / thư viện chép vào): chỉ ĐÁNH DẤU ở bước này (cột r0_reason, theo thứ tự a, b, c, d).
  3. n_vuln_funcs_in_commit tính SAU khi bỏ R0 (mọi ngôn ngữ, kể cả ngoài 7 ngôn ngữ); n_vuln_funcs_in_commit_raw tính trước R0.

Máy ít RAM: đọc method_change theo khối nhỏ, không giữ cột code của cả bảng trong bộ nhớ.
  - Lượt 1: đọc toàn bộ method_change, chỉ giữ siêu dữ liệu nhỏ mỗi dòng (unit_id, độ dài dòng dài nhất, ...).
  - Lượt 2: đọc lại, ghi func của các dòng được giữ ra parquet theo từng nhóm dòng (~64 MB).
Đầu vào thêm: intermediate/file_change_slim.parquet (do 04_schema.py tạo).
"""
from __future__ import annotations
import hashlib
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import pandas as pd  # noqa: E402
import pyarrow as pa  # noqa: E402
import pyarrow.parquet as pq  # noqa: E402

CR, _BF = C.import_package_modules()

DB = C.DB_DIR / "CVEfixes.db"
INTER = C.WORK / "intermediate"
FC_SLIM = INTER / "file_change_slim.parquet"
META = INTER / "method_meta.parquet"
OUT = C.WORK / "raw_functions.parquet"
REPORT_MD = INTER / "step4.md"
REPORT_JSON = INTER / "step4.json"
FETCH = 100                       # số dòng mỗi lần fetch (giá trị code lớn nhất ~3,7 MB)
FLUSH_BYTES = 64 << 20            # ghi một nhóm dòng parquet khi đã gom ~64 MB mã

# ---- Ngôn ngữ, bước B (theo duyệt của người dùng)
EXT_MAP = {
    ".c": "C",
    ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".c++": "C++", ".hpp": "C++", ".hh": "C++", ".hxx": "C++",
    ".cs": "C#", ".go": "Go", ".java": "Java",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".py": "Python",
}
# Đuôi không rõ -> giữ theo programming_language. Mọi đuôi khác (không thuộc EXT_MAP, không thuộc tập này)
# được coi là đuôi rõ ràng của ngôn ngữ/định dạng khác -> bỏ dòng (bảng chi tiết ghi trong báo cáo).
EXT_AMBIG = {"", ".h", ".inc", ".in", ".inl", ".ipp", ".tcc", ".tpp", ".h++", ".pyw", ".es6", ".jsm"}

# ---- R0
R0_DIR = re.compile(r"(^|/)(node_modules|bower_components|vendor|third_party|dist)/", re.I)
R0_MINJS = re.compile(r"([.-]min|\.bundle|-bundle|\.pack|\.packed)\.js$", re.I)
R0_LONGLINE = 1000
R0_MASS = 300
R0_MASS_ALT = (100, 300, 1000)
APPROVED_R0_COMMITS = {"Go": {"5016fb8d7cdff38c79e22e8293e58300f8d3bd57"}}   # người dùng duyệt 16/11/2026
TOP_JS = INTER / "top30_js_files_after_r0.csv"
R0_NAMES = {"a": "a: thư mục node_modules/bower_components/vendor/third_party/dist",
            "b": "b: tên file .min/.bundle/.pack(ed).js",
            "c": "c: có dòng dài hơn 1.000 ký tự",
            "d": "d: file_change có hơn 300 dòng method_change"}


def log(msg):
    print(msg, flush=True)


def join_set(values) -> str:
    return ";".join(sorted({v for v in values if isinstance(v, str) and v}))


def schema_lang_counts() -> dict:
    """Đọc bảng ngôn ngữ (mục 5) và số dòng method_change (mục 1) mà 04_schema.py đã ghi trong schema.md."""
    text = (C.WORK / "schema.md").read_text(encoding="utf-8")
    sec = text.split("## 5. Ngôn ngữ", 1)[1].split("\n### ", 1)[0]
    out, other = {}, 0
    for line in sec.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 5 and cells[2].replace(",", "").isdigit():
            n = int(cells[3].replace(",", "")) + int(cells[4].replace(",", ""))
            if cells[0] in C.LANGS:
                out[cells[0]] = n
            else:
                other += n
    m = re.search(r"\| method_change \| ([\d,]+) \|", text)
    out["_total"] = int(m.group(1).replace(",", ""))
    out["_other"] = other
    assert set(C.LANGS) <= set(out), "Không đọc được bảng ngôn ngữ trong schema.md"
    return out


def pass1(con) -> pd.DataFrame:
    """Đọc toàn bộ method_change một lượt, trả về siêu dữ liệu nhỏ cho từng dòng (không giữ code)."""
    cols = {k: [] for k in ["raw_id", "method_change_id", "file_change_id", "method_name", "signature",
                            "before_change", "unit_id", "n_chars", "max_line_len"]}
    cur = con.execute("SELECT rowid, method_change_id, file_change_id, name, signature, before_change, code "
                      "FROM method_change ORDER BY rowid")
    n = 0
    t0 = t_last = time.time()
    while True:
        batch = cur.fetchmany(FETCH)
        if not batch:
            break
        for rid, mcid, fcid, name, sig, bc, code in batch:
            assert isinstance(code, str), f"code không phải chuỗi ở rowid {rid}"
            norm = CR.normalize_func(code)
            uid = hashlib.sha256(norm.encode("utf-8")).hexdigest() if norm else None
            if n % 997 == 0:   # đối chiếu định nghĩa unit_id với clean_rules (trên một phần nhỏ các dòng)
                assert (uid or CR.unit_id("")) == CR.unit_id(code)
            cols["raw_id"].append(rid)
            cols["method_change_id"].append(mcid)
            cols["file_change_id"].append(fcid)
            cols["method_name"].append(name)
            cols["signature"].append(sig)
            cols["before_change"].append(bc)
            cols["unit_id"].append(uid)
            cols["n_chars"].append(len(norm))
            cols["max_line_len"].append(max(map(len, norm.split("\n"))) if norm else 0)
            n += 1
        if time.time() - t_last > 60:
            t_last = time.time()
            log(f"  lượt 1: {n:,} dòng | {(t_last - t0) / 60:.1f} phút")
    log(f"  lượt 1 xong: {n:,} dòng sau {(time.time() - t0) / 60:.1f} phút")
    return pd.DataFrame(cols)


def pass2(con, raw: pd.DataFrame, schema: pa.Schema):
    """Đọc lại method_change, ghi func của các dòng thuộc raw (đã sắp theo raw_id) ra parquet theo khối."""
    want = raw.raw_id.to_numpy()
    meta_cols = [f.name for f in schema if f.name != "func"]
    tmp = OUT.with_suffix(".parquet.partial")
    writer = pq.ParquetWriter(tmp, schema, compression="zstd")
    pos = start = 0
    codes, nbytes = [], 0
    t0 = t_last = time.time()

    def flush():
        nonlocal start, codes, nbytes
        if not codes:
            return
        part = raw.iloc[start:start + len(codes)]
        # đối chiếu với lượt 1: dòng sẽ dùng ở các bước sau (không R0) kiểm tra toàn bộ, các dòng khác kiểm tra mẫu
        for i, (code, uid, r0) in enumerate(zip(codes, part.unit_id, part.r0_reason)):
            if r0 is None or i % 50 == 0:
                norm = CR.normalize_func(code)
                assert (hashlib.sha256(norm.encode("utf-8")).hexdigest() if norm else None) == uid, \
                    f"unit_id lệch giữa hai lượt ở raw_id {part.raw_id.iloc[i]}"
        arrays = {c: part[c].tolist() for c in meta_cols}
        arrays["func"] = codes
        writer.write_table(pa.Table.from_pydict(arrays, schema=schema))
        start += len(codes)
        codes, nbytes = [], 0

    cur = con.execute("SELECT rowid, code FROM method_change ORDER BY rowid")
    while True:
        batch = cur.fetchmany(FETCH)
        if not batch:
            break
        for rid, code in batch:
            if pos < len(want) and rid == want[pos]:
                codes.append(code)
                nbytes += len(code)
                pos += 1
        if nbytes >= FLUSH_BYTES:
            flush()
        if time.time() - t_last > 60:
            t_last = time.time()
            log(f"  lượt 2: đã ghi {start:,} / {len(want):,} dòng | {(t_last - t0) / 60:.1f} phút")
    flush()
    writer.close()
    assert pos == len(want) == start, f"Lượt 2 chỉ tìm thấy {pos:,} / {len(want):,} dòng"
    tmp.replace(OUT)
    log(f"  lượt 2 xong sau {(time.time() - t0) / 60:.1f} phút")


def counts(df, by_lang="language"):
    t = df.groupby([by_lang, "target"]).size().unstack(fill_value=0).reindex(columns=[1, 0], fill_value=0)
    t.columns = ["target=1", "target=0"]
    t["tổng"] = t.sum(axis=1)
    t = t.reindex([l for l in C.LANGS if l in t.index] + [l for l in t.index if l not in C.LANGS])
    t.loc["Tổng"] = t.sum()
    return t.reset_index().rename(columns={by_lang: "ngôn ngữ"})


def main():
    C.check_package_hashes()
    assert DB.exists() and FC_SLIM.exists(), "Cần chạy 03_build_db.py và 04_schema.py trước"
    INTER.mkdir(exist_ok=True)
    con = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)
    md, js = [], {}
    w = md.append

    # ---------------- Lượt 1: siêu dữ liệu từng dòng method_change
    if META.exists():
        log(f"Dùng lại {META.name} (xóa file này để tính lại lượt 1)")
        meta = pd.read_parquet(META)
    else:
        log("Lượt 1: đọc method_change theo khối ...")
        meta = pass1(con)
        meta.to_parquet(META, index=False)
    assert meta.raw_id.is_unique and meta.method_change_id.is_unique
    assert set(meta.before_change.unique()) <= {"True", "False"}, f"before_change lạ: {meta.before_change.unique()}"
    meta["target"] = (meta.before_change == "True").astype("int64")

    # ---------------- Nối file_change, fixes, cwe_classification
    fc = pd.read_parquet(FC_SLIM)
    assert fc.file_change_id.is_unique
    fp = fc.new_path.where(fc.new_path.notna() & ~fc.new_path.isin(["None", ""]), fc.old_path)
    fp = fp.where(fp.notna() & ~fp.isin(["None", ""]), fc.filename)
    fc["file_path"] = fp.astype(str).str.replace("\\", "/", regex=False)
    base = fc.file_path.str.rsplit("/", n=1).str[-1]
    fc["file_ext"] = base.str.extract(r"(\.[^.]+)$", expand=False).str.lower().fillna("")
    fc["r0_a"] = fc.file_path.map(lambda p: bool(R0_DIR.search(p)))
    fc["r0_b"] = fc.file_path.map(lambda p: bool(R0_MINJS.search(p)))
    meta = meta.merge(fc[["file_change_id", "hash", "programming_language", "file_path", "file_ext", "change_type",
                          "r0_a", "r0_b"]], on="file_change_id", how="left", validate="many_to_one")
    assert meta.hash.notna().all(), "Có method_change không nối được sang file_change"
    meta = meta.rename(columns={"hash": "commit_hash"})

    fixes = pd.read_sql_query("SELECT cve_id, hash, repo_url FROM fixes", con)
    cwec = pd.read_sql_query("SELECT cve_id, cwe_id FROM cwe_classification", con)
    cve_by_hash = fixes.groupby("hash").cve_id.agg(join_set)
    repo_by_hash = fixes.groupby("hash").repo_url.agg(join_set)
    cwe_by_hash = (fixes[["hash", "cve_id"]].drop_duplicates().merge(cwec, on="cve_id", how="left")
                   .groupby("hash").cwe_id.agg(join_set))
    meta["cve_id"] = meta.commit_hash.map(cve_by_hash)
    meta["cwe_id"] = meta.commit_hash.map(cwe_by_hash).fillna("")
    meta["repo_url"] = meta.commit_hash.map(repo_by_hash)
    assert meta.cve_id.notna().all() and (meta.cve_id != "").all(), "Có hàm không có CVE"

    # ---------------- R0 trên mọi dòng (mọi ngôn ngữ)
    meta["n_methods_in_file_change"] = meta.file_change_id.map(meta.groupby("file_change_id").size()).astype("int64")
    meta["is_empty"] = meta.unit_id.isna()
    r0c = meta.max_line_len > R0_LONGLINE
    r0d = meta.n_methods_in_file_change > R0_MASS
    meta["r0_reason"] = None
    for code, cond in (("d", r0d), ("c", r0c), ("b", meta.r0_b), ("a", meta.r0_a)):   # gán ngược để a thắng
        meta.loc[cond, "r0_reason"] = code
    meta["r0_reason"] = meta.r0_reason.astype(object).where(meta.r0_reason.notna(), None)

    # ---------------- n_vuln_funcs_in_commit (mọi ngôn ngữ; raw = trước R0, chính = sau R0)
    vul = meta[(meta.target == 1) & ~meta.is_empty]
    nv_raw = vul.groupby("commit_hash").unit_id.nunique()
    nv = vul[vul.r0_reason.isna()].groupby("commit_hash").unit_id.nunique()
    meta["n_vuln_funcs_in_commit_raw"] = meta.commit_hash.map(nv_raw).fillna(0).astype("int64")
    meta["n_vuln_funcs_in_commit"] = meta.commit_hash.map(nv).fillna(0).astype("int64")

    # ---------------- Ngôn ngữ: bước A và B
    pairs = meta[["programming_language", "file_ext"]].drop_duplicates()
    dec = {}
    for pl, ext in pairs.itertuples(index=False):
        if pl not in C.LANGS:
            dec[(pl, ext)] = (None, "A: ngoài 7 ngôn ngữ")
        elif ext in EXT_MAP:
            dec[(pl, ext)] = (EXT_MAP[ext], "B: theo đuôi")
        elif ext in EXT_AMBIG:
            dec[(pl, ext)] = (pl, "B: đuôi không rõ, giữ programming_language")
        else:
            dec[(pl, ext)] = (None, "B: đuôi thuộc ngôn ngữ/định dạng khác, bỏ")
    keys = list(zip(meta.programming_language, meta.file_ext))
    meta["language"] = [dec[k][0] for k in keys]
    meta["lang_rule"] = [dec[k][1] for k in keys]

    n_all = len(meta)
    w("## Bước 4: trích xuất hàm thô\n")
    w(f"Bảng `method_change` có {n_all:,} dòng (target=1: {int(meta.target.sum()):,}; target=0: {int((meta.target == 0).sum()):,}). "
      "Mỗi dòng `method_change` là một dòng thô; `raw_id` = `rowid` của dòng trong cơ sở dữ liệu (thứ tự của bản dump).\n")

    w("### 4.1 Ngôn ngữ\n")
    a_drop = meta[meta.lang_rule == "A: ngoài 7 ngôn ngữ"]
    t = a_drop.groupby(["programming_language", "target"], dropna=False).size().unstack(fill_value=0).reindex(columns=[1, 0], fill_value=0)
    t.columns = ["target=1", "target=0"]
    t["tổng"] = t.sum(axis=1)
    t = t.sort_values("tổng", ascending=False)
    t.loc["Tổng"] = t.sum()
    t = t.reset_index().rename(columns={"programming_language": "programming_language (không giữ)"})
    t.iloc[:, 0] = t.iloc[:, 0].map(lambda v: "(NULL)" if v is None or v != v else v)
    w(f"**Bước A** bỏ {len(a_drop):,} dòng của các ngôn ngữ khác (mục 6.2: đếm nhưng không giữ):\n")
    w(C.md_table(t) + "\n")
    in7 = meta[meta.programming_language.isin(C.LANGS)]
    bdrop = in7[in7.language.isna()]
    raw = meta[meta.language.notna()].sort_values("raw_id").reset_index(drop=True)

    # Bảng chéo đầy đủ: programming_language gốc x ngôn ngữ cuối (kể cả "bỏ ở bước A", "bỏ ở bước B")
    OTHER, DROP_A, DROP_B = "khác (ngoài 7 ngôn ngữ)", "bỏ ở bước A", "bỏ ở bước B"
    src = meta.programming_language.where(meta.programming_language.isin(C.LANGS), OTHER)
    dst = meta.language.astype(object).copy()
    dst[meta.lang_rule == "A: ngoài 7 ngôn ngữ"] = DROP_A
    dst[meta.lang_rule == "B: đuôi thuộc ngôn ngữ/định dạng khác, bỏ"] = DROP_B
    assert dst.notna().all()
    xt = pd.crosstab(src, dst).reindex(index=C.LANGS + [OTHER], columns=C.LANGS + [DROP_A, DROP_B], fill_value=0)
    xt["tổng (gốc)"] = xt.sum(axis=1)
    xt.loc["tổng (cuối)"] = xt.sum()
    w(f"**Bước A và B**: bảng chéo `programming_language` gốc (hàng) × ngôn ngữ cuối (cột), số dòng `method_change`:\n")
    w(C.md_table(xt.reset_index().rename(columns={"index": "gốc \\ cuối", "programming_language": "gốc \\ cuối"})) + "\n")
    rows = []
    moved = (src != dst) & src.isin(C.LANGS)
    for (s, d_), g in meta[moved].assign(_s=src[moved], _d=dst[moved]).groupby(["_s", "_d"]):
        rows.append({"gốc": s, "cuối": d_, "số dòng": len(g), "target=1": int(g.target.sum()),
                     "target=0": int((g.target == 0).sum()),
                     "đuôi file gây chuyển đổi (số dòng)": ", ".join(f"{e or '(không đuôi)'} ({n:,})" for e, n in g.file_ext.value_counts().items())})
    w("Các chuyển đổi (gốc khác cuối) và đuôi file gây ra:\n")
    w(C.md_table(pd.DataFrame(rows)) + "\n")
    w("Quy tắc bước B: đuôi trong bảng ánh xạ → lấy theo đuôi (" + ", ".join(f"`{e}`→{l}" for e, l in EXT_MAP.items())
      + "); đuôi không rõ (" + ", ".join(f"`{e or '(không đuôi)'}`" for e in sorted(EXT_AMBIG))
      + ") → giữ `programming_language`; mọi đuôi khác → bỏ. Đuôi lấy từ tên file cuối của `file_path` "
      "(`new_path`, nếu là `'None'` thì `old_path`, rồi `filename`), chữ thường, phần sau dấu chấm cuối cùng "
      "(nên `.d.ts` được tính là `.ts`).\n")

    # Đối chiếu với bảng ngôn ngữ của bước 3 (schema.md) và assert
    s3 = schema_lang_counts()
    pl_counts = meta.programming_language.value_counts()
    final = raw.language.value_counts()
    rec = []
    for L in C.LANGS:
        assert s3[L] == int(pl_counts.get(L, 0)), f"{L}: bảng bước 3 có {s3[L]:,} dòng, bước 4 đếm {int(pl_counts.get(L, 0)):,}"
        drop_b = int(((src == L) & (dst == DROP_B)).sum())
        out_ = int(((src == L) & (dst != L) & (dst != DROP_B)).sum())
        in_ = int(((src != L) & (dst == L)).sum())
        fin = int(final.get(L, 0))
        assert s3[L] - drop_b - out_ + in_ == fin, f"{L}: {s3[L]} - {drop_b} - {out_} + {in_} != {fin}"
        rec.append({"ngôn ngữ": L, "bảng bước 3": s3[L], "bỏ ở bước B": drop_b, "chuyển ra": out_, "chuyển vào": in_,
                    "sau A và B": fin, "chênh so với bước 3": fin - s3[L]})
    n_a, n_b = len(a_drop), len(bdrop)
    assert s3["_total"] == n_all and len(raw) + n_a + n_b == n_all, "Tổng số dòng không khớp số dòng method_change"
    assert n_a == s3["_other"], f"Bước A bỏ {n_a:,} nhưng bảng bước 3 có {s3['_other']:,} dòng ngoài 7 ngôn ngữ"
    rt = pd.DataFrame(rec)
    tot = rt.drop(columns="ngôn ngữ").sum().astype(object)
    tot["ngôn ngữ"] = "Tổng"
    rt = pd.concat([rt, tot.to_frame().T], ignore_index=True)
    w(f"Đối chiếu với bảng ngôn ngữ của bước 3 (đã `assert` trong script): với mỗi ngôn ngữ, bảng bước 3 − bỏ ở bước B "
      f"− chuyển ra + chuyển vào = sau A và B; và {len(raw):,} + {n_a:,} (bước A) + {n_b:,} (bước B) = {n_all:,}.\n")
    w(C.md_table(rt) + "\n")
    js["lang"] = {"A_dropped": n_a, "B_dropped": n_b, "in7": len(in7), "reconciliation": rec}
    w(f"Sau bước A và B còn **{len(raw):,} dòng thô**:\n")
    w(C.md_table(counts(raw)) + "\n")

    # ---------------- R0
    w("### 4.2 Quy tắc R0 (mã sinh tự động / đóng gói / thư viện chép vào)\n")
    w("Chỉ đánh dấu ở bước này (cột `r0_reason`), bước 5 mới bỏ. `r0_reason` là điều kiện đầu tiên thỏa theo thứ tự "
      "a, b, c, d: " + "; ".join(R0_NAMES.values()) + ". Đường dẫn so khớp không phân biệt hoa thường, phân cách `/`.\n")
    rows = []
    for lg in C.LANGS:
        s = raw[raw.language == lg]
        row = {"ngôn ngữ": lg, "số dòng": len(s)}
        for code in "abcd":
            for tg in (1, 0):
                row[f"{code} (t={tg})"] = int(((s.r0_reason == code) & (s.target == tg)).sum())
        row["R0 tổng"] = int(s.r0_reason.notna().sum())
        row["% bị R0"] = round(100 * row["R0 tổng"] / max(1, len(s)), 2)
        rows.append(row)
    r0t = pd.DataFrame(rows)
    tot = r0t.drop(columns=["ngôn ngữ", "% bị R0"]).sum().astype(object)
    tot["ngôn ngữ"], tot["% bị R0"] = "Tổng", round(100 * tot["R0 tổng"] / tot["số dòng"], 2)
    r0t = pd.concat([r0t, tot.to_frame().T], ignore_index=True)
    w("Số dòng bị đánh dấu theo điều kiện đầu tiên thỏa, theo ngôn ngữ và nhãn:\n")
    w(C.md_table(r0t) + "\n")
    rows = []
    for lg in C.LANGS + ["Tổng"]:
        s = raw if lg == "Tổng" else raw[raw.language == lg]
        row = {"ngôn ngữ": lg}
        for thr in R0_MASS_ALT:
            big = s.n_methods_in_file_change > thr
            row[f"d với ngưỡng {thr:,}"] = int(big.sum())
            row[f"R0 tổng nếu ngưỡng {thr:,}"] = int((s.r0_a | s.r0_b | (s.max_line_len > R0_LONGLINE) | big).sum())
        rows.append(row)
    w("Điều kiện d với các ngưỡng 100, 300 và 1.000 (cột *d với ngưỡng*: mọi dòng thuộc file_change vượt ngưỡng, "
      "không xét thứ tự; cột *R0 tổng*: số dòng bị R0 nếu dùng ngưỡng đó):\n")
    w(C.md_table(pd.DataFrame(rows)) + "\n")
    alone = {code: int(cond.sum()) for code, cond in
             (("a", raw.r0_a), ("b", raw.r0_b), ("c", raw.max_line_len > R0_LONGLINE), ("d", raw.n_methods_in_file_change > R0_MASS))}
    w("Số dòng thỏa từng điều kiện (không xét thứ tự, một dòng có thể thỏa nhiều điều kiện): "
      + ", ".join(f"{k}: {v:,}" for k, v in alone.items()) + ".\n")

    kept = raw[raw.r0_reason.isna()]
    top = (kept[kept.language == "JavaScript"].groupby(["file_change_id", "file_path", "repo_url", "commit_hash"])
           .agg(**{"số hàm": ("raw_id", "size"), "target=1": ("target", "sum")}).reset_index()
           .sort_values(["số hàm", "file_path"], ascending=[False, True]).head(30))
    top["commit"] = top.commit_hash.str[:10]
    top.to_csv(TOP_JS, index=False)
    w("30 file JavaScript còn nhiều hàm nhất sau R0 (để kiểm tra còn sót file đóng gói):\n")
    w(C.md_table(top[["file_path", "repo_url", "commit", "số hàm", "target=1"]]) + "\n")

    loss = {lg: float(r0t.loc[r0t["ngôn ngữ"] == lg, "% bị R0"].iloc[0]) for lg in C.LANGS}
    js["r0_loss_pct"] = loss
    js["r0_counts"] = {lg: int(r0t.loc[r0t["ngôn ngữ"] == lg, "R0 tổng"].iloc[0]) for lg in C.LANGS}

    w(f"Sau khi bỏ R0 còn {len(kept):,} dòng (bước 5 mới bỏ thật):\n")
    w(C.md_table(counts(kept)) + "\n")
    ne = kept[~kept.is_empty]
    w(f"Trong đó hàm rỗng sau chuẩn hóa (bước 5 bỏ): {int(kept.is_empty.sum()):,} dòng "
      f"(trên toàn bộ dòng thô: {int(raw.is_empty.sum()):,}).\n")

    # ---------------- Tỷ lệ ghép cặp (mục 6.6)
    def pairing(df):
        z = df[df.target == 0]
        zero = set(zip(z.file_change_id, z.method_name))
        v = df[df.target == 1]
        ok = pd.Series([(f, n) in zero for f, n in zip(v.file_change_id, v.method_name)], index=v.index)
        g = ok.groupby(v.language).agg(["size", "sum"])
        g = g.reindex([l for l in C.LANGS if l in g.index])
        g.loc["Tổng"] = g.sum()
        g["tỷ lệ (%)"] = (100 * g["sum"] / g["size"]).round(1)
        return g
    p_raw, p_kept = pairing(raw), pairing(kept)
    pt = pd.DataFrame({"ngôn ngữ": p_raw.index,
                       "hàm t=1 (thô)": p_raw["size"].astype(int).values, "có cặp (thô)": p_raw["sum"].astype(int).values,
                       "tỷ lệ % (thô)": p_raw["tỷ lệ (%)"].values})
    pt = pt.merge(pd.DataFrame({"ngôn ngữ": p_kept.index, "hàm t=1 (sau R0)": p_kept["size"].astype(int).values,
                                "có cặp (sau R0)": p_kept["sum"].astype(int).values,
                                "tỷ lệ % (sau R0)": p_kept["tỷ lệ (%)"].values}), on="ngôn ngữ", how="left")
    w("### 4.3 Tỷ lệ ghép cặp (mục 6.6)\n")
    w("Với mỗi hàm target=1, kiểm tra trong cùng `file_change` có hàm target=0 cùng `name` hay không. "
      "Cột *sau R0*: chỉ xét các dòng không bị R0 ở cả hai phía.\n")
    w(C.md_table(pt) + "\n")
    js["pairing"] = pt.to_dict(orient="records")

    # ---------------- n_vuln
    w("### 4.4 `n_vuln_funcs_in_commit`\n")
    w("Số `unit_id` khác nhau có target=1 trong cùng `commit_hash`, tính trên mọi ngôn ngữ của `method_change` "
      "(kể cả ngoài 7 ngôn ngữ và các dòng bị bỏ ở bước B), bỏ hàm rỗng. `n_vuln_funcs_in_commit` bỏ các dòng R0; "
      "`n_vuln_funcs_in_commit_raw` tính trước R0. Không dùng để lọc.\n")
    d = pd.DataFrame({"": ["sau R0", "trước R0 (raw)"],
                      "trung vị": [nv.median(), nv_raw.median()], "p90": [nv.quantile(.9), nv_raw.quantile(.9)],
                      "p99": [nv.quantile(.99), nv_raw.quantile(.99)], "lớn nhất": [int(nv.max()), int(nv_raw.max())],
                      "số commit có ≥1 hàm t=1": [len(nv), len(nv_raw)]})
    w("Phân bố theo commit (chỉ commit có ít nhất một hàm target=1):\n")
    w(C.md_table(d) + "\n")

    # ---------------- Ghi raw_functions.parquet
    schema = pa.schema([
        ("raw_id", pa.int64()), ("func", pa.string()), ("language", pa.string()), ("target", pa.int64()),
        ("cve_id", pa.string()), ("cwe_id", pa.string()), ("repo_url", pa.string()), ("commit_hash", pa.string()),
        ("file_path", pa.string()), ("method_name", pa.string()), ("signature", pa.string()),
        ("r0_reason", pa.string()), ("n_vuln_funcs_in_commit", pa.int64()), ("n_vuln_funcs_in_commit_raw", pa.int64()),
        ("unit_id", pa.string()), ("is_empty", pa.bool_()), ("max_line_len", pa.int64()),
        ("n_methods_in_file_change", pa.int64()), ("method_change_id", pa.string()), ("file_change_id", pa.string()),
        ("programming_language", pa.string()), ("file_ext", pa.string()), ("change_type", pa.string()),
    ])
    raw = raw[[f.name for f in schema if f.name != "func"]]
    raw = raw.astype({"raw_id": "int64", "target": "int64"})
    raw = raw.astype(object).where(raw.notna(), None)
    log(f"Lượt 2: ghi {OUT.name} ({len(raw):,} dòng) ...")
    pass2(con, raw, schema)

    pf = pq.ParquetFile(OUT)
    assert pf.metadata.num_rows == len(raw)
    chk = pq.read_table(OUT, columns=["raw_id", "language", "target"]).to_pandas()
    assert chk.raw_id.is_monotonic_increasing and chk.raw_id.is_unique
    assert set(chk.language) <= set(C.LANGS) and set(chk.target) <= {0, 1}
    w(f"Đã ghi `raw_functions.parquet`: {pf.metadata.num_rows:,} dòng, {pf.metadata.num_row_groups} nhóm dòng, "
      f"{OUT.stat().st_size / 2**30:.2f} GiB (gồm cả dòng R0). Các cột: {', '.join('`' + f.name + '`' for f in schema)}.\n")

    js["n_raw"] = int(len(raw))
    js["n_after_r0"] = int(len(kept))
    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    REPORT_JSON.write_text(json.dumps(js, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    pd.set_option("display.width", 250)
    log("\nSố dòng thô (sau bước A, B) theo ngôn ngữ và nhãn:\n" + counts(raw).to_string(index=False))
    log("\nR0 theo ngôn ngữ:\n" + r0t.to_string(index=False))
    log("\nSau R0:\n" + counts(kept).to_string(index=False))
    log("\nGhép cặp:\n" + pt.to_string(index=False))

    # ---------------- Điều kiện dừng do người dùng đặt: ngôn ngữ khác JavaScript mất hơn 20% vì R0.
    # Ngoại lệ người dùng đã duyệt: commit vendor của Go (chép nguyên thư viện wazero) -> tính tỷ lệ không kể commit này.
    bad = {}
    for lg, v in loss.items():
        if lg == "JavaScript":
            continue
        s = raw[(raw.language == lg) & ~raw.commit_hash.isin(APPROVED_R0_COMMITS.get(lg, set()))]
        v2 = 100 * s.r0_reason.notna().sum() / max(1, len(s))
        if v2 > 20:
            bad[lg] = round(v2, 2)
    if bad:
        log(f"\nDỪNG: R0 bỏ hơn 20% số dòng ở {bad}. Báo người dùng trước khi làm tiếp.")
        sys.exit(2)
    log(f"\nĐã ghi {REPORT_MD} và {REPORT_JSON}.")


if __name__ == "__main__":
    main()
