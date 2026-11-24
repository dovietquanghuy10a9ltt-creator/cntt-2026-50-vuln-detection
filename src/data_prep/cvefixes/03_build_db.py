"""Bước 2b: dựng cơ sở dữ liệu SQLite từ bản dump SQL nén trong file zip.

Gói v1.0.8 không chứa sẵn CVEfixes.db mà chỉ có Data/CVEfixes_v1.0.8.sql.gz; INSTALL.md hướng dẫn
`gzcat Data/CVEfixes_v1.0.8.sql.gz | sqlite3 Data/CVEfixes.db`. Script này làm đúng việc đó bằng Python:
đọc luồng zip -> gzip -> từng câu lệnh SQL -> sqlite3, không giải nén trung gian ra đĩa và không giữ
bản dump trong bộ nhớ (mỗi lúc chỉ giữ một câu lệnh).

Chạy lại được: ghi vào db/CVEfixes.db.partial, xong mới đổi tên thành db/CVEfixes.db và ghi db/build_info.json.
Nếu db/CVEfixes.db và build_info.json đã có (cùng MD5 file zip) thì bỏ qua.
"""
from __future__ import annotations
import gzip
import json
import shutil
import sqlite3
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()

MIN_FREE = 3 * 2**30          # dừng nếu ổ đĩa còn dưới 3 GiB
DB = C.DB_DIR / "CVEfixes.db"
PARTIAL = C.DB_DIR / "CVEfixes.db.partial"
BUILD_INFO = C.DB_DIR / "build_info.json"


def statements(stream):
    """Tách bản dump thành từng câu lệnh (bytes).

    Bản dump của sqlite chỉ dùng dấu nháy đơn cho chuỗi ('' là nháy đơn bên trong chuỗi), nên số dấu
    nháy đơn lẻ/chẵn trên mỗi dòng cho biết dòng đó kết thúc ở trong hay ngoài chuỗi. Câu lệnh kết thúc
    khi đang ở ngoài chuỗi và dòng kết thúc bằng ';'. Đọc ở chế độ nhị phân để giữ nguyên \\r\\n trong mã nguồn.
    """
    buf, in_string = [], False
    for line in stream:
        if line.count(b"'") & 1:
            in_string = not in_string
        buf.append(line)
        if not in_string and line.rstrip().endswith(b";"):
            yield b"".join(buf)
            buf = []
    tail = b"".join(buf)
    assert not tail.strip(), f"Bản dump kết thúc giữa chừng một câu lệnh ({len(tail)} byte dư)"


def main():
    C.check_package_hashes()
    info = json.loads((C.WORK / "download_info.json").read_text(encoding="utf-8"))
    zpath = C.DOWNLOAD / info["file_name"]
    assert zpath.stat().st_size == info["size_bytes"], "File zip chưa tải xong; chạy lại 02_download.py"
    C.DB_DIR.mkdir(exist_ok=True)

    if DB.exists() and BUILD_INFO.exists():
        prev = json.loads(BUILD_INFO.read_text(encoding="utf-8"))
        if prev.get("zip_md5") == info["md5_computed"] and prev.get("db_size_bytes") == DB.stat().st_size:
            print(f"Đã có {DB} ({DB.stat().st_size / 2**30:.2f} GiB), bỏ qua.")
            return
    for p in (PARTIAL, DB, BUILD_INFO):
        if p.exists():
            p.unlink()

    with zipfile.ZipFile(zpath) as z:
        dumps = [i for i in z.infolist() if i.filename.endswith(".sql.gz")]
        assert len(dumps) == 1, f"Mong đợi đúng 1 bản dump .sql.gz, thấy {[i.filename for i in dumps]}"
        entry = dumps[0]
        print(f"Bản dump: {entry.filename} ({entry.file_size / 2**30:.2f} GiB nén)")

        con = sqlite3.connect(PARTIAL, isolation_level=None)   # autocommit: BEGIN/COMMIT lấy từ bản dump
        con.execute("PRAGMA journal_mode=OFF")                  # hỏng giữa chừng thì dựng lại từ đầu
        con.execute("PRAGMA synchronous=OFF")
        con.execute("PRAGMA cache_size=-262144")                # 256 MiB

        n = n_bad_utf8 = sql_bytes = 0
        kinds: dict[str, int] = {}
        t0 = t_last = time.time()
        with z.open(entry) as raw, gzip.GzipFile(fileobj=raw) as gz:
            for stmt in statements(gz):
                n += 1
                sql_bytes += len(stmt)
                try:
                    sql = stmt.decode("utf-8")
                except UnicodeDecodeError:
                    n_bad_utf8 += 1
                    sql = stmt.decode("utf-8", errors="replace")
                assert sqlite3.complete_statement(sql), f"Câu lệnh thứ {n} không hoàn chỉnh: {sql[:200]!r}"
                head = " ".join(sql.split(None, 3)[:3]).upper()
                key = head if not head.startswith("INSERT") else "INSERT INTO " + sql.split(None, 3)[2].strip('"')
                kinds[key] = kinds.get(key, 0) + 1
                con.execute(sql)
                if n % 2000 == 0 and time.time() - t_last > 60:
                    t_last = time.time()
                    free = shutil.disk_usage(C.DB_DIR).free
                    print(f"  {n:>10,} câu lệnh | dump {100 * raw.tell() / entry.file_size:5.1f}% | "
                          f"SQL {sql_bytes / 2**30:6.2f} GiB | db {PARTIAL.stat().st_size / 2**30:6.2f} GiB | "
                          f"trống {free / 2**30:5.1f} GiB | {(t_last - t0) / 60:5.1f} phút", flush=True)
                    if free < MIN_FREE:
                        raise SystemExit("DỪNG: ổ đĩa sắp đầy khi dựng cơ sở dữ liệu (mục 3 của đặc tả).")
        if con.in_transaction:
            con.execute("COMMIT")
        ok = con.execute("PRAGMA quick_check").fetchone()[0]
        assert ok == "ok", f"PRAGMA quick_check: {ok}"
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        con.close()

    PARTIAL.rename(DB)
    out = {
        "zip_md5": info["md5_computed"],
        "dump_entry": entry.filename,
        "dump_gz_bytes": entry.file_size,
        "dump_sql_bytes": sql_bytes,
        "n_statements": n,
        "n_statements_invalid_utf8": n_bad_utf8,
        "statement_kinds": dict(sorted(kinds.items())),
        "tables": tables,
        "db_path": str(DB.relative_to(C.WORK)).replace("\\", "/"),
        "db_size_bytes": DB.stat().st_size,
    }
    BUILD_INFO.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(out, indent=2, ensure_ascii=False))
    print(f"Xong sau {(time.time() - t0) / 60:.1f} phút.")


if __name__ == "__main__":
    main()
