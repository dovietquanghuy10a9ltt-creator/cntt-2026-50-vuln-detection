"""Đóng gói theo mục 14.1 của đặc tả -> cvefixes_work/cvefixes_v2_package.zip.

Gồm: data_report.md, schema.md, audit_r2_sample.md, environment.txt, scripts/, groups_and_folds_cvefixes_v1.csv,
groups_and_folds_cvefixes_v2.csv, groups_and_folds_cvefixes_v2_len768.csv (yêu cầu bổ sung),
excluded_units_cvefixes_v2.csv, cluster_stats_cvefixes_v1.csv, và units_v1.parquet nếu nhỏ hơn 200 MB.
Không gửi units_v1.csv.gz (người dùng dùng để kiểm tra độc lập trên máy).
"""
from __future__ import annotations
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
C.check_package_hashes()

OUT = C.WORK / "cvefixes_v2_package.zip"
FILES = ["data_report.md", "schema.md", "audit_r2_sample.md", "environment.txt",
         "groups_and_folds_cvefixes_v1.csv", "groups_and_folds_cvefixes_v2.csv",
         "groups_and_folds_cvefixes_v2_len768.csv", "groups_and_folds_cvefixes_v2_len768_paired.csv",
         "excluded_units_cvefixes_v2.csv", "cluster_stats_cvefixes_v1.csv"]
UNITS_LIMIT = 200 * 10**6


def main():
    items = [(C.WORK / f, f) for f in FILES]
    items += [(p, f"scripts/{p.name}") for p in sorted(C.SCRIPTS.glob("*.py"))]
    units = C.WORK / "units_v1.parquet"
    if units.stat().st_size < UNITS_LIMIT:
        items.append((units, units.name))
    else:
        print(f"units_v1.parquet {units.stat().st_size / 1e6:.0f} MB >= 200 MB: không gửi kèm")
    for p, _ in items:
        assert p.exists(), f"Thiếu {p}"
    tmp = OUT.with_suffix(".zip.partial")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p, arc in items:
            z.write(p, arc)
    tmp.replace(OUT)
    with zipfile.ZipFile(OUT) as z:
        assert z.testzip() is None
        names = z.namelist()
    sha = C.file_hash(OUT)
    (C.WORK / "package_sha256.txt").write_text(f"{sha}  {OUT.name}\n", encoding="utf-8")
    print(f"Đã ghi {OUT} ({OUT.stat().st_size / 2**20:.1f} MiB, {len(names)} file), SHA-256 {sha}")
    for n in names:
        print("  " + n)


if __name__ == "__main__":
    main()
