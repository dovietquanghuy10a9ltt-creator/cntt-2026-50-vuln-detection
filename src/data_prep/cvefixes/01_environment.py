"""Bước 1: kiểm tra SHA-256 của gói, ghi phiên bản thư viện, RAM và dung lượng ổ đĩa vào environment.txt."""
from __future__ import annotations
import datetime as dt
import importlib.metadata as md
import platform
import shutil
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import psutil  # noqa: E402

hashes = C.check_package_hashes()

lines = []
lines.append("# Môi trường dựng CVEfixes v2 (đề tài CNTT-2026-50)")
lines.append(f"Ngày ghi: {dt.datetime.now().astimezone().isoformat(timespec='seconds')}")
lines.append("")
lines.append("## Hệ thống")
lines.append(f"Hệ điều hành: {platform.platform()}")
lines.append(f"CPU: {platform.processor()} ({psutil.cpu_count(logical=False)} nhân, {psutil.cpu_count()} luồng)")
vm = psutil.virtual_memory()
lines.append(f"RAM tổng: {vm.total / 2**30:.1f} GB")
lines.append(f"RAM trống lúc ghi: {vm.available / 2**30:.1f} GB")
du = shutil.disk_usage(C.WORK)
lines.append(f"Ổ chứa cvefixes_work ({C.WORK.anchor}): tổng {du.total / 2**30:.1f} GB, trống {du.free / 2**30:.1f} GB")
lines.append("")
lines.append("## Python và thư viện")
lines.append(f"Python: {sys.version}")
lines.append(f"sqlite3 (thư viện SQLite): {sqlite3.sqlite_version}")
for dist in sorted(md.distributions(), key=lambda d: d.metadata["Name"].lower()):
    lines.append(f"{dist.metadata['Name']}=={dist.version}")
lines.append("")
lines.append("## SHA-256 của các file trong gói (đã assert khớp mục 1 của đặc tả)")
for name, h in hashes.items():
    lines.append(f"{h}  {name}")
lines.append("")

out = C.WORK / "environment.txt"
out.write_text("\n".join(lines), encoding="utf-8")
print("\n".join(lines))
print(f"Đã ghi {out}")
