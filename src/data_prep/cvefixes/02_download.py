"""Bước 2a: tải CVEfixes v1.0.8 từ Zenodo (record 13118970), tải tiếp được nếu bị ngắt, kiểm tra MD5.

Tên file, kích thước và MD5 lấy từ API của Zenodo (không đoán tên file).
Tải theo đoạn (HTTP Range) bằng vài kết nối song song vì một kết nối đơn tới Zenodo rất chậm và hay đứt.
Trạng thái từng đoạn lưu trong download/<tên file>.state.json nên chạy lại là tải tiếp.
Kết quả: download/<tên file>, download_info.json, zip_listing.txt.
"""
from __future__ import annotations
import datetime as dt
import json
import os
import shutil
import sys
import threading
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

C.utf8_stdout()
import requests  # noqa: E402

API = f"https://zenodo.org/api/records/{C.ZENODO_RECORD}"
UA = {"User-Agent": "python-requests"}
INFO = C.WORK / "download_info.json"
LISTING = C.WORK / "zip_listing.txt"
SEG = 32 << 20            # 32 MiB mỗi đoạn
N_CONN = 12               # số kết nối song song (nếu log có nhiều lỗi ngắt kết nối thì hạ về 8)
CHUNK = 256 << 10


def zenodo_file():
    for attempt in range(1, 11):
        try:
            rec = requests.get(API, headers=UA, timeout=60).json()
            break
        except Exception as e:
            print(f"  Lỗi gọi API Zenodo ({type(e).__name__}); thử lại sau {10 * attempt}s", flush=True)
            time.sleep(10 * attempt)
    else:
        raise SystemExit("Không gọi được API Zenodo.")
    version = rec["metadata"].get("version")
    assert version == "v1.0.8", f"Phiên bản trên Zenodo là {version}, không phải v1.0.8"
    zips = [f for f in rec["files"] if f["key"].lower().endswith(".zip")]
    assert len(zips) == 1, f"Mong đợi đúng 1 file zip, thấy: {[f['key'] for f in rec['files']]}"
    f = zips[0]
    algo, md5 = f["checksum"].split(":", 1)
    assert algo == "md5"
    return rec, f["key"], int(f["size"]), f["links"]["self"], md5


def download(url: str, part: Path, state_path: Path, size: int):
    n_seg = (size + SEG - 1) // SEG
    seg_len = [min(SEG, size - i * SEG) for i in range(n_seg)]
    if state_path.exists():
        st = json.loads(state_path.read_text(encoding="utf-8"))
        assert st["size"] == size and st["seg"] == SEG, "File trạng thái không khớp; xóa download/*.part và *.state.json rồi chạy lại"
        done = st["done"]
    else:
        # lần đầu: phần đã có trên đĩa (nếu có) là một tiền tố liên tục tải bằng một kết nối
        prefix = part.stat().st_size if part.exists() else 0
        done = [max(0, min(seg_len[i], prefix - i * SEG)) for i in range(n_seg)]
    with open(part, "r+b" if part.exists() else "w+b") as f:
        f.truncate(size)

    lock = threading.Lock()
    todo = [i for i in range(n_seg) if done[i] < seg_len[i]]
    todo.reverse()                                   # pop() lấy đoạn có chỉ số nhỏ nhất trước
    fatal: list[BaseException] = []

    def save_state():
        with lock:
            snap = list(done)
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"size": size, "seg": SEG, "done": snap}), encoding="utf-8")
        os.replace(tmp, state_path)

    def worker():
        sess = requests.Session()
        fails = 0
        with open(part, "r+b") as f:
            while not fatal:
                with lock:
                    if not todo:
                        return
                    i = todo.pop()
                while done[i] < seg_len[i] and not fatal:
                    start, end = i * SEG + done[i], i * SEG + seg_len[i] - 1
                    try:
                        with sess.get(url, headers={**UA, "Range": f"bytes={start}-{end}"}, stream=True,
                                      timeout=(30, 90)) as r:
                            if r.status_code == 429:
                                time.sleep(int(r.headers.get("Retry-After", "60")) + 1)
                                continue
                            if r.status_code != 206:
                                raise RuntimeError(f"HTTP {r.status_code} (mong đợi 206)")
                            f.seek(start)
                            for chunk in r.iter_content(chunk_size=CHUNK):
                                chunk = chunk[: seg_len[i] - done[i]]
                                f.write(chunk)
                                f.flush()
                                with lock:
                                    done[i] += len(chunk)
                                fails = 0
                    except RuntimeError as e:
                        fatal.append(e)
                    except Exception:
                        fails += 1
                        if fails > 300:
                            fatal.append(RuntimeError(f"Đoạn {i} lỗi liên tiếp quá 300 lần"))
                        time.sleep(min(120, 5 * fails))

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(N_CONN)]
    for t in threads:
        t.start()
    t0, b0 = time.time(), sum(done)
    last_b, last_t = b0, t0
    while any(t.is_alive() for t in threads):
        time.sleep(60)
        save_state()
        now, b = time.time(), sum(done)
        rate = (b - last_b) / (now - last_t)
        avg = (b - b0) / (now - t0)
        eta = (size - b) / avg / 3600 if avg > 0 else float("inf")
        print(f"  {b / 2**30:6.2f} / {size / 2**30:.2f} GiB ({100 * b / size:5.1f}%) | {rate / 1024:6.0f} KiB/s | "
              f"còn khoảng {eta:5.1f} giờ", flush=True)
        last_b, last_t = b, now
    save_state()
    if fatal:
        raise SystemExit(f"DỪNG khi tải: {fatal[0]}")
    assert done == seg_len, "Còn đoạn chưa tải xong"


def main():
    C.check_package_hashes()
    C.DOWNLOAD.mkdir(exist_ok=True)
    rec, name, size, url, want = zenodo_file()
    dest = C.DOWNLOAD / name
    part = C.DOWNLOAD / (name + ".part")
    state_path = C.DOWNLOAD / (name + ".state.json")
    print(f"File: {name}  kích thước: {size:,} byte ({size / 2**30:.2f} GiB)  MD5: {want}")

    if not (dest.exists() and dest.stat().st_size == size):
        if dest.exists() and not part.exists():
            dest.rename(part)                         # phần tải dở của lượt chạy một kết nối trước đó
        have = part.stat().st_size if part.exists() and not state_path.exists() else 0
        free = shutil.disk_usage(C.DOWNLOAD).free
        if not state_path.exists():
            assert free > (size - have) + 5 * 2**30, f"Ổ đĩa không đủ chỗ để tải: trống {free / 2**30:.1f} GiB"
        download(url, part, state_path, size)
        assert part.stat().st_size == size
        print("Đang tính MD5 ...", flush=True)
        got = C.file_hash(part, "md5")
        assert got == want, f"MD5 không khớp: {got} != {want} (xóa download/*.part và *.state.json rồi tải lại)"
        part.rename(dest)
        state_path.unlink()
    else:
        print("File đã tải đủ kích thước; kiểm tra lại MD5 ...", flush=True)
        got = C.file_hash(dest, "md5")
        assert got == want, f"MD5 không khớp: {got} != {want}"
    print(f"MD5 khớp: {got}")

    prev = json.loads(INFO.read_text(encoding="utf-8")) if INFO.exists() else {}
    info = {
        "source": f"https://zenodo.org/records/{C.ZENODO_RECORD}",
        "doi": rec.get("doi"),
        "version": rec["metadata"].get("version"),
        "publication_date": rec["metadata"].get("publication_date"),
        "file_name": name,
        "size_bytes": size,
        "md5_zenodo": want,
        "md5_computed": got,
        # giữ ngày tải lần đầu để chạy lại script cho cùng kết quả
        "download_date": prev.get("download_date") if prev.get("md5_computed") == got
        else dt.date.today().isoformat(),
    }
    INFO.write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")

    with zipfile.ZipFile(dest) as z:
        rows = [f"{i.file_size:>16,}  {i.compress_size:>16,}  {i.filename}" for i in z.infolist()]
    LISTING.write_text("kích thước gốc     kích thước nén    tên\n" + "\n".join(rows) + "\n", encoding="utf-8")
    print(f"{len(rows)} mục trong file zip; danh sách ghi ở {LISTING}")
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
