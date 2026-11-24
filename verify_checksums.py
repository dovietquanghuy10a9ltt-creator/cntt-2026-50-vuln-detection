"""Kiểm tra repo khớp với các bản đăng ký trước.

1. Các file có mã SHA-256 ghi trong bản đăng ký (Phụ lục A của báo cáo): so trực tiếp.
2. Mọi file trong repo: so với CHECKSUMS.sha256.

data/cvefixes/units_v1.parquet nằm ở mục Releases (không có trong git); nếu chưa tải về, file này được báo là
"chưa tải" chứ không tính là lệch.

Dùng:  python verify_checksums.py
"""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FROM_RELEASE = {"data/cvefixes/units_v1.parquet"}
REGISTERED = {
    "data/mvd_v1/groups_and_folds_v1.csv": "ed59a0c8b0701e91bbb8314fe541faab95fc36503e8c75ef95f7c51ebbf4db2a",
    "src/training/grouped_cv_splits.py": "2d3d9d9a8fa5d144ac2b6e8c1426e7b055f65b47c417b450a9b4f3c9d6a4f592",
    "src/training/run_grouped_cv.py": "2483a032c07dd9739fc46d3770c49822c81bad5defc68cf32429ff6e0d5ee4a9",
    "src/training/grouped_cv_analysis.py": "029f5a45cd78a227c84332b7dd1aa0dd0539bafbd860c5753d7df1c8d6541a46",
    "data/mvd_v1/random_folds_v1.csv": "c44585956f1108c0dd982d6745a8815f0281f37ffd95f703acbedebabcc0a14f",
    "src/training/leak_compare_analysis.py": "d40359cbc80eb8e46d626468403907737599b74a7a98e4eb782b1f0d69055e48",
    "data/mvd_v2/groups_and_folds_v2.csv": "27169f52a13c9712e72cd96dad600916ccf69cd7b46e47f63364a8ebcf4e5fd9",
    "data/mvd_v2/excluded_units_v2.csv": "7d8e98b46dfd714c1c9af897af3a4cde13c0c0fb931890bfe293ec0a71a5be82",
    "src/training/run_grouped_cv_v2.py": "18c55181357a9aa9238c6b37923313f8609823c7fcb82950f8b5a70c9208df78",
    "data/mvd_v1/twin_folds_v1.csv": "d8635ef0f5e154bcb2416c3baa540e08c93ce42eee3bafb5ba4ea1a757953d61",
    "src/training/build_twin_folds.py": "c2bf8ac070a824112237ad9688b3387c2a425c15cf1bbeb51514d4bebb9a539a",
    "src/training/twin_analysis.py": "ce9fb0f4ed7cafa949d1e6a6071bf3067001511d7823dbc4c4256bdcabf2c872",
    "src/training/run_cvefixes.py": "aacbdb25379316f2dc51f6033f9bb849d382e6b46ed07666663b8318918b3c95",
    "src/training/cvf_analysis.py": "18dad1309aed49deb89b021cc73915e469fe2289523fad589071627136765b14",
    "src/training/cvf_seeds_analysis.py": "0caf8ceb2a951797a4737df883e7fc4786644c1ac04251722ff291db6f78c4ce",
    "data/cvefixes/groups_and_folds_cvefixes_v2_len768_paired.csv": "9938574e4059f0471663b84f177c9671b75be686ee34b098bc44f8e5365b7d9f",
    "data/cvefixes/units_v1.parquet": "105fb47c46dbe1be1bc8ae5212e8b5f9223b841a5181b7b466811b4e9952d90c",
    "src/training/run_codebert.py": "3aca67792510b8dc4e5f53b72b5fcdeee41c7a27ae59dd652e27ed6eeffd5568",
    "src/training/codebert_analysis.py": "2b87229915c49a044f26632392211db517a7bd76647bd5a096aeed91cfc2fb6f",
    "data/mvd_v2/mvd_v2_commit_size.csv": "74636cb6470861e507a55adb5c6ebb598ba0e2177a60a69731387929b7b77205",
    "src/training/thamdo_analysis.py": "dfcfaf4f137accb4d434540668396daa1bbc223db9b3112882f94787327bf5e1",
    "data/mvd_v2/mvd_v2_cwe.csv": "4f41f852d5160110ae438538c991734f45f67afae6b1f7ece2d5cbf384f6bf9c",
}


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    bad = 0
    print("1. File có mã băm trong bản đăng ký")
    for rel, h in REGISTERED.items():
        if rel in FROM_RELEASE and not (ROOT / rel).exists():
            print(f"   chưa tải {rel} (ở mục Releases)")
            continue
        ok = (ROOT / rel).exists() and sha(ROOT / rel) == h
        bad += not ok
        print(f"   {'khớp ' if ok else 'LỆCH '} {rel}")
    print("2. Mọi file so với CHECKSUMS.sha256")
    n = 0
    for line in (ROOT / "CHECKSUMS.sha256").read_text(encoding="utf-8").splitlines():
        h, rel = line.split("  ", 1)
        if rel in FROM_RELEASE and not (ROOT / rel).exists():
            continue
        n += 1
        if not (ROOT / rel).exists() or sha(ROOT / rel) != h:
            bad += 1
            print(f"   LỆCH  {rel}")
    print(f"   đã kiểm tra {n} file")
    print("KẾT QUẢ:", "tất cả khớp" if bad == 0 else f"{bad} file không khớp")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
