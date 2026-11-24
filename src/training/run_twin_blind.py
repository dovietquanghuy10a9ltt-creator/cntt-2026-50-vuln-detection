"""Thí nghiệm "RS-blind" (bản bổ sung lần 7 của osf.io/96a2g): tách cặp sinh đôi nhưng không cho mô hình thấy hàm đối ứng.

Xuất phát từ đúng phép chia ngẫu nhiên theo hàm của bản bổ sung lần 1 (random_folds_v1.csv): MỌI hàm giữ nguyên fold
ngoài và cờ validation nội bộ. Thay đổi duy nhất nằm ở từng job:
  với mỗi cặp sinh đôi bị tách (hàm x ở fold i, hàm đối ứng x' ở fold j != i), job có tập kiểm tra là fold i
  (mono của ngôn ngữ đó, và multi) bỏ x' khỏi tập huấn luyện và validation; job của fold j bỏ x tương tự.
Như vậy mỗi hàm của 930 cặp vẫn được chấm bởi mô hình của fold mình (hai hàm, hai mô hình khác nhau, như RS), nhưng
mô hình đó chưa từng thấy hàm đối ứng mang nhãn ngược. Các job khác (k khác i, j) giữ nguyên như RS.

Cặp sinh đôi = khối (ngôn ngữ, cụm CVE của groups_and_folds_v1.csv) có đúng 2 hàm, mang cả hai nhãn (1.157 cặp; 930 cặp
bị tách trong random_folds_v1.csv), đúng định nghĩa của bản bổ sung lần 3 (build_twin_folds.py).

Mã huấn luyện, cấu hình, mô hình, seed và cách chọn checkpoint lấy nguyên từ run_grouped_cv.py (không sửa file đó).

Dùng (giống run_grouped_cv.py):
  python src/training/run_twin_blind.py --folds-csv random_folds_v1.csv --groups-csv groups_and_folds_v1.csv \
      --out /kaggle/working/blind_cv_results --jobs mono:C:0 multi:ALL:1 --seeds 17
  python src/training/run_twin_blind.py --folds-csv ... --groups-csv ... --smoke
  python src/training/run_twin_blind.py --folds-csv ... --groups-csv ... --write-drops twin_blind_drops_v1.csv
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from src.training import grouped_cv_splits as S

N_SPLIT_PAIRS = 930
N_PAIRS = 1157


def twin_pairs(groups_v1: pd.DataFrame, folds: pd.DataFrame) -> pd.DataFrame:
    """1.157 cặp sinh đôi theo đúng định nghĩa của bản bổ sung lần 3, kèm fold của hai hàm trong `folds` (RS)."""
    g = groups_v1.groupby(["language", "group"])
    blk = g.agg(n=("unit_id", "size"), nt=("target", "nunique")).reset_index()
    blk = blk[(blk.n == 2) & (blk.nt == 2)].sort_values(["language", "group"]).reset_index(drop=True)
    d = groups_v1.merge(blk[["language", "group"]], on=["language", "group"])
    pos = d[d.target == 1].set_index(["language", "group"]).unit_id.rename("u_pos")
    neg = d[d.target == 0].set_index(["language", "group"]).unit_id.rename("u_neg")
    p = blk[["language", "group"]].join(pos, on=["language", "group"]).join(neg, on=["language", "group"])
    f = folds.set_index("unit_id").fold
    p["fold_pos"] = f.loc[p.u_pos].values
    p["fold_neg"] = f.loc[p.u_neg].values
    p["split_in_random"] = p.fold_pos != p.fold_neg
    assert len(p) == N_PAIRS and int(p.split_in_random.sum()) == N_SPLIT_PAIRS, (len(p), int(p.split_in_random.sum()))
    return p.reset_index(drop=True)


def twin_of(pairs: pd.DataFrame) -> dict[str, str]:
    """unit_id -> hàm đối ứng, CHỈ cho 930 cặp bị tách."""
    s = pairs[pairs.split_in_random]
    m = dict(zip(s.u_pos, s.u_neg))
    m.update(zip(s.u_neg, s.u_pos))
    return m


def blind_split(df: pd.DataFrame, twin: dict[str, str], mode: str, key: str, k: int):
    """Phép chia của RS cho job (mode, key, k), rồi bỏ khỏi train/val mọi hàm đối ứng của các hàm trong tập kiểm tra."""
    assert mode in ("mono", "multi"), "RS-blind chỉ gồm job mono và multi"
    tr, va, te, removed = S.get_split(df, mode, key, k)
    drop = {twin[u] for u in te.unit_id if u in twin}
    # hàm đối ứng của một hàm trong fold k luôn nằm ở fold khác k, nên không bao giờ nằm trong tập kiểm tra
    assert not (drop & set(te.unit_id))
    in_tr, in_va = tr.unit_id.isin(drop), va.unit_id.isin(drop)
    if mode == "mono":
        assert set(df.set_index("unit_id").loc[list(drop), "language"]) <= {key}
        assert int(in_tr.sum() + in_va.sum()) == len(drop), "mỗi hàm đối ứng phải nằm trong train hoặc val của job"
    info = dict(n_dropped_train=int(in_tr.sum()), n_dropped_val=int(in_va.sum()),
                dropped=sorted(set(tr.unit_id[in_tr]) | set(va.unit_id[in_va])))
    return (tr[~in_tr].copy(), va[~in_va].copy(), te, removed), info


def drops_table(df: pd.DataFrame, twin: dict[str, str], jobs) -> pd.DataFrame:
    rows = []
    for mode, key, k in jobs:
        _, info = blind_split(df, twin, mode, key, k)
        for u in info["dropped"]:
            rows.append(dict(mode=mode, key=key, fold=k, dropped_unit_id=u, twin_in_test=twin[u]))
    return pd.DataFrame(rows).sort_values(["mode", "key", "fold", "dropped_unit_id"]).reset_index(drop=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--folds-csv", type=Path, required=True, help="random_folds_v1.csv (phép chia RS, bổ sung lần 1)")
    ap.add_argument("--groups-csv", type=Path, required=True, help="groups_and_folds_v1.csv (để xác định cặp sinh đôi)")
    ap.add_argument("--out", type=Path, default=Path("/kaggle/working/blind_cv_results"))
    ap.add_argument("--seeds", nargs="*", type=int, default=[17])
    ap.add_argument("--jobs", nargs="*", default=None, help="dạng mode:key:fold; mặc định 40 job mono + multi")
    ap.add_argument("--max-hours", type=float, default=8.3)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--report-dir", type=Path, default=Path("/kaggle/working/pilot_outputs"))
    ap.add_argument("--write-drops", type=Path, default=None, help="chỉ ghi bảng hàm bị bỏ của 40 job rồi thoát (không cần GPU)")
    ap.add_argument("--fake-clean", action="store_true", help="kiểm thử không cần dữ liệu thô: dùng cột func giả")
    args = ap.parse_args()

    folds = pd.read_csv(args.folds_csv)
    groups_v1 = pd.read_csv(args.groups_csv)
    pairs = twin_pairs(groups_v1, folds)
    twin = twin_of(pairs)

    if args.fake_clean:
        clean = groups_v1[["unit_id", "language", "target"]].assign(func="x")
    else:
        from src.preprocessing.dataset_loader import MVDDatasetLoader
        clean = MVDDatasetLoader().clean_exact_hash(copy=True)
    df = S.attach_folds(clean, folds)
    all_jobs = S.build_jobs(df, modes=("mono", "multi"))
    jobs = S.select_jobs(all_jobs, args.jobs) if args.jobs else all_jobs

    if args.write_drops:
        t = drops_table(df, twin, all_jobs)
        t.to_csv(args.write_drops, index=False, lineterminator="\n")
        print(f"đã ghi {len(t)} dòng ({t.dropped_unit_id.nunique()} hàm) vào {args.write_drops}")
        print(t.groupby("mode").size().to_dict())
        print("sha256:", hashlib.sha256(args.write_drops.read_bytes()).hexdigest())
        return 0

    import torch
    from src.preprocessing.tokenization import UniXcoderInputPipeline
    from src.training import run_grouped_cv as R

    cfg = json.loads(R.CONFIG_PATH.read_text(encoding="utf-8"))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    cache = R.RecordCache(UniXcoderInputPipeline())
    if args.smoke:
        import tempfile
        R.smoke(df, cache, cfg, device, Path(tempfile.mkdtemp()), args.report_dir)
        (_, _, te, _), info = blind_split(df, twin, "mono", "C", 0)
        print("kiểm tra phép chia mono:C:0 →", {k: v for k, v in info.items() if k != "dropped"}, "| test:", len(te))
        return 0

    plan = S.plan_table(df, epochs=int(cfg["training_execution"]["max_epochs"]), jobs=jobs)
    print(f"Số job: {len(jobs)}")
    start, done_passes, done_secs = time.time(), 0.0, 0.0
    for seed in args.seeds:
        for (mode, key, k), (_, row) in zip(jobs, plan.iterrows()):
            d = R.job_dir(args.out, mode, key, k, seed)
            if R.job_done(d):
                print(f"[BỎ QUA] đã xong: {d}")
                continue
            elapsed = (time.time() - start) / 3600
            est = (row["sample_passes"] / (done_passes / done_secs) / 3600 * 1.1) if done_secs > 0 else 0.0
            if elapsed + est > args.max_hours:
                print(f"[DỪNG] đã chạy {elapsed:.2f} giờ, job kế tiếp cần ~{est:.2f} giờ. Chạy lại ở phiên sau.")
                return 0
            split, info = blind_split(df, twin, mode, key, k)
            print(f"[{mode}/{key}/fold{k}] bỏ {info['n_dropped_train']} hàm khỏi train, {info['n_dropped_val']} khỏi val",
                  flush=True)
            res = R.run_job(mode, key, k, seed, df, cache, cfg, device, args.out, split=split)
            log = json.loads((d / "log.json").read_text(encoding="utf-8"))
            log["twin_blind"] = info
            (d / "log.json").write_text(json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8")
            done_passes += float(row["sample_passes"])
            done_secs += res["seconds"]
    print("HOÀN TẤT các job được yêu cầu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
