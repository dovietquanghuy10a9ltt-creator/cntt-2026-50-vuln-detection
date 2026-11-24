"""
Huấn luyện Grouped 5-fold CV (mono / multi) và LOLO trên tập sạch 18.694 đơn vị, dùng lại engine của repo.
Đặt file này ở src/training/run_grouped_cv.py (cùng thư mục với grouped_cv_splits.py).

Giữ nguyên công thức đã đóng băng của repo (UniXcoder, AdamW lr 2e-5, batch 8, 5 epoch, max_length 768, fp32,
warmup 10%, clip 1.0). Thay đổi DUY NHẤT so với repo cũ:
  - checkpoint chọn theo AUROC validation (macro theo ngôn ngữ), không dùng F1 tại ngưỡng 0,5;
  - chia dữ liệu theo cụm CVE (grouped_cv_splits.py), validation nội bộ cố định theo file fold.
Tập test của mỗi job chỉ được dự đoán MỘT lần, bằng checkpoint tốt nhất trên validation.
Không lưu checkpoint ra đĩa; chỉ lưu dự đoán xác suất + nhật ký.
"""
from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score
from torch import nn
from torch.optim import AdamW
from transformers import get_linear_schedule_with_warmup

from src.preprocessing.dataset_loader import MVDDatasetLoader
from src.preprocessing.tokenization import UniXcoderInputPipeline
from src.training import grouped_cv_splits as S
from src.training.modeling import UniXcoderBinaryClassifier
from src.training.training_engine import (
    EncodedPilotDataset,
    PilotBatchCollator,
    build_train_loader,
    build_validation_loader,
    optimizer_step_count,
    preencode_frame,
    set_global_seed,
    train_one_epoch,
    warmup_step_count,
)

CONFIG_PATH = REPO_ROOT / "configs" / "rq1_mono_training_v1.json"
CHECKPOINT_METRIC = "val_auroc_macro_by_language"


def env_info() -> dict:
    import transformers
    return dict(gpu=torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu",
                torch=torch.__version__, transformers=transformers.__version__)


def clean_key(key: str) -> str:
    return key.replace("#", "sharp").replace("+", "plus").lower()


def job_dir(out: Path, mode: str, key: str, k: int, seed: int) -> Path:
    return out / mode / clean_key(key) / (f"fold{k}" if k >= 0 else "all") / f"seed_{seed}"


def job_done(d: Path) -> bool:
    return (d / "predictions.csv").is_file() and (d / "log.json").is_file()


class RecordCache:
    """Mã hoá từng đơn vị đúng một lần cho cả phiên chạy."""

    def __init__(self, pipeline: UniXcoderInputPipeline) -> None:
        self.pipeline = pipeline
        self.records: dict[str, object] = {}

    def dataset(self, frame: pd.DataFrame) -> EncodedPilotDataset:
        missing = frame[~frame["unit_id"].isin(self.records)]
        if len(missing):
            ds = preencode_frame(missing[["unit_id", "func", "language", "target"]], self.pipeline)
            for i in range(len(ds)):
                rec = ds[i]
                self.records[rec.unit_id] = rec
        return EncodedPilotDataset([self.records[u] for u in frame["unit_id"]])


@torch.inference_mode()
def predict(model: nn.Module, loader, device: torch.device, criterion: nn.Module):
    model.eval()
    ids, langs, ys, ps = [], [], [], []
    loss_sum, n = 0.0, 0
    for batch in loader:
        input_ids = batch["input_ids"].to(device, non_blocking=True)
        attention_mask = batch["attention_mask"].to(device, non_blocking=True)
        labels = batch["labels"].to(device, non_blocking=True)
        logits = model(input_ids=input_ids, attention_mask=attention_mask)
        loss_sum += float(criterion(logits, labels).item()) * int(labels.shape[0])
        n += int(labels.shape[0])
        ps.extend(torch.softmax(logits.float(), dim=-1)[:, 1].cpu().tolist())
        ys.extend(labels.cpu().tolist())
        ids.extend(batch["unit_ids"])
        langs.extend(batch["languages"])
    return pd.DataFrame({"unit_id": ids, "language": langs, "true_label": ys, "prob_vulnerable": ps}), loss_sum / max(n, 1)


def macro_auroc(frame: pd.DataFrame) -> float:
    vals = []
    for _, g in frame.groupby("language"):
        if g["true_label"].nunique() == 2:
            vals.append(roc_auc_score(g["true_label"], g["prob_vulnerable"]))
    return float(np.mean(vals)) if vals else float("nan")


def run_job(mode, key, k, seed, df, cache, cfg, device, out: Path, split=None, epochs=None) -> dict:
    d = job_dir(out, mode, key, k, seed)
    tr, va, te, removed = split if split is not None else S.get_split(df, mode, key, k)
    ex = cfg["training_execution"]
    bsz = int(ex["physical_batch_size"])
    max_epochs = int(epochs) if epochs is not None else int(ex["max_epochs"])
    accum, clip = int(ex["gradient_accumulation_steps"]), float(ex["gradient_clipping_max_norm"])

    set_global_seed(seed)
    collator = PilotBatchCollator(cache.pipeline)
    train_loader = build_train_loader(cache.dataset(tr), collator, bsz, seed=seed)
    val_loader = build_validation_loader(cache.dataset(va), collator, bsz)
    test_loader = build_validation_loader(cache.dataset(te), collator, bsz)

    mcfg = cfg["model"]
    model = UniXcoderBinaryClassifier(
        model_name=mcfg["name"], revision=mcfg["revision"],
        expected_hidden_size=int(mcfg["classification_head"]["hidden_size"]),
        num_labels=int(mcfg["classification_head"]["num_labels"]),
    ).to(device)
    criterion = nn.CrossEntropyLoss()
    o = cfg["optimizer"]
    optimizer = AdamW(model.parameters(), lr=float(o["learning_rate"]),
                      weight_decay=float(o["weight_decay"]), eps=float(o["adam_epsilon"]))
    total = optimizer_step_count(len(train_loader), accum, max_epochs)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_step_count(total, float(ex["warmup_ratio"])), num_training_steps=total)

    t0 = time.time()
    best_score, best_epoch, best_state, log = -float("inf"), -1, None, []
    for epoch in range(1, max_epochs + 1):
        train_loss = train_one_epoch(model, train_loader, optimizer, scheduler, criterion, device, accum, clip)
        vpred, vloss = predict(model, val_loader, device, criterion)
        auroc = macro_auroc(vpred)
        score = auroc if not np.isnan(auroc) else -vloss  # chỉ xảy ra nếu validation chỉ có một lớp
        f1 = float(((vpred.prob_vulnerable >= 0.5) & (vpred.true_label == 1)).sum() * 2 /
                   max(((vpred.prob_vulnerable >= 0.5).sum() + (vpred.true_label == 1).sum()), 1))
        log.append(dict(epoch=epoch, train_loss=float(train_loss), val_loss=float(vloss),
                        val_auroc_macro=None if np.isnan(auroc) else float(auroc), val_f1_at_0p5=f1))
        print(f"[{mode}/{key}/fold{k}/seed{seed}] epoch {epoch}/{max_epochs} train_loss={train_loss:.4f} "
              f"val_loss={vloss:.4f} val_auroc={auroc:.4f}", flush=True)
        if score > best_score:  # nghiêm ngặt: hoà thì giữ epoch sớm hơn
            best_score, best_epoch = score, epoch
            best_state = {n: p.detach().to("cpu", copy=True) for n, p in model.state_dict().items()}

    model.load_state_dict(best_state)
    tpred, _ = predict(model, test_loader, device, criterion)  # test: một lần duy nhất
    meta = te.set_index("unit_id")[["group", "fold"]]
    tpred = tpred.join(meta, on="unit_id")
    tpred["mode"], tpred["seed"] = mode, seed
    d.mkdir(parents=True, exist_ok=True)
    tpred.to_csv(d / "predictions.csv", index=False)
    summary = dict(mode=mode, key=key, outer_fold=k, seed=seed, n_train=len(tr), n_val=len(va), n_test=len(te),
                   removed_for_decontamination=removed, selected_epoch=best_epoch,
                   checkpoint_metric=CHECKPOINT_METRIC, best_val_score=float(best_score),
                   seconds=round(time.time() - t0, 1), env=env_info(), epochs=log)
    (d / "log.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    del model, optimizer, scheduler, best_state
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return summary


def smoke(df, cache, cfg, device, out: Path, report_dir: Path) -> None:
    """Chạy thử toàn bộ đường đi (train -> chọn checkpoint -> dự đoán -> ghi file) trên mẫu rất nhỏ.
    Dùng các đơn vị VALIDATION của mono/Python/fold 0 làm 'test giả', KHÔNG dùng test thật, kết quả bị bỏ."""
    tr, va, _, _ = S.get_split(df, "mono", "Python", 0)
    split = (tr.head(48), va.head(24), va.iloc[24:48], 0)
    res = run_job("smoke", "Python", 0, 0, df, cache, cfg, device, out, split=split, epochs=2)
    pred = pd.read_csv(job_dir(out, "smoke", "Python", 0, 0) / "predictions.csv")
    assert len(pred) == 24 and pred["prob_vulnerable"].between(0, 1).all()
    info = {k: res[k] for k in ("n_train", "n_val", "n_test", "selected_epoch", "seconds")}
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "smoke_report.json").write_text(json.dumps(dict(status="SMOKE OK", **info, env=env_info(),
                                                                  epochs=res["epochs"]), indent=2), encoding="utf-8")
    print("SMOKE OK:", info)


def pilot(df, cache, cfg, device, steps: int, report_dir: Path) -> None:
    """Đo tốc độ trên dữ liệu trộn 7 ngôn ngữ (train của multi, fold 0); KHÔNG chạm tập test."""
    mode, key, k = "multi", "ALL", 0
    tr, va, _, _ = S.get_split(df, mode, key, k)
    ex = cfg["training_execution"]
    bsz = int(ex["physical_batch_size"])
    collator = PilotBatchCollator(cache.pipeline)
    loader = build_train_loader(cache.dataset(tr), collator, bsz, seed=0)
    mcfg = cfg["model"]
    model = UniXcoderBinaryClassifier(
        model_name=mcfg["name"], revision=mcfg["revision"],
        expected_hidden_size=int(mcfg["classification_head"]["hidden_size"]),
        num_labels=int(mcfg["classification_head"]["num_labels"])).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = AdamW(model.parameters(), lr=float(cfg["optimizer"]["learning_rate"]))
    model.train()
    if device.type == "cuda":
        torch.cuda.reset_peak_memory_stats()
    seen, t0, warm = 0, None, 3
    for i, batch in enumerate(loader):
        if i == warm:
            if device.type == "cuda":
                torch.cuda.synchronize()
            t0, seen = time.time(), 0
        logits = model(input_ids=batch["input_ids"].to(device), attention_mask=batch["attention_mask"].to(device))
        loss = criterion(logits, batch["labels"].to(device))
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        optimizer.zero_grad(set_to_none=True)
        seen += int(batch["labels"].shape[0])
        if i + 1 >= warm + steps:
            break
    if device.type == "cuda":
        torch.cuda.synchronize()
    rate = seen / (time.time() - t0)
    vsub = va.head(64)
    vpred, vloss = predict(model, build_validation_loader(cache.dataset(vsub), collator, bsz), device, criterion)
    plan = S.plan_table(df, epochs=int(ex["max_epochs"]))
    passes = float(plan["sample_passes"].sum())
    hours = passes / rate / 3600 * 1.1  # +10% cho validation/test
    report = dict(samples_per_second=round(rate, 2), steps_measured=steps, batch_size=bsz,
                  peak_gpu_mem_gb=round(torch.cuda.max_memory_allocated() / 1e9, 2) if device.type == "cuda" else None,
                  sample_passes_per_seed=passes, est_hours_per_seed=round(hours, 2),
                  est_hours_per_seed_by_mode={m: round(float(plan.loc[plan["mode"] == m, "sample_passes"].sum()) / rate / 3600 * 1.1, 2)
                                              for m in ("mono", "multi", "lolo")},
                  est_hours_per_job={f"{r['mode']}|{r['key']}|{r['fold']}": round(r["sample_passes"] / rate / 3600 * 1.1, 3)
                                     for _, r in plan.iterrows()},
                  val_probe_loss=round(vloss, 4), env=env_info())
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "pilot_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("=" * 70)
    print(f"Tốc độ huấn luyện đo được: {rate:.1f} mẫu/giây  (peak GPU mem: "
          f"{torch.cuda.max_memory_allocated() / 1e9:.1f} GB)" if device.type == "cuda" else f"Tốc độ: {rate:.1f} mẫu/giây (CPU)")
    print(f"Đường dự đoán validation chạy được: {len(vpred)} mẫu, loss={vloss:.3f}")
    print(f"Tổng số lượt mẫu-epoch mỗi seed (mono+multi+lolo): {passes:,.0f}")
    print(f"Ước tính thời gian MỖI SEED: {hours:.1f} giờ GPU")
    print(f"Ước tính 3 seed: {3 * hours:.1f} giờ  (hạn mức Kaggle ~30 giờ/tuần, mỗi phiên tối đa 9 giờ)")
    print("=" * 70)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--folds-csv", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("/kaggle/working/grouped_cv_results"))
    ap.add_argument("--modes", nargs="*", default=["mono", "multi", "lolo"])
    ap.add_argument("--seeds", nargs="*", type=int, default=[17])
    ap.add_argument("--languages", nargs="*", default=None)
    ap.add_argument("--folds", nargs="*", type=int, default=None)
    ap.add_argument("--jobs", nargs="*", default=None,
                    help="chỉ chạy các job này, dạng mode:key:fold (vd mono:C#:0 multi:ALL:1 lolo:Java:-1); thay cho --modes/--languages/--folds")
    ap.add_argument("--max-hours", type=float, default=8.3, help="dừng sạch trước giới hạn 9 giờ của phiên Kaggle")
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--pilot-steps", type=int, default=60)
    ap.add_argument("--report-dir", type=Path, default=Path("/kaggle/working/pilot_outputs"))
    ap.add_argument("--plan-only", action="store_true")
    args = ap.parse_args()

    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    clean = MVDDatasetLoader().clean_exact_hash(copy=True)
    df = S.attach_folds(clean, pd.read_csv(args.folds_csv))
    if args.jobs:
        jobs = S.select_jobs(S.build_jobs(df), args.jobs)
    else:
        jobs = S.build_jobs(df, modes=args.modes, languages=args.languages, folds=args.folds)
    plan = S.plan_table(df, epochs=int(cfg["training_execution"]["max_epochs"]), jobs=jobs)
    print(plan.groupby("mode")[["n_train", "n_val", "n_test", "sample_passes"]].sum())
    print(f"Số job mỗi seed: {len(jobs)}")
    if args.plan_only:
        return 0

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Thiết bị:", device)
    cache = RecordCache(UniXcoderInputPipeline())
    if args.smoke:
        import tempfile
        smoke(df, cache, cfg, device, Path(tempfile.mkdtemp()), args.report_dir)
        return 0
    if args.pilot:
        pilot(df, cache, cfg, device, args.pilot_steps, args.report_dir)
        return 0

    start, done_passes, done_secs = time.time(), 0.0, 0.0
    for seed in args.seeds:
        for (mode, key, k), (_, row) in zip(jobs, plan.iterrows()):
            d = job_dir(args.out, mode, key, k, seed)
            if job_done(d):
                print(f"[BỎ QUA] đã xong: {d}")
                continue
            elapsed = (time.time() - start) / 3600
            est = (row["sample_passes"] / (done_passes / done_secs) / 3600 * 1.1) if done_secs > 0 else 0.0
            if elapsed + est > args.max_hours:
                print(f"[DỪNG] đã chạy {elapsed:.2f} giờ, job kế tiếp cần ~{est:.2f} giờ, vượt {args.max_hours} giờ. "
                      "Lưu kết quả rồi chạy lại cell này ở phiên sau (tự bỏ qua job đã xong).")
                return 0
            res = run_job(mode, key, k, seed, df, cache, cfg, device, args.out)
            done_passes += float(row["sample_passes"])
            done_secs += res["seconds"]
    print("HOÀN TẤT các job được yêu cầu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
