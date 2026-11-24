"""
Runner cho CVEfixes (bản bổ sung lần 4 của osf.io/96a2g). Dẫn xuất từ run_grouped_cv_v2.py; phần huấn luyện,
cấu hình mô hình, cách chọn checkpoint (AUROC validation macro theo ngôn ngữ) giữ nguyên.

Hai loại job (dạng "EPOCHS:mode:key:fold"):
  1. CV trên CVEfixes (tập chính v2_len768_paired, 19.907 hàm): mono/multi/lolo như MVD, chia theo cụm CVE bằng
     grouped_cv_splits.py. Sau mỗi epoch dự đoán validation và test (để vẽ đường học, không dùng để chọn gì).
     Với mono/multi: dự đoán THÊM các hàm của v2 đầy đủ không thuộc tập chính (hàm không ghép cặp, hàm dài hơn
     768 token) cùng fold (và cùng ngôn ngữ với mono), bằng trọng số tại epoch được chọn -> extra_predictions.csv.
     Các hàm này thuộc cụm của fold k nên không bao giờ có mặt trong tập huấn luyện của job fold k.
  2. Huấn luyện trên MVD, kiểm tra trên CVEfixes: xmulti:ALL:-1 và xmono:<ngôn ngữ>:-1.
     Train = hàm MVD v2 (của ngôn ngữ đó với xmono) không có cờ inner_val_fold0; validation = hàm có cờ đó (theo cụm).
     Test = hàm của tập chính CVEfixes có cvefixes_only_eval (CVE không có trong MVD, hàm không trùng MVD).
     Test chỉ dự đoán một lần bằng trọng số tại epoch được chọn.
Hai bộ dữ liệu dùng hai bộ nhớ đệm mã hoá riêng (cùng unit_id có thể mang nhãn khác nhau giữa hai bộ).
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


def job_dir(out: Path, mode: str, key: str, k: int, seed: int, epochs: int | None = None) -> Path:
    if epochs is not None:
        out = out / f"e{epochs}"
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


def build_model(cfg, device):
    mcfg = cfg["model"]
    return UniXcoderBinaryClassifier(
        model_name=mcfg["name"], revision=mcfg["revision"],
        expected_hidden_size=int(mcfg["classification_head"]["hidden_size"]),
        num_labels=int(mcfg["classification_head"]["num_labels"]),
    ).to(device)


def run_job(mode, key, k, seed, parts, caches, cfg, device, out: Path, epochs: int, per_epoch_test: bool) -> dict:
    """parts: dict(train, val, test, extra|None, removed); caches: dict(train, test) — RecordCache cho từng bộ dữ liệu."""
    d = job_dir(out, mode, key, k, seed, epochs)
    tr, va, te, ex_units, removed = parts["train"], parts["val"], parts["test"], parts.get("extra"), parts["removed"]
    ex = cfg["training_execution"]
    bsz = int(ex["physical_batch_size"])
    max_epochs = int(epochs)
    accum, clip = int(ex["gradient_accumulation_steps"]), float(ex["gradient_clipping_max_norm"])

    set_global_seed(seed)
    collator = PilotBatchCollator(caches["train"].pipeline)
    train_loader = build_train_loader(caches["train"].dataset(tr), collator, bsz, seed=seed)
    val_loader = build_validation_loader(caches["train"].dataset(va), collator, bsz)
    test_loader = build_validation_loader(caches["test"].dataset(te), collator, bsz)
    need_state = (not per_epoch_test) or (ex_units is not None and len(ex_units) > 0)

    model = build_model(cfg, device)
    criterion = nn.CrossEntropyLoss()
    o = cfg["optimizer"]
    optimizer = AdamW(model.parameters(), lr=float(o["learning_rate"]),
                      weight_decay=float(o["weight_decay"]), eps=float(o["adam_epsilon"]))
    total = optimizer_step_count(len(train_loader), accum, max_epochs)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_step_count(total, float(ex["warmup_ratio"])), num_training_steps=total)

    t0 = time.time()
    best_score, best_epoch, log = -float("inf"), -1, []
    vby, tby, best_tpred, best_state = {}, {}, None, None
    for epoch in range(1, max_epochs + 1):
        train_loss = train_one_epoch(model, train_loader, optimizer, scheduler, criterion, device, accum, clip)
        vpred, vloss = predict(model, val_loader, device, criterion)
        vby[f"p_e{epoch}"] = vpred.set_index("unit_id")["prob_vulnerable"]
        if per_epoch_test:  # chỉ để mô tả quá trình học, KHÔNG dùng để chọn checkpoint
            tpred_e, _ = predict(model, test_loader, device, criterion)
            tby[f"p_e{epoch}"] = tpred_e.set_index("unit_id")["prob_vulnerable"]
        auroc = macro_auroc(vpred)
        score = auroc if not np.isnan(auroc) else -vloss
        f1 = float(((vpred.prob_vulnerable >= 0.5) & (vpred.true_label == 1)).sum() * 2 /
                   max(((vpred.prob_vulnerable >= 0.5).sum() + (vpred.true_label == 1).sum()), 1))
        log.append(dict(epoch=epoch, train_loss=float(train_loss), val_loss=float(vloss),
                        val_auroc_macro=None if np.isnan(auroc) else float(auroc), val_f1_at_0p5=f1))
        print(f"[{mode}/{key}/fold{k}/seed{seed}] epoch {epoch}/{max_epochs} train_loss={train_loss:.4f} "
              f"val_loss={vloss:.4f} val_auroc={auroc:.4f}", flush=True)
        if score > best_score:  # nghiêm ngặt: hoà thì giữ epoch sớm hơn
            best_score, best_epoch = score, epoch
            if per_epoch_test:
                best_tpred = tpred_e
            if need_state:
                best_state = {n: t.detach().to("cpu", copy=True) for n, t in model.state_dict().items()}

    if need_state:
        model.load_state_dict(best_state)
    if per_epoch_test:
        tpred = best_tpred
        if need_state:  # kiểm tra trọng số nạp lại đúng là của epoch được chọn
            chk = te.head(min(64, len(te)))
            cpred, _ = predict(model, build_validation_loader(caches["test"].dataset(chk), collator, bsz), device, criterion)
            ref = best_tpred.set_index("unit_id")["prob_vulnerable"].reindex(cpred["unit_id"]).to_numpy()
            assert np.allclose(cpred["prob_vulnerable"].to_numpy(), ref, atol=2e-3), "trọng số nạp lại không khớp epoch được chọn"
    else:
        tpred, _ = predict(model, test_loader, device, criterion)
    meta = te.set_index("unit_id")[["group", "fold"]]
    tpred = tpred.join(meta, on="unit_id")
    tpred["mode"], tpred["seed"] = mode, seed
    d.mkdir(parents=True, exist_ok=True)
    tpred.to_csv(d / "predictions.csv", index=False)
    n_extra = 0
    if ex_units is not None and len(ex_units) > 0:
        xpred, _ = predict(model, build_validation_loader(caches["test"].dataset(ex_units), collator, bsz), device, criterion)
        xpred = xpred.join(ex_units.set_index("unit_id")[["group", "fold"]], on="unit_id")
        xpred["mode"], xpred["seed"] = mode, seed
        xpred.to_csv(d / "extra_predictions.csv", index=False)
        n_extra = len(xpred)
    pd.concat([vpred.set_index("unit_id")[["language", "true_label"]], pd.DataFrame(vby)], axis=1) \
      .reset_index().to_csv(d / "val_by_epoch.csv", index=False)
    if per_epoch_test:
        pd.concat([tpred_e.set_index("unit_id")[["language", "true_label"]], pd.DataFrame(tby)], axis=1) \
          .reset_index().to_csv(d / "test_by_epoch.csv", index=False)
    summary = dict(mode=mode, key=key, outer_fold=k, seed=seed, n_train=len(tr), n_val=len(va), n_test=len(te),
                   n_extra=n_extra, removed_for_decontamination=removed, selected_epoch=best_epoch,
                   max_epochs=max_epochs, per_epoch_test=per_epoch_test,
                   checkpoint_metric=CHECKPOINT_METRIC, best_val_score=float(best_score),
                   seconds=round(time.time() - t0, 1), env=env_info(), epochs=log)
    (d / "log.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    del model, optimizer, scheduler, best_state
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return summary


class Data:
    """Nạp CVEfixes (bắt buộc) và MVD v2 (chỉ khi có job huấn luyện trên MVD)."""

    def __init__(self, units: Path, folds_csv: Path, extra_folds_csv: Path, mvd_folds_csv: Path | None):
        u = pd.read_parquet(units, columns=["unit_id", "func", "language", "target", "cvefixes_only_eval"])
        main = pd.read_csv(folds_csv)
        allv2 = pd.read_csv(extra_folds_csv)
        assert set(main["unit_id"]) <= set(allv2["unit_id"]), "tập chính phải là tập con của v2"
        self.cvf = S.attach_folds(u[u["unit_id"].isin(main["unit_id"])][["unit_id", "func", "language", "target"]]
                                  .reset_index(drop=True), main)
        ext = allv2[~allv2["unit_id"].isin(main["unit_id"])]
        self.extra = S.attach_folds(u[u["unit_id"].isin(ext["unit_id"])][["unit_id", "func", "language", "target"]]
                                    .reset_index(drop=True), ext)
        ev = set(u.loc[u["cvefixes_only_eval"].astype(bool), "unit_id"])
        self.cvf_eval = self.cvf[self.cvf["unit_id"].isin(ev)].reset_index(drop=True)
        self.mvd_folds_csv = mvd_folds_csv
        self._mvd = None
        print(f"CVEfixes: tập chính {len(self.cvf)} hàm, thêm {len(self.extra)} hàm v2 ngoài tập chính, "
              f"{len(self.cvf_eval)} hàm chỉ có ở CVEfixes", flush=True)

    @property
    def mvd(self) -> pd.DataFrame:
        if self._mvd is None:
            folds = pd.read_csv(self.mvd_folds_csv)
            clean = MVDDatasetLoader().clean_exact_hash(copy=True)
            clean = clean[clean["unit_id"].isin(folds["unit_id"])].reset_index(drop=True)
            self._mvd = S.attach_folds(clean, folds)
            print(f"MVD v2: {len(self._mvd)} hàm", flush=True)
        return self._mvd

    def parts(self, mode: str, key: str, k: int) -> dict:
        if mode in ("mono", "multi", "lolo"):
            tr, va, te, removed = S.get_split(self.cvf, mode, key, k)
            extra = None
            if mode == "mono":
                extra = self.extra[(self.extra["fold"] == k) & (self.extra["language"] == key)].reset_index(drop=True)
            elif mode == "multi":
                extra = self.extra[self.extra["fold"] == k].reset_index(drop=True)
            if extra is not None and len(extra):
                # hàm thêm thuộc cụm của fold k -> không được trùng cụm với train/val của job này
                assert not (set(extra["group"]) & (set(tr["group"]) | set(va["group"]))), "RÒ RỈ cụm ở tập thêm"
            return dict(train=tr, val=va, test=te, extra=extra, removed=removed)
        if mode in ("xmono", "xmulti"):
            m = self.mvd if mode == "xmulti" else self.mvd[self.mvd["language"] == key]
            te = self.cvf_eval if mode == "xmulti" else self.cvf_eval[self.cvf_eval["language"] == key]
            va = m[m["inner_val_fold0"]].reset_index(drop=True)
            tr = m[~m["inner_val_fold0"]].reset_index(drop=True)
            assert not (set(tr["group"]) & set(va["group"])), "RÒ RỈ cụm giữa train và validation MVD"
            assert not (set(te["unit_id"]) & (set(tr["unit_id"]) | set(va["unit_id"]))), "hàm kiểm tra trùng hàm MVD"
            return dict(train=tr, val=va, test=te.reset_index(drop=True), extra=None, removed=0)
        raise ValueError(mode)


def all_job_names(data: Data):
    jobs = [f"{m}:{key}:{k}" for m, key, k in S.build_jobs(data.cvf)]
    jobs += ["xmulti:ALL:-1"] + [f"xmono:{lang}:-1" for lang in S.LANGUAGES]
    return jobs


A_TRAIN, B_INFER = 0.100, 0.0403   # giây/mẫu trên T4 với MVD (5 epoch, max_length 768)
LEN_CVF, LEN_EXTRA = 1.2, 1.6      # hệ số độ dài: hàm CVEfixes dài hơn MVD (ước lượng thận trọng từ phân bố token)


def estimate(e, mode, n_train, n_val, n_test, n_extra):
    if mode in ("xmono", "xmulti"):
        return e * n_train * A_TRAIN + e * n_val * B_INFER + n_test * B_INFER * LEN_CVF
    return (e * n_train * A_TRAIN + e * (n_val + n_test) * B_INFER) * LEN_CVF + n_extra * B_INFER * LEN_EXTRA


def smoke(data: Data, caches: dict, cfg, device, out: Path, report_dir: Path) -> None:
    """Chạy thử cả hai loại job trên mẫu rất nhỏ (2 epoch). Không dùng test thật của job CV; kết quả bị bỏ."""
    p = data.parts("mono", "Python", 0)
    va = p["val"]
    mini = dict(train=p["train"].head(48), val=va.head(24), test=va.iloc[24:48].reset_index(drop=True),
                extra=p["extra"].head(16), removed=0)
    r1 = run_job("smoke", "Python", 0, 0, mini, dict(train=caches["cvf"], test=caches["cvf"]), cfg, device, out, 2, True)
    jd = job_dir(out, "smoke", "Python", 0, 0, 2)
    pred = pd.read_csv(jd / "predictions.csv"); xp = pd.read_csv(jd / "extra_predictions.csv")
    tby = pd.read_csv(jd / "test_by_epoch.csv").set_index("unit_id")
    assert len(pred) == 24 and len(xp) == 16 and pred["prob_vulnerable"].between(0, 1).all()
    sel = f"p_e{r1['selected_epoch']}"
    assert np.allclose(pred.set_index("unit_id")["prob_vulnerable"].reindex(tby.index), tby[sel])
    p = data.parts("xmono", "Python", -1)
    mini = dict(train=p["train"].head(48), val=p["val"].head(24), test=p["test"].head(24), extra=None, removed=0)
    r2 = run_job("smokex", "Python", -1, 0, mini, dict(train=caches["mvd"], test=caches["cvf"]), cfg, device, out, 2, False)
    jd = job_dir(out, "smokex", "Python", -1, 0, 2)
    assert len(pd.read_csv(jd / "predictions.csv")) == 24 and not (jd / "test_by_epoch.csv").exists()
    info = {f"{n}_{k}": r[k] for n, r in (("cv", r1), ("cross", r2)) for k in ("n_train", "n_val", "n_test", "selected_epoch", "seconds")}
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "smoke_report.json").write_text(json.dumps(dict(status="SMOKE OK", **info, env=env_info()), indent=2), encoding="utf-8")
    print("SMOKE OK:", info)


def parse_jobs(specs):
    out = []
    for s in specs:
        e, m, key, k = s.split(":")
        out.append((int(e), m, key, int(k)))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--units", type=Path, required=True)
    ap.add_argument("--folds-csv", type=Path, required=True, help="groups_and_folds_cvefixes_v2_len768_paired.csv")
    ap.add_argument("--extra-folds-csv", type=Path, required=True, help="groups_and_folds_cvefixes_v2.csv")
    ap.add_argument("--mvd-folds-csv", type=Path, default=None, help="groups_and_folds_v2.csv của MVD (job x*)")
    ap.add_argument("--out", type=Path, default=Path("/kaggle/working/cvefixes_results"))
    ap.add_argument("--seeds", nargs="*", type=int, default=[17])
    ap.add_argument("--jobs", nargs="*", default=None, help='dạng "10:mono:C:0", "10:xmulti:ALL:-1"')
    ap.add_argument("--max-hours", type=float, default=8.3)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--report-dir", type=Path, default=Path("/kaggle/working/smoke_cvefixes"))
    ap.add_argument("--plan-only", action="store_true")
    args = ap.parse_args()

    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    data = Data(args.units, args.folds_csv, args.extra_folds_csv, args.mvd_folds_csv)
    valid = set(all_job_names(data))
    specs = parse_jobs(args.jobs or [f"10:{j}" for j in all_job_names(data)])
    todo = []
    for e, m, key, k in specs:
        assert f"{m}:{key}:{k}" in valid, f"job không tồn tại: {m}:{key}:{k}"
        if m.startswith("x") and args.mvd_folds_csv is None:
            raise SystemExit("job huấn luyện trên MVD cần --mvd-folds-csv")
        p = data.parts(m, key, k)
        nx = 0 if p["extra"] is None else len(p["extra"])
        todo.append((e, m, key, k, estimate(e, m, len(p["train"]), len(p["val"]), len(p["test"]), nx)))
    print(f"Số job yêu cầu: {len(todo)}  |  ước tính tổng {sum(t[4] for t in todo) / 3600:.2f} giờ GPU", flush=True)
    if args.plan_only:
        for e, m, key, k, est in todo:
            print(f"  {e:2d} epoch  {m}:{key}:{k}  ~{est / 3600:.2f} giờ")
        return 0

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Thiết bị:", device)
    pipe = UniXcoderInputPipeline()
    caches = dict(cvf=RecordCache(pipe), mvd=RecordCache(pipe))
    if args.smoke:
        import tempfile
        smoke(data, caches, cfg, device, Path(tempfile.mkdtemp()), args.report_dir)
        return 0

    start, act, pred_sum, left = time.time(), 0.0, 0.0, []
    for seed in args.seeds:
        for e, m, key, k, est in todo:
            d = job_dir(args.out, m, key, k, seed, e)
            if job_done(d):
                print(f"[BỎ QUA] đã xong: {d}")
                continue
            ratio = (act / pred_sum) if pred_sum > 0 else 1.0
            need = est * ratio * 1.1 / 3600
            elapsed = (time.time() - start) / 3600
            if elapsed + need > args.max_hours:
                print(f"[ĐỂ LẦN SAU] {e} epoch {m}/{key}/fold{k}: cần ~{need:.2f} giờ, còn {args.max_hours - elapsed:.2f} giờ")
                left.append(f"{e}:{m}:{key}:{k}")
                continue
            print(f"[BẮT ĐẦU] {e} epoch {m}/{key}/fold{k} (ước tính {need:.2f} giờ, đã chạy {elapsed:.2f} giờ)", flush=True)
            cross = m.startswith("x")
            c = dict(train=caches["mvd"] if cross else caches["cvf"], test=caches["cvf"])
            res = run_job(m, key, k, seed, data.parts(m, key, k), c, cfg, device, args.out, e, per_epoch_test=not cross)
            act += res["seconds"]
            pred_sum += est
    if left:
        print(f"CÒN {len(left)} job cho lần chạy sau: {left}")
    else:
        print("HOÀN TẤT các job được yêu cầu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
