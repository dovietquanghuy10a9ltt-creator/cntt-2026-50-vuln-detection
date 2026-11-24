"""
Runner cho thí nghiệm CodeBERT (bản bổ sung lần 6 của osf.io/96a2g). Dẫn xuất từ run_cvefixes.py.

Giữ nguyên so với các lần chạy UniXcoder 10 epoch (MVD v2 ở bổ sung lần 2, CVEfixes ở bổ sung lần 4):
  - chia dữ liệu theo cụm CVE bằng grouped_cv_splits.py (không đổi), cùng file fold, cùng 47 job mỗi bộ dữ liệu
    (Mono 7 ngôn ngữ × 5 fold, Multi 5 fold, LOLO 7 ngôn ngữ, khử nhiễm theo cụm);
  - đầu phân loại: trung bình các trạng thái ẩn cuối trên vị trí không đệm -> Linear(768 -> 2), tinh chỉnh toàn bộ
    (dùng lại lớp UniXcoderBinaryClassifier của repo: lớp này chỉ là AutoModel + mean pooling + Linear);
  - AdamW lr 2e-5, weight decay 0, eps 1e-8, batch 8, fp32, warmup 10% rồi giảm tuyến tính, clip 1.0, 10 epoch,
    seed 17; checkpoint chọn theo AUROC validation macro theo ngôn ngữ (hoà thì giữ epoch sớm hơn);
  - sau mỗi epoch dự đoán validation và test, chỉ để vẽ đường học, không dùng để chọn gì; predictions.csv là dự đoán
    test tại epoch được chọn.
Khác DUY NHẤT: bộ mã hoá và cách đưa đầu vào.
  - microsoft/codebert-base, revision cố định (MODEL_REVISION); tokenizer cùng revision.
  - Đầu vào "<s> CODE </s>", tối đa 512 token (giới hạn vị trí của CodeBERT), tức tối đa 510 token mã; cắt bên
    phải (giữ phần đầu hàm), đệm động theo batch. UniXcoder dùng "<s> <encoder-only> </s> CODE </s>", tối đa 768.
  - predictions.csv có thêm hai cột n_code_tokens (số token mã theo tokenizer CodeBERT, trước khi cắt) và truncated,
    dùng cho độ nhạy S5 (chỉ các hàm CodeBERT thấy trọn vẹn).
Không có job huấn luyện chéo MVD -> CVEfixes và không dự đoán tập thêm.

Job dạng "EPOCHS:dataset:mode:key:fold", ví dụ "10:mvd:mono:C:0", "10:cvf:lolo:Go:-1".
Kết quả: <out>/<dataset>/e<EPOCHS>/<mode>/<key>/<fold|all>/seed_<s>/.
Hai bộ dữ liệu dùng hai bộ nhớ đệm mã hoá riêng.
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
from transformers import RobertaTokenizer, get_linear_schedule_with_warmup

from src.preprocessing.dataset_loader import MVDDatasetLoader
from src.preprocessing.tokenization import EncodedFunction
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
MODEL_NAME = "microsoft/codebert-base"
MODEL_REVISION = "3b0952feddeffad0063f274080e3c23d75e7eb39"
MAX_LENGTH = 512
CODE_BUDGET = MAX_LENGTH - 2   # <s> CODE </s>
DATASETS = ("mvd", "cvf")


def env_info() -> dict:
    import transformers
    return dict(gpu=torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu",
                torch=torch.__version__, transformers=transformers.__version__,
                model=MODEL_NAME, revision=MODEL_REVISION, max_length=MAX_LENGTH)


class CodeBERTInputPipeline:
    """<s> CODE </s>, tối đa 512 token; cắt phải (giữ CODE_BUDGET token mã đầu tiên); đệm phải, động theo batch."""

    def __init__(self) -> None:
        self.tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME, revision=MODEL_REVISION)
        self.tokenizer.padding_side = "right"
        self.tokenizer.truncation_side = "right"
        t = self.tokenizer
        self.cls_token_id = int(t.convert_tokens_to_ids(t.cls_token))
        self.sep_token_id = int(t.convert_tokens_to_ids(t.sep_token))
        self.pad_token_id = int(t.convert_tokens_to_ids(t.pad_token))
        assert tuple(map(str, (t.cls_token, t.sep_token, t.pad_token))) == ("<s>", "</s>", "<pad>"), \
            "token đặc biệt không như RoBERTa"
        assert (self.cls_token_id, self.pad_token_id, self.sep_token_id) == (0, 1, 2), "id token đặc biệt lệch"
        assert len(t) == 50265, f"kích thước từ vựng {len(t)} != 50265"
        self.max_length = MAX_LENGTH

    def encode_function(self, code: str) -> EncodedFunction:
        ids = [int(i) for i in self.tokenizer.convert_tokens_to_ids(self.tokenizer.tokenize(str(code)))]
        used = ids[:CODE_BUDGET]
        input_ids = [self.cls_token_id, *used, self.sep_token_id]
        assert len(input_ids) <= MAX_LENGTH
        return EncodedFunction(input_ids=input_ids, attention_mask=[1] * len(input_ids),
                               code_token_length_untruncated=len(ids), code_token_length_used=len(used),
                               truncated=len(used) < len(ids))

    def collate_batch(self, samples):
        longest = max(len(s.input_ids) for s in samples)
        assert longest <= MAX_LENGTH
        ids = [s.input_ids + [self.pad_token_id] * (longest - len(s.input_ids)) for s in samples]
        mask = [s.attention_mask + [0] * (longest - len(s.attention_mask)) for s in samples]
        return {"input_ids": torch.tensor(ids, dtype=torch.long), "attention_mask": torch.tensor(mask, dtype=torch.long)}


def clean_key(key: str) -> str:
    return key.replace("#", "sharp").replace("+", "plus").lower()


def job_dir(out: Path, ds: str, mode: str, key: str, k: int, seed: int, epochs: int) -> Path:
    return out / ds / f"e{epochs}" / mode / clean_key(key) / (f"fold{k}" if k >= 0 else "all") / f"seed_{seed}"


def job_done(d: Path) -> bool:
    return (d / "predictions.csv").is_file() and (d / "log.json").is_file()


class RecordCache:
    """Mã hoá từng đơn vị đúng một lần cho cả phiên chạy."""

    def __init__(self, pipeline: CodeBERTInputPipeline) -> None:
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

    def lengths(self, unit_ids) -> pd.DataFrame:
        rec = [self.records[u].encoded for u in unit_ids]
        return pd.DataFrame({"unit_id": list(unit_ids), "n_code_tokens": [r.code_token_length_untruncated for r in rec],
                             "truncated": [bool(r.truncated) for r in rec]})


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


def check_config(cfg) -> None:
    """Công thức huấn luyện phải đúng như các lần chạy UniXcoder."""
    ex, o, h = cfg["training_execution"], cfg["optimizer"], cfg["model"]["classification_head"]
    got = (int(ex["physical_batch_size"]), int(ex["gradient_accumulation_steps"]), float(ex["warmup_ratio"]),
           float(ex["gradient_clipping_max_norm"]), float(o["learning_rate"]), float(o["weight_decay"]),
           float(o["adam_epsilon"]), h["pooling"], int(h["hidden_size"]), int(h["num_labels"]), ex["precision"])
    want = (8, 1, 0.1, 1.0, 2e-5, 0.0, 1e-8, "attention_mask_mean_over_non_padding_positions", 768, 2, "fp32")
    assert got == want, f"công thức huấn luyện lệch: {got} != {want}"


def build_model(device):
    model = UniXcoderBinaryClassifier(model_name=MODEL_NAME, revision=MODEL_REVISION,
                                      expected_hidden_size=768, num_labels=2).to(device)
    c = model.encoder.config
    assert c.model_type == "roberta" and c.vocab_size == 50265 and c.max_position_embeddings == 514, \
        (c.model_type, c.vocab_size, c.max_position_embeddings)
    return model


def run_job(ds, mode, key, k, seed, parts, cache, cfg, device, out: Path, epochs: int) -> dict:
    """parts: dict(train, val, test, removed)."""
    d = job_dir(out, ds, mode, key, k, seed, epochs)
    tr, va, te, removed = parts["train"], parts["val"], parts["test"], parts["removed"]
    ex = cfg["training_execution"]
    bsz = int(ex["physical_batch_size"])
    max_epochs = int(epochs)
    accum, clip = int(ex["gradient_accumulation_steps"]), float(ex["gradient_clipping_max_norm"])

    set_global_seed(seed)
    collator = PilotBatchCollator(cache.pipeline)
    train_loader = build_train_loader(cache.dataset(tr), collator, bsz, seed=seed)
    val_loader = build_validation_loader(cache.dataset(va), collator, bsz)
    test_loader = build_validation_loader(cache.dataset(te), collator, bsz)

    model = build_model(device)
    criterion = nn.CrossEntropyLoss()
    o = cfg["optimizer"]
    optimizer = AdamW(model.parameters(), lr=float(o["learning_rate"]),
                      weight_decay=float(o["weight_decay"]), eps=float(o["adam_epsilon"]))
    total = optimizer_step_count(len(train_loader), accum, max_epochs)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_step_count(total, float(ex["warmup_ratio"])), num_training_steps=total)

    t0 = time.time()
    best_score, best_epoch, log = -float("inf"), -1, []
    vby, tby, best_tpred = {}, {}, None
    for epoch in range(1, max_epochs + 1):
        train_loss = train_one_epoch(model, train_loader, optimizer, scheduler, criterion, device, accum, clip)
        vpred, vloss = predict(model, val_loader, device, criterion)
        vby[f"p_e{epoch}"] = vpred.set_index("unit_id")["prob_vulnerable"]
        tpred_e, _ = predict(model, test_loader, device, criterion)  # chỉ để mô tả, KHÔNG dùng để chọn checkpoint
        tby[f"p_e{epoch}"] = tpred_e.set_index("unit_id")["prob_vulnerable"]
        auroc = macro_auroc(vpred)
        score = auroc if not np.isnan(auroc) else -vloss
        f1 = float(((vpred.prob_vulnerable >= 0.5) & (vpred.true_label == 1)).sum() * 2 /
                   max(((vpred.prob_vulnerable >= 0.5).sum() + (vpred.true_label == 1).sum()), 1))
        log.append(dict(epoch=epoch, train_loss=float(train_loss), val_loss=float(vloss),
                        val_auroc_macro=None if np.isnan(auroc) else float(auroc), val_f1_at_0p5=f1))
        print(f"[{ds}/{mode}/{key}/fold{k}/seed{seed}] epoch {epoch}/{max_epochs} train_loss={train_loss:.4f} "
              f"val_loss={vloss:.4f} val_auroc={auroc:.4f}", flush=True)
        if score > best_score:  # nghiêm ngặt: hoà thì giữ epoch sớm hơn
            best_score, best_epoch, best_tpred = score, epoch, tpred_e

    tpred = best_tpred  # dự đoán test tại epoch có AUROC validation cao nhất
    meta = te.set_index("unit_id")[["group", "fold"]]
    tpred = tpred.join(meta, on="unit_id").merge(cache.lengths(tpred["unit_id"]), on="unit_id", how="left",
                                                 validate="one_to_one")
    tpred["mode"], tpred["seed"], tpred["dataset"], tpred["model"] = mode, seed, ds, "codebert"
    d.mkdir(parents=True, exist_ok=True)
    tpred.to_csv(d / "predictions.csv", index=False)
    pd.concat([vpred.set_index("unit_id")[["language", "true_label"]], pd.DataFrame(vby)], axis=1) \
      .reset_index().to_csv(d / "val_by_epoch.csv", index=False)
    pd.concat([tpred_e.set_index("unit_id")[["language", "true_label"]], pd.DataFrame(tby)], axis=1) \
      .reset_index().to_csv(d / "test_by_epoch.csv", index=False)
    summary = dict(dataset=ds, mode=mode, key=key, outer_fold=k, seed=seed, n_train=len(tr), n_val=len(va),
                   n_test=len(te), removed_for_decontamination=removed, selected_epoch=best_epoch,
                   max_epochs=max_epochs, checkpoint_metric=CHECKPOINT_METRIC, best_val_score=float(best_score),
                   n_test_truncated=int(tpred["truncated"].sum()),
                   seconds=round(time.time() - t0, 1), env=env_info(), epochs=log)
    (d / "log.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    del model, optimizer, scheduler
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return summary


class Data:
    """MVD v2 (14.945 hàm) và tập chính CVEfixes (19.907 hàm), mỗi bộ có cột fold/cụm từ file fold đã đăng ký."""

    def __init__(self, mvd_folds_csv: Path, cvf_units: Path, cvf_folds_csv: Path):
        folds = pd.read_csv(mvd_folds_csv)
        clean = MVDDatasetLoader().clean_exact_hash(copy=True)
        clean = clean[clean["unit_id"].isin(folds["unit_id"])].reset_index(drop=True)
        self.mvd = S.attach_folds(clean, folds)
        u = pd.read_parquet(cvf_units, columns=["unit_id", "func", "language", "target"])
        main = pd.read_csv(cvf_folds_csv)
        self.cvf = S.attach_folds(u[u["unit_id"].isin(main["unit_id"])].reset_index(drop=True), main)
        assert len(self.mvd) == 14945 and len(self.cvf) == 19907, (len(self.mvd), len(self.cvf))
        print(f"MVD v2: {len(self.mvd)} hàm | CVEfixes tập chính: {len(self.cvf)} hàm", flush=True)

    def frame(self, ds: str) -> pd.DataFrame:
        return self.mvd if ds == "mvd" else self.cvf

    def parts(self, ds: str, mode: str, key: str, k: int) -> dict:
        tr, va, te, removed = S.get_split(self.frame(ds), mode, key, k)
        return dict(train=tr, val=va, test=te, removed=removed)


def all_job_names(data: Data):
    return [f"{ds}:{m}:{key}:{k}" for ds in DATASETS for m, key, k in S.build_jobs(data.frame(ds))]


# Thời gian ước tính: hệ số mẫu/giây khớp từ các lần chạy UniXcoder 10 epoch trên T4 (MVD v2: 57,7 giờ; CVEfixes:
# 93,4 giờ cho 47 job), nhân hệ số thời gian của CodeBERT (cắt ở 512 token): 0,92 với MVD, 0,81 với CVEfixes.
A_TRAIN, B_INFER = 0.100, 0.0403
LEN = {"mvd": 1.00 * 0.92, "cvf": 1.2 * 0.81}


def estimate(ds, e, n_train, n_val, n_test):
    return (e * n_train * A_TRAIN + e * (n_val + n_test) * B_INFER) * LEN[ds]


def smoke(data: Data, cache: dict, cfg, device, out: Path, report_dir: Path) -> None:
    """Chạy thử trên mẫu rất nhỏ (2 epoch) cho cả hai bộ dữ liệu. Dùng validation làm 'test giả'; kết quả bị bỏ."""
    info = {}
    for ds in DATASETS:
        p = data.parts(ds, "mono", "Python", 0)
        va = p["val"]
        # thêm hàm dài nhất (theo số ký tự) của train job này vào train mini để đi qua nhánh cắt 512 token
        tr = p["train"]
        longest = tr.loc[[tr["func"].str.len().idxmax()]]
        mini = dict(train=pd.concat([tr.head(47), longest]).reset_index(drop=True), val=va.head(24),
                    test=va.iloc[24:48].reset_index(drop=True), removed=0)
        r = run_job(ds, "smoke", "Python", 0, 0, mini, cache[ds], cfg, device, out, 2)
        jd = job_dir(out, ds, "smoke", "Python", 0, 0, 2)
        pred = pd.read_csv(jd / "predictions.csv")
        tby = pd.read_csv(jd / "test_by_epoch.csv").set_index("unit_id")
        assert len(pred) == 24 and pred["prob_vulnerable"].between(0, 1).all() and pred["n_code_tokens"].notna().all()
        assert np.allclose(pred.set_index("unit_id")["prob_vulnerable"].reindex(tby.index), tby[f"p_e{r['selected_epoch']}"])
        enc = cache[ds].records[longest["unit_id"].iloc[0]].encoded
        assert len(enc.input_ids) <= MAX_LENGTH and enc.input_ids[0] == 0 and enc.input_ids[-1] == 2
        assert enc.truncated == (enc.code_token_length_untruncated > CODE_BUDGET)
        assert not enc.truncated or len(enc.input_ids) == MAX_LENGTH
        info[ds] = dict(n_train=r["n_train"], selected_epoch=r["selected_epoch"], seconds=r["seconds"],
                        longest_train_code_tokens=enc.code_token_length_untruncated, longest_truncated=enc.truncated)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "smoke_report.json").write_text(json.dumps(dict(status="SMOKE OK", **info, env=env_info()), indent=2),
                                                  encoding="utf-8")
    print("SMOKE OK:", info)


def parse_jobs(specs):
    out = []
    for s in specs:
        e, ds, m, key, k = s.split(":")
        out.append((int(e), ds, m, key, int(k)))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mvd-folds-csv", type=Path, required=True, help="groups_and_folds_v2.csv của MVD")
    ap.add_argument("--cvf-units", type=Path, required=True, help="units_v1.parquet của CVEfixes")
    ap.add_argument("--cvf-folds-csv", type=Path, required=True, help="groups_and_folds_cvefixes_v2_len768_paired.csv")
    ap.add_argument("--out", type=Path, default=Path("/kaggle/working/codebert_results"))
    ap.add_argument("--seeds", nargs="*", type=int, default=[17])
    ap.add_argument("--jobs", nargs="*", default=None, help='dạng "10:mvd:mono:C:0", "10:cvf:lolo:Go:-1"')
    ap.add_argument("--max-hours", type=float, default=8.3)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--report-dir", type=Path, default=Path("/kaggle/working/smoke_codebert"))
    ap.add_argument("--plan-only", action="store_true")
    args = ap.parse_args()

    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    check_config(cfg)
    data = Data(args.mvd_folds_csv, args.cvf_units, args.cvf_folds_csv)
    valid = set(all_job_names(data))
    specs = parse_jobs(args.jobs or [f"10:{j}" for j in all_job_names(data)])
    todo = []
    for e, ds, m, key, k in specs:
        assert f"{ds}:{m}:{key}:{k}" in valid, f"job không tồn tại: {ds}:{m}:{key}:{k}"
        p = data.parts(ds, m, key, k)
        todo.append((e, ds, m, key, k, estimate(ds, e, len(p["train"]), len(p["val"]), len(p["test"]))))
    print(f"Số job yêu cầu: {len(todo)}  |  ước tính tổng {sum(t[5] for t in todo) / 3600:.2f} giờ GPU", flush=True)
    if args.plan_only:
        for e, ds, m, key, k, est in todo:
            print(f"  {e:2d} epoch  {ds}:{m}:{key}:{k}  ~{est / 3600:.2f} giờ")
        return 0

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Thiết bị:", device)
    pipe = CodeBERTInputPipeline()
    cache = {ds: RecordCache(pipe) for ds in DATASETS}
    if args.smoke:
        import tempfile
        smoke(data, cache, cfg, device, Path(tempfile.mkdtemp()), args.report_dir)
        return 0

    start, act, pred_sum, left = time.time(), 0.0, 0.0, []
    for seed in args.seeds:
        for e, ds, m, key, k, est in todo:
            d = job_dir(args.out, ds, m, key, k, seed, e)
            if job_done(d):
                print(f"[BỎ QUA] đã xong: {d}")
                continue
            ratio = (act / pred_sum) if pred_sum > 0 else 1.0
            need = est * ratio * 1.1 / 3600
            elapsed = (time.time() - start) / 3600
            if elapsed + need > args.max_hours:
                print(f"[ĐỂ LẦN SAU] {e} epoch {ds}/{m}/{key}/fold{k}: cần ~{need:.2f} giờ, còn {args.max_hours - elapsed:.2f} giờ")
                left.append(f"{e}:{ds}:{m}:{key}:{k}")
                continue
            print(f"[BẮT ĐẦU] {e} epoch {ds}/{m}/{key}/fold{k} (ước tính {need:.2f} giờ, đã chạy {elapsed:.2f} giờ)", flush=True)
            res = run_job(ds, m, key, k, seed, data.parts(ds, m, key, k), cache[ds], cfg, device, args.out, e)
            act += res["seconds"]
            pred_sum += est
    if left:
        print(f"CÒN {len(left)} job cho lần chạy sau: {left}")
    else:
        print("HOÀN TẤT các job được yêu cầu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
