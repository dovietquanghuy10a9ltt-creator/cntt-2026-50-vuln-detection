from __future__ import annotations

import json
import math
import random
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset

from src.preprocessing.tokenization import EncodedFunction, UniXcoderInputPipeline


class TrainingEngineContractError(RuntimeError):
    """Raised when Training Pilot v1 execution semantics are violated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TrainingEngineContractError(message)


def set_global_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


@dataclass(frozen=True)
class EncodedPilotRecord:
    encoded: EncodedFunction
    label: int
    language: str
    unit_id: str


class EncodedPilotDataset(Dataset[EncodedPilotRecord]):
    def __init__(self, records: Sequence[EncodedPilotRecord]) -> None:
        self._records = list(records)

    def __len__(self) -> int:
        return len(self._records)

    def __getitem__(self, index: int) -> EncodedPilotRecord:
        return self._records[index]


class PilotBatchCollator:
    def __init__(self, pipeline: UniXcoderInputPipeline) -> None:
        self.pipeline = pipeline

    def __call__(self, records: Sequence[EncodedPilotRecord]) -> dict:
        require(len(records) > 0, "Cannot collate an empty batch.")

        encoded = [record.encoded for record in records]
        batch = self.pipeline.collate_batch(encoded)

        batch["labels"] = torch.tensor(
            [record.label for record in records],
            dtype=torch.long,
        )
        batch["languages"] = [record.language for record in records]
        batch["unit_ids"] = [record.unit_id for record in records]
        return batch


def preencode_frame(
    frame,
    pipeline: UniXcoderInputPipeline,
) -> EncodedPilotDataset:
    required_columns = {"unit_id", "func", "language", "target"}
    missing = required_columns.difference(frame.columns)
    require(
        not missing,
        f"Pilot frame missing required columns: {sorted(missing)}",
    )

    records: list[EncodedPilotRecord] = []
    for row in frame.itertuples(index=False):
        label = int(row.target)
        require(label in (0, 1), f"Unexpected binary label: {label}")

        records.append(
            EncodedPilotRecord(
                encoded=pipeline.encode_function(str(row.func)),
                label=label,
                language=str(row.language),
                unit_id=str(row.unit_id),
            )
        )

    return EncodedPilotDataset(records)


def build_train_loader(
    dataset: EncodedPilotDataset,
    collator: PilotBatchCollator,
    batch_size: int,
    seed: int,
) -> DataLoader:
    require(batch_size > 0, "batch_size must be positive.")

    generator = torch.Generator()
    generator.manual_seed(seed)

    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        drop_last=False,
        num_workers=0,
        pin_memory=torch.cuda.is_available(),
        collate_fn=collator,
        generator=generator,
    )


def build_validation_loader(
    dataset: EncodedPilotDataset,
    collator: PilotBatchCollator,
    batch_size: int,
) -> DataLoader:
    require(batch_size > 0, "batch_size must be positive.")

    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=False,
        drop_last=False,
        num_workers=0,
        pin_memory=torch.cuda.is_available(),
        collate_fn=collator,
    )


@dataclass(frozen=True)
class LanguageMetrics:
    language: str
    support: int
    target0: int
    target1: int
    tp: int
    tn: int
    fp: int
    fn: int
    precision_vulnerable: float
    recall_vulnerable: float
    f1_vulnerable: float
    accuracy: float


@dataclass(frozen=True)
class EvaluationResult:
    validation_loss: float
    equal_weight_language_mean_f1: float
    per_language: tuple[LanguageMetrics, ...]


@dataclass(frozen=True)
class EpochResult:
    learning_rate: float
    epoch: int
    train_loss: float
    validation_loss: float
    checkpoint_score: float
    per_language: tuple[LanguageMetrics, ...]


@dataclass(frozen=True)
class CandidateSelection:
    learning_rate: float
    selected_epoch: int
    selected_score: float


@dataclass(frozen=True)
class PilotSelection:
    learning_rate: float
    selected_epoch: int
    selected_score: float
    budget_boundary_hit: bool


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator / denominator)


def _language_metrics(
    labels: Sequence[int],
    predictions: Sequence[int],
    languages: Sequence[str],
    expected_languages: Sequence[str],
) -> tuple[LanguageMetrics, ...]:
    require(
        len(labels) == len(predictions) == len(languages),
        "labels/predictions/languages length mismatch.",
    )

    result: list[LanguageMetrics] = []

    for language in expected_languages:
        pairs = [
            (int(label), int(prediction))
            for label, prediction, observed_language in zip(
                labels, predictions, languages
            )
            if observed_language == language
        ]

        require(
            len(pairs) > 0,
            f"Validation language missing from evaluation: {language}",
        )

        target0 = sum(label == 0 for label, _ in pairs)
        target1 = sum(label == 1 for label, _ in pairs)
        tp = sum(label == 1 and prediction == 1 for label, prediction in pairs)
        tn = sum(label == 0 and prediction == 0 for label, prediction in pairs)
        fp = sum(label == 0 and prediction == 1 for label, prediction in pairs)
        fn = sum(label == 1 and prediction == 0 for label, prediction in pairs)

        precision = _safe_ratio(tp, tp + fp)
        recall = _safe_ratio(tp, tp + fn)
        f1 = _safe_ratio(2 * tp, 2 * tp + fp + fn)
        accuracy = _safe_ratio(tp + tn, len(pairs))

        result.append(
            LanguageMetrics(
                language=language,
                support=len(pairs),
                target0=target0,
                target1=target1,
                tp=tp,
                tn=tn,
                fp=fp,
                fn=fn,
                precision_vulnerable=precision,
                recall_vulnerable=recall,
                f1_vulnerable=f1,
                accuracy=accuracy,
            )
        )

    return tuple(result)


def train_one_epoch(
    model: nn.Module,
    data_loader: DataLoader,
    optimizer: torch.optim.Optimizer,
    scheduler,
    criterion: nn.Module,
    device: torch.device,
    gradient_accumulation_steps: int,
    gradient_clipping_max_norm: float,
) -> float:
    require(
        gradient_accumulation_steps >= 1,
        "gradient_accumulation_steps must be >= 1.",
    )
    require(
        gradient_clipping_max_norm > 0,
        "gradient_clipping_max_norm must be positive.",
    )

    model.train()
    optimizer.zero_grad(set_to_none=True)

    running_loss_sum = 0.0
    observed_examples = 0

    for batch_index, batch in enumerate(data_loader, start=1):
        input_ids = batch["input_ids"].to(device, non_blocking=True)
        attention_mask = batch["attention_mask"].to(device, non_blocking=True)
        labels = batch["labels"].to(device, non_blocking=True)

        logits = model(
            input_ids=input_ids,
            attention_mask=attention_mask,
        )
        loss = criterion(logits, labels)

        batch_size = int(labels.shape[0])
        running_loss_sum += float(loss.detach().item()) * batch_size
        observed_examples += batch_size

        scaled_loss = loss / gradient_accumulation_steps
        scaled_loss.backward()

        should_step = (
            batch_index % gradient_accumulation_steps == 0
            or batch_index == len(data_loader)
        )

        if should_step:
            torch.nn.utils.clip_grad_norm_(
                model.parameters(),
                max_norm=gradient_clipping_max_norm,
            )
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad(set_to_none=True)

    require(observed_examples > 0, "Training loader produced zero examples.")
    return running_loss_sum / observed_examples


@torch.inference_mode()
def evaluate(
    model: nn.Module,
    data_loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
    expected_languages: Sequence[str],
) -> EvaluationResult:
    model.eval()

    loss_sum = 0.0
    observed_examples = 0
    all_labels: list[int] = []
    all_predictions: list[int] = []
    all_languages: list[str] = []

    for batch in data_loader:
        input_ids = batch["input_ids"].to(device, non_blocking=True)
        attention_mask = batch["attention_mask"].to(device, non_blocking=True)
        labels = batch["labels"].to(device, non_blocking=True)

        logits = model(
            input_ids=input_ids,
            attention_mask=attention_mask,
        )
        loss = criterion(logits, labels)

        predictions = logits.argmax(dim=-1)

        batch_size = int(labels.shape[0])
        loss_sum += float(loss.item()) * batch_size
        observed_examples += batch_size

        all_labels.extend(labels.detach().cpu().tolist())
        all_predictions.extend(predictions.detach().cpu().tolist())
        all_languages.extend(batch["languages"])

    require(observed_examples > 0, "Validation loader produced zero examples.")

    per_language = _language_metrics(
        labels=all_labels,
        predictions=all_predictions,
        languages=all_languages,
        expected_languages=expected_languages,
    )

    score = float(
        sum(metric.f1_vulnerable for metric in per_language)
        / len(per_language)
    )

    return EvaluationResult(
        validation_loss=loss_sum / observed_examples,
        equal_weight_language_mean_f1=score,
        per_language=per_language,
    )


def select_best_epoch(
    epoch_results: Sequence[EpochResult],
) -> CandidateSelection:
    require(len(epoch_results) > 0, "No epoch results supplied.")

    learning_rates = {float(result.learning_rate) for result in epoch_results}
    require(
        len(learning_rates) == 1,
        "select_best_epoch requires results from exactly one learning rate.",
    )

    # max() over (-epoch) enforces earliest epoch on an exact score tie.
    best = max(
        epoch_results,
        key=lambda result: (
            float(result.checkpoint_score),
            -int(result.epoch),
        ),
    )

    return CandidateSelection(
        learning_rate=float(best.learning_rate),
        selected_epoch=int(best.epoch),
        selected_score=float(best.checkpoint_score),
    )


def select_best_learning_rate(
    candidates: Sequence[CandidateSelection],
    boundary_epoch: int,
) -> PilotSelection:
    require(len(candidates) > 0, "No candidate selections supplied.")

    # Higher score wins. On an exact score tie, smaller LR wins.
    best = max(
        candidates,
        key=lambda candidate: (
            float(candidate.selected_score),
            -float(candidate.learning_rate),
        ),
    )

    return PilotSelection(
        learning_rate=float(best.learning_rate),
        selected_epoch=int(best.selected_epoch),
        selected_score=float(best.selected_score),
        budget_boundary_hit=int(best.selected_epoch) == int(boundary_epoch),
    )


def optimizer_step_count(
    train_loader_length: int,
    gradient_accumulation_steps: int,
    max_epochs: int,
) -> int:
    require(train_loader_length > 0, "train_loader_length must be positive.")
    require(
        gradient_accumulation_steps >= 1,
        "gradient_accumulation_steps must be >= 1.",
    )
    require(max_epochs >= 1, "max_epochs must be >= 1.")

    updates_per_epoch = math.ceil(
        train_loader_length / gradient_accumulation_steps
    )
    return updates_per_epoch * max_epochs


def warmup_step_count(
    total_optimizer_steps: int,
    warmup_ratio: float,
) -> int:
    require(total_optimizer_steps > 0, "total_optimizer_steps must be positive.")
    require(
        0.0 <= warmup_ratio < 1.0,
        "warmup_ratio must satisfy 0 <= ratio < 1.",
    )

    # Deterministic implementation of the frozen ratio:
    # floor(total optimizer steps × warmup ratio).
    return int(total_optimizer_steps * warmup_ratio)


def epoch_result_to_jsonable(result: EpochResult) -> dict:
    payload = {
        "learning_rate": result.learning_rate,
        "epoch": result.epoch,
        "train_loss": result.train_loss,
        "validation_loss": result.validation_loss,
        "checkpoint_score": result.checkpoint_score,
        "per_language": [asdict(metric) for metric in result.per_language],
    }
    return payload


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
