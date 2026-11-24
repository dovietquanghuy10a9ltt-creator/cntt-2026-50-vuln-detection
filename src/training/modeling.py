from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import nn
from transformers import AutoModel


class TrainingModelContractError(RuntimeError):
    """Raised when the frozen Week 3 model-adaptation contract is violated."""


@dataclass(frozen=True)
class ModelIdentity:
    name: str
    revision: str
    hidden_size: int
    num_labels: int


class UniXcoderBinaryClassifier(nn.Module):
    """
    W3-I009 implementation:
        UniXcoder final hidden states
        -> attention-mask mean pooling
        -> Linear(hidden_size -> 2)

    The pretrained encoder is fully fine-tuned. No extra MLP or task-head
    dropout is introduced here.
    """

    def __init__(
        self,
        model_name: str,
        revision: str,
        expected_hidden_size: int = 768,
        num_labels: int = 2,
    ) -> None:
        super().__init__()

        if num_labels != 2:
            raise TrainingModelContractError(
                f"Binary classifier requires num_labels=2, got {num_labels}."
            )

        self.encoder = AutoModel.from_pretrained(
            model_name,
            revision=revision,
        )

        hidden_size = int(self.encoder.config.hidden_size)
        if hidden_size != expected_hidden_size:
            raise TrainingModelContractError(
                "Pinned encoder hidden size drifted: "
                f"expected={expected_hidden_size}, observed={hidden_size}"
            )

        self.classifier = nn.Linear(hidden_size, num_labels)

        self.identity = ModelIdentity(
            name=model_name,
            revision=revision,
            hidden_size=hidden_size,
            num_labels=num_labels,
        )

        # Full fine-tuning is part of W3-I009.
        if not all(parameter.requires_grad for parameter in self.encoder.parameters()):
            raise TrainingModelContractError(
                "All encoder parameters must remain trainable for full fine-tuning."
            )

    @staticmethod
    def attention_mask_mean_pool(
        last_hidden_state: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        if last_hidden_state.ndim != 3:
            raise TrainingModelContractError(
                "last_hidden_state must have shape [batch, seq, hidden]."
            )
        if attention_mask.ndim != 2:
            raise TrainingModelContractError(
                "attention_mask must have shape [batch, seq]."
            )
        if last_hidden_state.shape[:2] != attention_mask.shape:
            raise TrainingModelContractError(
                "Hidden-state and attention-mask batch/sequence dimensions differ."
            )

        mask = attention_mask.unsqueeze(-1).to(dtype=last_hidden_state.dtype)
        denominator = mask.sum(dim=1).clamp_min(1.0)
        return (last_hidden_state * mask).sum(dim=1) / denominator

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        outputs = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict=True,
        )
        pooled = self.attention_mask_mean_pool(
            outputs.last_hidden_state,
            attention_mask,
        )
        return self.classifier(pooled)
