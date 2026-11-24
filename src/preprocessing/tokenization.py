from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import torch
except ImportError:
    torch = None

from transformers import RobertaTokenizer

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "tokenization_v1.json"


class TokenizationContractError(RuntimeError):
    """Raised when the frozen tokenization contract is invalid or violated."""


def load_tokenization_config(
    config_path: str | Path = DEFAULT_CONFIG_PATH,
) -> dict[str, Any]:
    """Load and minimally validate the frozen tokenization contract."""
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Tokenization config not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    required_top_level = {
        "schema_version",
        "status",
        "decision_ids",
        "protocol_version",
        "model",
        "input",
        "truncation",
        "padding",
        "attention_mask",
    }
    missing = sorted(required_top_level - set(config))
    if missing:
        raise TokenizationContractError(
            f"Tokenization config missing required keys: {missing}"
        )

    if config["status"] != "FROZEN":
        raise TokenizationContractError(
            f"Expected frozen config, got status={config['status']!r}"
        )

    decision_ids = set(config["decision_ids"])
    required_decisions = {"W3-I005", "W3-I006"}
    if not required_decisions.issubset(decision_ids):
        raise TokenizationContractError(
            "Frozen tokenization config must reference W3-I005 and W3-I006."
        )

    return config


@dataclass(frozen=True)
class EncodedFunction:
    """One unpadded UniXcoder encoder-only input."""

    input_ids: list[int]
    attention_mask: list[int]
    code_token_length_untruncated: int
    code_token_length_used: int
    truncated: bool

    @property
    def sequence_length(self) -> int:
        return len(self.input_ids)


class UniXcoderInputPipeline:
    """
    Frozen Week 3 UniXcoder encoder-only input pipeline.

    Sequence convention:
        <s> <encoder-only> </s> CODE </s>

    W3-I005:
        maximum final sequence length = 768

    W3-I006:
        code-token budget = 764
        right truncation
        right padding
        dynamic per-batch padding
        attention mask excludes padding
    """

    def __init__(
        self,
        config_path: str | Path = DEFAULT_CONFIG_PATH,
    ) -> None:
        self.config_path = Path(config_path)
        self.config = load_tokenization_config(self.config_path)

        model_cfg = self.config["model"]
        input_cfg = self.config["input"]
        trunc_cfg = self.config["truncation"]
        padding_cfg = self.config["padding"]
        mask_cfg = self.config["attention_mask"]

        self.model_name = str(model_cfg["name"])
        self.model_revision = str(model_cfg["revision"])
        self.mode = str(model_cfg["mode"])

        self.canonical_input_field = str(input_cfg["canonical_field"])
        self.max_length = int(input_cfg["max_length"])
        self.special_token_overhead = int(input_cfg["special_token_overhead"])
        self.code_token_budget = int(input_cfg["code_token_budget"])

        self.truncation_enabled = bool(trunc_cfg["enabled"])
        self.truncation_side = str(trunc_cfg["side"])
        self.truncation_policy = str(trunc_cfg["policy"])

        self.padding_side = str(padding_cfg["side"])
        self.padding_strategy = str(padding_cfg["strategy"])
        self.global_pad_to_max_length = bool(
            padding_cfg["global_pad_to_max_length"]
        )

        self.exclude_padding_positions = bool(
            mask_cfg["exclude_padding_positions"]
        )

        self._validate_frozen_values()

        self.tokenizer = RobertaTokenizer.from_pretrained(
            self.model_name,
            revision=self.model_revision,
        )

        # Keep tokenizer metadata aligned with the frozen contract.
        self.tokenizer.padding_side = "right"
        self.tokenizer.truncation_side = "right"

        self.cls_token_id = self._require_token_id(
            self.tokenizer.cls_token, "cls token"
        )
        self.sep_token_id = self._require_token_id(
            self.tokenizer.sep_token, "sep token"
        )
        self.pad_token_id = self._require_token_id(
            self.tokenizer.pad_token, "pad token"
        )
        self.mode_token_id = self._require_token_id(
            self.mode, "encoder-only mode token"
        )

        # The mode token must be a real vocabulary token, not <unk>.
        if (
            self.tokenizer.unk_token_id is not None
            and self.mode_token_id == self.tokenizer.unk_token_id
        ):
            raise TokenizationContractError(
                f"Mode token {self.mode!r} resolved to the unknown token id."
            )

        round_trip_mode = self.tokenizer.convert_ids_to_tokens(
            self.mode_token_id
        )
        if round_trip_mode != self.mode:
            raise TokenizationContractError(
                "Encoder-only mode token does not round-trip through tokenizer: "
                f"{self.mode!r} -> {self.mode_token_id} -> {round_trip_mode!r}"
            )

    def _validate_frozen_values(self) -> None:
        """Fail fast if code/config drift from W3-I005/W3-I006 occurs."""
        expected = {
            "canonical_input_field": "func",
            "max_length": 768,
            "special_token_overhead": 4,
            "code_token_budget": 764,
            "mode": "<encoder-only>",
            "truncation_enabled": True,
            "truncation_side": "right",
            "truncation_policy": "keep_first_code_tokens",
            "padding_side": "right",
            "padding_strategy": "dynamic_longest_in_batch",
            "global_pad_to_max_length": False,
            "exclude_padding_positions": True,
        }
        observed = {
            "canonical_input_field": self.canonical_input_field,
            "max_length": self.max_length,
            "special_token_overhead": self.special_token_overhead,
            "code_token_budget": self.code_token_budget,
            "mode": self.mode,
            "truncation_enabled": self.truncation_enabled,
            "truncation_side": self.truncation_side,
            "truncation_policy": self.truncation_policy,
            "padding_side": self.padding_side,
            "padding_strategy": self.padding_strategy,
            "global_pad_to_max_length": self.global_pad_to_max_length,
            "exclude_padding_positions": self.exclude_padding_positions,
        }

        mismatches = {
            key: (expected[key], observed[key])
            for key in expected
            if expected[key] != observed[key]
        }
        if mismatches:
            raise TokenizationContractError(
                f"Frozen tokenization contract mismatch: {mismatches}"
            )

        if self.code_token_budget + self.special_token_overhead != self.max_length:
            raise TokenizationContractError(
                "code_token_budget + special_token_overhead must equal max_length."
            )

    def _require_token_id(self, token: str | None, label: str) -> int:
        if token is None:
            raise TokenizationContractError(f"Tokenizer has no {label}.")

        token_id = self.tokenizer.convert_tokens_to_ids(token)
        if token_id is None:
            raise TokenizationContractError(
                f"Tokenizer could not resolve {label}: {token!r}"
            )
        return int(token_id)

    def tokenize_code(self, code: str) -> list[str]:
        """Tokenize code without adding model special tokens."""
        if not isinstance(code, str):
            raise TypeError(f"code must be str, got {type(code).__name__}")
        return list(self.tokenizer.tokenize(code))

    def encode_function(self, code: str) -> EncodedFunction:
        """
        Encode one function according to W3-I005/W3-I006.

        No padding is applied here. Padding is deliberately deferred to
        collate_batch() so that it is dynamic per batch.
        """
        code_tokens = self.tokenize_code(code)
        untruncated_length = len(code_tokens)

        code_token_ids = [
            int(token_id)
            for token_id in self.tokenizer.convert_tokens_to_ids(code_tokens)
        ]

        if self.truncation_enabled:
            used_code_token_ids = code_token_ids[: self.code_token_budget]
        else:
            used_code_token_ids = code_token_ids

        truncated = len(used_code_token_ids) < len(code_token_ids)

        input_ids = [
            self.cls_token_id,
            self.mode_token_id,
            self.sep_token_id,
            *used_code_token_ids,
            self.sep_token_id,
        ]

        if len(input_ids) > self.max_length:
            raise TokenizationContractError(
                "Encoded sequence exceeds frozen max_length: "
                f"{len(input_ids)} > {self.max_length}"
            )

        attention_mask = [1] * len(input_ids)

        return EncodedFunction(
            input_ids=input_ids,
            attention_mask=attention_mask,
            code_token_length_untruncated=untruncated_length,
            code_token_length_used=len(used_code_token_ids),
            truncated=truncated,
        )

    def encode_record(self, record: Mapping[str, Any]) -> EncodedFunction:
        """Encode a dataset-like record using the frozen canonical field."""
        if self.canonical_input_field not in record:
            raise KeyError(
                f"Record missing canonical field {self.canonical_input_field!r}"
            )
        return self.encode_function(str(record[self.canonical_input_field]))

    def collate_batch(
        self,
        samples: Sequence[EncodedFunction],
    ) -> dict[str, torch.Tensor]:
        """
        Dynamically right-pad a batch to its longest sequence.

        The batch is never globally padded to max_length=768 unless the
        longest sample in that particular batch is itself length 768.
        """
        if not samples:
            raise ValueError("collate_batch() requires at least one sample.")

        longest = max(sample.sequence_length for sample in samples)
        if longest > self.max_length:
            raise TokenizationContractError(
                f"Batch contains sequence length {longest} > {self.max_length}"
            )

        batch_input_ids: list[list[int]] = []
        batch_attention_masks: list[list[int]] = []

        for sample in samples:
            if len(sample.input_ids) != len(sample.attention_mask):
                raise TokenizationContractError(
                    "input_ids and attention_mask lengths differ before padding."
                )

            pad_count = longest - sample.sequence_length

            padded_ids = sample.input_ids + [self.pad_token_id] * pad_count
            padded_mask = sample.attention_mask + [0] * pad_count

            if len(padded_ids) != longest or len(padded_mask) != longest:
                raise TokenizationContractError(
                    "Dynamic padding produced inconsistent batch length."
                )

            batch_input_ids.append(padded_ids)
            batch_attention_masks.append(padded_mask)

        if torch is None:
            raise ImportError(
                "PyTorch is required for collate_batch() tensor conversion, but torch is not installed."
            )

        return {
            "input_ids": torch.tensor(batch_input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(
                batch_attention_masks, dtype=torch.long
            ),
        }

    def encode_and_collate(
        self,
        codes: Iterable[str],
    ) -> dict[str, torch.Tensor]:
        """Convenience wrapper for encode_function() + collate_batch()."""
        encoded = [self.encode_function(code) for code in codes]
        return self.collate_batch(encoded)
