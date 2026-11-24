from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "dataset_loader_v1.json"

SPECIFIC_CWE_RE = re.compile(r"^CWE-\d+$")


class DatasetLoaderContractError(RuntimeError):
    """Raised when the frozen dataset-loader contract is violated."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DatasetLoaderContractError(message)


def normalize_func(value: str) -> str:
    """
    Frozen exact-identity normalization.

    - CRLF / CR -> LF
    - strip outer whitespace
    """
    if not isinstance(value, str):
        raise TypeError(f"func must be str, got {type(value).__name__}")

    return (
        value
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .strip()
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def is_specific_cwe(value: object) -> bool:
    return bool(SPECIFIC_CWE_RE.fullmatch(str(value)))


def sorted_string_tuple(values: Iterable[object]) -> tuple[str, ...]:
    return tuple(sorted({str(value) for value in values}))


def tuple_column_union(
    frame: pd.DataFrame,
    column: str,
) -> set[str]:
    result: set[str] = set()
    for values in frame[column]:
        result.update(values)
    return result


def tuple_intersects(
    values: tuple[str, ...],
    reference: set[str],
) -> bool:
    return bool(set(values) & reference)


def load_dataset_loader_config(
    config_path: str | Path = DEFAULT_CONFIG_PATH,
) -> dict[str, Any]:
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"Dataset-loader config not found: {path}"
        )

    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    required_top_level = {
        "schema_version",
        "status",
        "decision_ids",
        "protocol_version",
        "canonical_input_field",
        "raw_main_files",
        "clean_model_unit",
        "tracks",
        "target_test_governance",
        "near_duplicate_status",
        "fail_closed_on_invariant_violation",
    }
    missing = sorted(required_top_level - set(config))
    if missing:
        raise DatasetLoaderContractError(
            f"Config missing required keys: {missing}"
        )

    _require(
        config["status"] == "FROZEN",
        f"Expected FROZEN config, got {config['status']!r}",
    )

    decisions = set(config["decision_ids"])
    _require(
        {"W3-I007", "W3-I008"}.issubset(decisions),
        "Config must reference W3-I007 and W3-I008.",
    )

    _require(
        config["protocol_version"] == "v1",
        "Dataset loader must remain bound to Protocol v1.",
    )

    return config


@dataclass(frozen=True)
class DatasetPopulation:
    """One training/evaluation population returned by the frozen loader."""

    track: str
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame
    target_language: str | None = None

    def counts(self) -> dict[str, int]:
        return {
            "train": len(self.train),
            "validation": len(self.validation),
            "test": len(self.test),
        }


class MVDDatasetLoader:
    """
    Reusable implementation of W3-I007 / W3-I008.

    Training code should consume populations from this class instead of
    independently reimplementing split or decontamination logic.
    """

    LANGUAGE_ORDER = (
        "C",
        "C#",
        "C++",
        "Go",
        "Java",
        "JavaScript",
        "Python",
    )

    def __init__(
        self,
        config_path: str | Path = DEFAULT_CONFIG_PATH,
    ) -> None:
        self.config_path = Path(config_path)
        self.config = load_dataset_loader_config(
            self.config_path
        )
        self._validate_frozen_contract()

        raw_files = self.config["raw_main_files"]
        self.raw_paths = {
            split: REPO_ROOT / relative_path
            for split, relative_path in raw_files.items()
        }

        self._raw_cache: pd.DataFrame | None = None
        self._clean_cache: pd.DataFrame | None = None

    def _validate_frozen_contract(self) -> None:
        config = self.config
        clean_cfg = config["clean_model_unit"]
        identity_cfg = clean_cfg["identity"]
        representative_cfg = clean_cfg["representative_row"]
        metadata_cfg = clean_cfg["metadata"]
        tracks = config["tracks"]

        expected_raw_files = {
            "train": "data/raw/train_w_line.csv",
            "validation": "data/raw/val_w_line.csv",
            "test": "data/raw/test_w_line.csv",
        }

        _require(
            config["canonical_input_field"] == "func",
            "Canonical input field must be func.",
        )
        _require(
            config["raw_main_files"] == expected_raw_files,
            "Raw main-file mapping drifted from W3-I008.",
        )

        _require(
            identity_cfg["field"] == "func",
            "Exact identity must be computed from func.",
        )
        _require(
            identity_cfg["newline_normalization"]
            == "CRLF_and_CR_to_LF",
            "Unexpected newline-normalization policy.",
        )
        _require(
            identity_cfg["outer_whitespace"] == "strip",
            "Unexpected outer-whitespace policy.",
        )
        _require(
            identity_cfg["hash"] == "sha256_utf8",
            "Unexpected exact-identity hash policy.",
        )

        _require(
            clean_cfg["exclude_whole_hash_group_if"]
            == [
                "conflicting_target",
                "cross_language_exact_identity",
            ],
            "Unexpected clean exact-hash exclusion policy.",
        )
        _require(
            clean_cfg["effective_split_precedence"]
            == ["train", "validation", "test"],
            "Unexpected effective-split precedence.",
        )
        _require(
            clean_cfg["effective_split_selection"]
            == "highest_precedence",
            "Unexpected effective-split selection rule.",
        )
        _require(
            clean_cfg["max_model_units_per_hash"] == 1,
            "Each retained hash must contribute at most one model unit.",
        )

        _require(
            representative_cfg["scope"]
            == "effective_split_occurrences",
            "Representative row must be selected within effective split.",
        )
        _require(
            representative_cfg["tie_breaker"]
            == "smallest_string_valued_id",
            "Unexpected representative-row tie breaker.",
        )
        _require(
            representative_cfg["purpose"]
            == ["representative_id", "func"],
            "Representative row purpose drifted.",
        )

        _require(
            metadata_cfg["language"]
            == "must_be_unique_per_retained_hash",
            "Language aggregation contract drifted.",
        )
        _require(
            metadata_cfg["target"]
            == "must_be_unique_per_retained_hash",
            "Target aggregation contract drifted.",
        )
        _require(
            metadata_cfg["effective_specific_cwes"]
            == "sorted_union_within_effective_split_specific_CWE_values",
            "CWE aggregation contract drifted.",
        )
        _require(
            metadata_cfg["all_cves"]
            == "sorted_union_over_all_original_occurrences",
            "CVE aggregation contract drifted.",
        )
        _require(
            metadata_cfg["all_projects"]
            == "sorted_union_over_all_original_occurrences",
            "Project aggregation contract drifted.",
        )

        required_tracks = {
            "PREDEFINED_BENCHMARK",
            "CLEAN_EXACT_HASH",
            "CLEAN_STRICT_LOLO",
        }
        _require(
            set(tracks) == required_tracks,
            "Dataset-loader track set drifted from W3-I008.",
        )

        _require(
            tracks["CLEAN_STRICT_LOLO"]["project_policy"]
            == "verify_zero_overlap_fail_closed_no_new_filter",
            "Strict-LOLO project policy drifted.",
        )
        _require(
            config["near_duplicate_status"] == "NOT_ASSESSED",
            "Near-duplicate status must remain NOT_ASSESSED.",
        )
        _require(
            config["fail_closed_on_invariant_violation"] is True,
            "Loader must fail closed on invariant violations.",
        )

    @property
    def split_precedence(self) -> Mapping[str, int]:
        ordered = self.config[
            "clean_model_unit"
        ]["effective_split_precedence"]
        return {
            split: index
            for index, split in enumerate(ordered)
        }

    def load_raw(self, *, copy: bool = True) -> pd.DataFrame:
        """
        Load the three main function-level MVD CSVs.

        Returned rows retain original dataset fields and gain:
        - split
        - source_row_index
        - normalized_func
        - func_hash
        """
        if self._raw_cache is None:
            frames: list[pd.DataFrame] = []

            for split in ("train", "validation", "test"):
                path = self.raw_paths[split]
                if not path.is_file():
                    raise FileNotFoundError(
                        f"Missing required raw dataset file: {path}"
                    )

                frame = pd.read_csv(path)

                required_columns = {
                    "id",
                    "language",
                    "CWE",
                    "cve_id",
                    "func",
                    "target",
                    "project",
                }
                missing = sorted(
                    required_columns - set(frame.columns)
                )
                if missing:
                    raise DatasetLoaderContractError(
                        f"{path.name} missing required columns: {missing}"
                    )

                if frame["func"].isna().any():
                    raise DatasetLoaderContractError(
                        f"{path.name} contains missing func values."
                    )

                frame = frame.copy()
                frame["split"] = split
                frame["source_row_index"] = range(len(frame))
                frames.append(frame)

            raw = pd.concat(
                frames,
                ignore_index=True,
            )

            if raw["id"].astype(str).duplicated().any():
                raise DatasetLoaderContractError(
                    "Raw id values are not globally unique."
                )

            raw["normalized_func"] = raw["func"].map(
                normalize_func
            )
            raw["func_hash"] = raw["normalized_func"].map(
                sha256_text
            )

            expected_raw_rows = int(
                self.config[
                    "clean_model_unit"
                ]["references"]["raw_rows"]
            )
            _require(
                len(raw) == expected_raw_rows,
                (
                    "Raw row-count drift: "
                    f"expected={expected_raw_rows}, "
                    f"actual={len(raw)}"
                ),
            )

            self._raw_cache = raw

        return (
            self._raw_cache.copy(deep=True)
            if copy
            else self._raw_cache
        )

    def predefined_benchmark(self) -> DatasetPopulation:
        """
        Preserve original rows and original predefined split.

        This track remains secondary benchmark-comparable and is not
        exact/CVE/project disjoint.
        """
        raw = self.load_raw(copy=True)

        return DatasetPopulation(
            track="PREDEFINED_BENCHMARK",
            train=raw[raw["split"].eq("train")].copy(),
            validation=raw[
                raw["split"].eq("validation")
            ].copy(),
            test=raw[raw["split"].eq("test")].copy(),
        )

    def clean_exact_hash(
        self,
        *,
        copy: bool = True,
    ) -> pd.DataFrame:
        """
        Build W3-I007 clean exact-hash model units.

        Important:
        - representative row supplies raw func only;
        - provenance is aggregated across all original occurrences;
        - CWE membership is aggregated within the effective split.
        """
        if self._clean_cache is None:
            raw = self.load_raw(copy=False)

            grouped = raw.groupby(
                "func_hash",
                sort=True,
            )

            conflicting_hashes = {
                func_hash
                for func_hash, group in grouped
                if group["target"].astype(int).nunique() > 1
            }

            cross_language_hashes = {
                func_hash
                for func_hash, group in grouped
                if group["language"].astype(str).nunique() > 1
            }

            excluded_hashes = (
                conflicting_hashes
                | cross_language_hashes
            )

            eligible = raw[
                ~raw["func_hash"].isin(excluded_hashes)
            ].copy()

            rows: list[dict[str, object]] = []
            precedence = self.split_precedence

            for func_hash, group in eligible.groupby(
                "func_hash",
                sort=True,
            ):
                languages = (
                    group["language"]
                    .astype(str)
                    .unique()
                    .tolist()
                )
                targets = (
                    group["target"]
                    .astype(int)
                    .unique()
                    .tolist()
                )

                _require(
                    len(languages) == 1,
                    (
                        "Retained hash has multiple languages: "
                        f"{func_hash}"
                    ),
                )
                _require(
                    len(targets) == 1,
                    (
                        "Retained hash has conflicting targets: "
                        f"{func_hash}"
                    ),
                )

                effective_split = max(
                    group["split"]
                    .astype(str)
                    .unique()
                    .tolist(),
                    key=lambda value: precedence[value],
                )

                effective = group[
                    group["split"].eq(effective_split)
                ].copy()

                raw_func_variants = int(
                    effective["func"]
                    .astype(str)
                    .nunique()
                )
                _require(
                    raw_func_variants == 1,
                    (
                        "Representative raw func is ambiguous "
                        f"for hash {func_hash}: "
                        f"{raw_func_variants} variants"
                    ),
                )

                effective = effective.assign(
                    _id_string=effective["id"].astype(str)
                )
                representative = (
                    effective
                    .sort_values(
                        by=[
                            "_id_string",
                            "source_row_index",
                        ],
                        kind="mergesort",
                    )
                    .iloc[0]
                )

                effective_specific_cwes = (
                    sorted_string_tuple(
                        value
                        for value in effective["CWE"]
                        if is_specific_cwe(value)
                    )
                )
                all_cves = sorted_string_tuple(
                    group["cve_id"]
                )
                all_projects = sorted_string_tuple(
                    group["project"]
                )

                rows.append(
                    {
                        "unit_id": func_hash,
                        "representative_id": str(
                            representative["id"]
                        ),
                        "func_hash": func_hash,
                        "func": str(representative["func"]),
                        "split": effective_split,
                        "language": languages[0],
                        "target": int(targets[0]),
                        "effective_specific_cwes":
                            effective_specific_cwes,
                        "all_cves": all_cves,
                        "all_projects": all_projects,
                        "effective_occurrence_count": len(effective),
                    }
                )

            clean = pd.DataFrame(rows)

            references = self.config[
                "clean_model_unit"
            ]["references"]

            _require(
                len(clean) == int(references["clean_units"]),
                (
                    "Clean model-unit count drift: "
                    f"expected={references['clean_units']}, "
                    f"actual={len(clean)}"
                ),
            )
            _require(
                clean["unit_id"].is_unique,
                "Clean model-unit IDs are not unique.",
            )
            _require(
                clean["func_hash"].is_unique,
                "Clean func hashes are not unique.",
            )

            required_fields = set(
                self.config[
                    "clean_model_unit"
                ]["required_fields"]
            )
            missing_fields = sorted(
                required_fields - set(clean.columns)
            )
            _require(
                not missing_fields,
                (
                    "Clean model-unit output missing fields: "
                    f"{missing_fields}"
                ),
            )

            self._clean_cache = clean

        return (
            self._clean_cache.copy(deep=True)
            if copy
            else self._clean_cache
        )

    def clean_exact_hash_population(
        self,
    ) -> DatasetPopulation:
        clean = self.clean_exact_hash(copy=True)

        return DatasetPopulation(
            track="CLEAN_EXACT_HASH",
            train=clean[
                clean["split"].eq("train")
            ].copy(),
            validation=clean[
                clean["split"].eq("validation")
            ].copy(),
            test=clean[
                clean["split"].eq("test")
            ].copy(),
        )

    def _validate_target_language(
        self,
        target_language: str,
    ) -> None:
        if target_language not in self.LANGUAGE_ORDER:
            raise ValueError(
                "Unsupported target language "
                f"{target_language!r}; expected one of "
                f"{self.LANGUAGE_ORDER}"
            )

    def mono(
        self,
        target_language: str,
    ) -> DatasetPopulation:
        """
        Primary RQ1 CLEAN_EXACT_HASH Mono(L) population.
        """
        self._validate_target_language(target_language)

        clean = self.clean_exact_hash(copy=True)

        return DatasetPopulation(
            track="CLEAN_EXACT_HASH_MONO",
            target_language=target_language,
            train=clean[
                clean["split"].eq("train")
                & clean["language"].eq(target_language)
            ].copy(),
            validation=clean[
                clean["split"].eq("validation")
                & clean["language"].eq(target_language)
            ].copy(),
            test=clean[
                clean["split"].eq("test")
                & clean["language"].eq(target_language)
            ].copy(),
        )

    def multi(
        self,
        target_language: str,
    ) -> DatasetPopulation:
        """
        Primary RQ2 Multi population.

        Train/validation use all seven clean languages.
        Test(L) is exactly the clean target-language test population.
        """
        self._validate_target_language(target_language)

        clean = self.clean_exact_hash(copy=True)

        return DatasetPopulation(
            track="CLEAN_EXACT_HASH_MULTI",
            target_language=target_language,
            train=clean[
                clean["split"].eq("train")
            ].copy(),
            validation=clean[
                clean["split"].eq("validation")
            ].copy(),
            test=clean[
                clean["split"].eq("test")
                & clean["language"].eq(target_language)
            ].copy(),
        )

    def strict_lolo(
        self,
        target_language: str,
    ) -> DatasetPopulation:
        """
        Primary RQ3 CLEAN_STRICT_LOLO population.

        Target-test metadata is used only for the pre-specified
        decontamination construction and invariant verification.
        No target-test model outcomes are accessed here.
        """
        self._validate_target_language(target_language)

        clean = self.clean_exact_hash(copy=True)

        target_test = clean[
            clean["split"].eq("test")
            & clean["language"].eq(target_language)
        ].copy()

        _require(
            len(target_test) > 0,
            (
                "Target test is empty for language "
                f"{target_language}"
            ),
        )

        target_hashes = set(
            target_test["func_hash"].astype(str)
        )
        target_cves = tuple_column_union(
            target_test,
            "all_cves",
        )
        target_projects = tuple_column_union(
            target_test,
            "all_projects",
        )

        source_base = clean[
            clean["split"].isin(
                ["train", "validation"]
            )
            & ~clean["language"].eq(target_language)
        ].copy()

        after_exact = source_base[
            ~source_base["func_hash"].isin(target_hashes)
        ].copy()

        cve_overlap_mask = after_exact[
            "all_cves"
        ].map(
            lambda values: tuple_intersects(
                values,
                target_cves,
            )
        )

        strict_source = after_exact[
            ~cve_overlap_mask
        ].copy()

        source_target_language_count = int(
            strict_source["language"]
            .eq(target_language)
            .sum()
        )
        exact_overlap = len(
            set(
                strict_source["func_hash"]
                .astype(str)
                .tolist()
            )
            & target_hashes
        )
        cve_overlap = len(
            tuple_column_union(
                strict_source,
                "all_cves",
            )
            & target_cves
        )
        project_overlap = len(
            tuple_column_union(
                strict_source,
                "all_projects",
            )
            & target_projects
        )

        _require(
            source_target_language_count == 0,
            (
                "Strict LOLO source still contains target "
                f"language {target_language}."
            ),
        )
        _require(
            exact_overlap == 0,
            (
                "Strict LOLO source still overlaps target-test "
                f"exact hashes for {target_language}."
            ),
        )
        _require(
            cve_overlap == 0,
            (
                "Strict LOLO source still overlaps target-test "
                f"CVE provenance for {target_language}."
            ),
        )

        # D-011 / W3-I008:
        # project overlap is verified, not silently repaired.
        _require(
            project_overlap == 0,
            (
                "Strict LOLO project-disjoint invariant failed "
                f"for {target_language}: overlap={project_overlap}. "
                "Failing closed; no implicit project filter applied."
            ),
        )

        return DatasetPopulation(
            track="CLEAN_STRICT_LOLO",
            target_language=target_language,
            train=strict_source[
                strict_source["split"].eq("train")
            ].copy(),
            validation=strict_source[
                strict_source["split"].eq("validation")
            ].copy(),
            test=target_test,
        )
