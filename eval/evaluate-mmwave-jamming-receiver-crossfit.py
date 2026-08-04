#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///
"""Evaluate a fixed jamming baseline with receiver-held-out cross-fitting."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "netbraid.mmwave_jamming_receiver_crossfit_eval.v0"
POLICY_SCHEMA = "netbraid.mmwave_jamming_receiver_crossfit_policy.v0"
ORACLE_SCHEMA = "netbraid.mmwave_jamming_observation_oracles.v0"
ADAPTER_SCHEMA = "netbraid.mmwave_jamming_paired_grid_cache.v0"
CAUSES = ("controlled_jammer_absent", "controlled_jammer_present")
FEATURE_NAMES = (
    "log_mean_power",
    "power_coefficient_of_variation",
    "adc_sample_axis_power_dispersion",
    "chirp_axis_power_dispersion",
    "frame_axis_power_dispersion",
)
EXPECTED_GRID_SHAPE = (16, 16, 8, 2)
EXPECTED_OBSERVATIONS = 80
EXPECTED_PAIRS = 40
EXPECTED_RECEIVERS = 4
MAX_JSON_BYTES = 512 * 1024
READ_CHUNK_BYTES = 1024**2
FORBIDDEN_REPORT_KEYS = {
    "path",
    "source_path",
    "filename",
    "filenames",
    "receiver_element",
    "receiver_group",
    "paired_cell_group",
    "observation_id",
}


class CrossfitError(RuntimeError):
    """Stable fail-closed rejection at the evaluation boundary."""


@dataclass(frozen=True)
class Observation:
    observation_id: str
    cause: str
    receiver_group: str
    configuration_group: str
    pair_group: str
    row: int
    features: tuple[float, ...]


@dataclass(frozen=True)
class FittedModel:
    active: tuple[int, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    centroids: Mapping[str, tuple[float, ...]]


@dataclass(frozen=True)
class Prediction:
    observation: Observation
    score: float
    predicted: str


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CrossfitError("duplicate_json_key")
        value[key] = item
    return value


def _read_regular_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum_bytes
        ):
            raise CrossfitError("json_missing_or_unsafe")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
    except CrossfitError:
        raise
    except OSError as error:
        raise CrossfitError("json_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity[:3] != (metadata.st_dev, metadata.st_ino, metadata.st_size):
            raise CrossfitError("json_changed_before_read")
        chunks: list[bytes] = []
        byte_count = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes + 1))
            if not chunk:
                break
            chunks.append(chunk)
            byte_count += len(chunk)
            if byte_count > maximum_bytes:
                raise CrossfitError("json_byte_limit")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity:
            raise CrossfitError("json_changed_during_read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def read_json_payload(
    path: Path, *, maximum_bytes: int = MAX_JSON_BYTES
) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_bytes(path, maximum_bytes=maximum_bytes)
    if not raw:
        raise CrossfitError("json_missing_or_unsafe")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CrossfitError("json_parse_failed") from error
    if not isinstance(value, dict):
        raise CrossfitError("json_root_not_object")
    return value, raw


def read_json(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    value, _raw = read_json_payload(path, maximum_bytes=maximum_bytes)
    return value


def _sha256_path(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise CrossfitError("matrix_missing_or_unsafe")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CrossfitError("matrix_open_failed") from error
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity[:3] != (metadata.st_dev, metadata.st_ino, metadata.st_size):
            raise CrossfitError("matrix_changed_before_read")
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity:
            raise CrossfitError("matrix_changed_during_read")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), byte_count


def _known_group(value: Any, code: str) -> str:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"state", "group_id"}
        or value.get("state") != "known"
        or not isinstance(value.get("group_id"), str)
        or len(value["group_id"]) != 64
    ):
        raise CrossfitError(code)
    return value["group_id"]


def validate_policy(policy: Mapping[str, Any]) -> None:
    expected_keys = {
        "campaign_id",
        "feature_policy",
        "limitations",
        "model",
        "preregistration",
        "primary_gate",
        "reporting",
        "schema",
        "split_policy",
        "target",
    }
    if set(policy) != expected_keys or policy.get("schema") != POLICY_SCHEMA:
        raise CrossfitError("policy_schema_mismatch")
    feature = policy.get("feature_policy")
    split = policy.get("split_policy")
    target = policy.get("target")
    model = policy.get("model")
    gate = policy.get("primary_gate")
    preregistration = policy.get("preregistration")
    reporting = policy.get("reporting")
    if (
        not isinstance(feature, Mapping)
        or set(feature)
        != {
            "components",
            "features",
            "fit",
            "grid_shape",
            "metadata_features",
            "power",
            "zero_variance_features",
        }
        or feature.get("features") != list(FEATURE_NAMES)
        or feature.get("grid_shape") != list(EXPECTED_GRID_SHAPE)
        or feature.get("metadata_features") is not False
        or not isinstance(split, Mapping)
        or set(split)
        != {
            "folds",
            "pair_group_atomic",
            "test_group",
            "test_receivers_per_fold",
            "train_receivers_per_fold",
            "use_each_receiver_once_for_test",
            "validation_or_calibration_roles",
        }
        or split.get("folds") != EXPECTED_RECEIVERS
        or split.get("test_group") != "receiver_group"
        or split.get("pair_group_atomic") is not True
        or split.get("train_receivers_per_fold") != 3
        or split.get("test_receivers_per_fold") != 1
        or split.get("validation_or_calibration_roles") is not False
        or not isinstance(target, Mapping)
        or set(target) != {"classes", "field"}
        or target.get("field") != "controlled_jamming_cause"
        or target.get("classes") != list(CAUSES)
        or not isinstance(model, Mapping)
        or set(model)
        != {
            "classifier",
            "distance",
            "hyperparameter_search",
            "score",
            "threshold",
            "tie_policy",
        }
        or model.get("hyperparameter_search") is not False
        or model.get("threshold") != 0.0
        or not isinstance(gate, Mapping)
        or set(gate)
        != {
            "direction",
            "exact_test",
            "minimum_non_tied_pairs",
            "p_value_at_most",
            "wins_strictly_greater_than_losses",
        }
        or gate.get("minimum_non_tied_pairs") != 36
        or gate.get("p_value_at_most") != 0.05
        or not isinstance(preregistration, Mapping)
        or set(preregistration)
        != {"execution_state", "missing_required_fields", "unknown_fields"}
        or preregistration.get("execution_state") != "not_executed"
        or not isinstance(reporting, Mapping)
        or set(reporting)
        != {"primary", "secondary", "uniform_chance_balanced_accuracy"}
    ):
        raise CrossfitError("policy_contract_mismatch")


def open_matrix(path: Path, adapter: Mapping[str, Any]) -> np.ndarray:
    if adapter.get("schema") != ADAPTER_SCHEMA or set(adapter) != {
        "counts",
        "grid_policy",
        "matrix",
        "privacy",
        "provenance",
        "rows",
        "schema",
    }:
        raise CrossfitError("adapter_schema_mismatch")
    grid = adapter.get("grid_policy")
    matrix_receipt = adapter.get("matrix")
    counts = adapter.get("counts")
    if (
        not isinstance(grid, Mapping)
        or grid.get("grid_shape") != list(EXPECTED_GRID_SHAPE)
        or grid.get("components") != ["real", "imaginary"]
        or grid.get("dtype") != "<f4"
        or not isinstance(counts, Mapping)
        or counts.get("observations") != EXPECTED_OBSERVATIONS
        or counts.get("paired_cells") != EXPECTED_PAIRS
        or not isinstance(matrix_receipt, Mapping)
        or matrix_receipt.get("shape") != [EXPECTED_OBSERVATIONS, *EXPECTED_GRID_SHAPE]
        or matrix_receipt.get("dtype") != "<f4"
        or matrix_receipt.get("format") != "npy"
    ):
        raise CrossfitError("adapter_matrix_contract_mismatch")
    actual_digest, actual_bytes = _sha256_path(path)
    if (
        matrix_receipt.get("sha256") != actual_digest
        or matrix_receipt.get("bytes") != actual_bytes
    ):
        raise CrossfitError("matrix_digest_mismatch")
    try:
        matrix = np.load(path, mmap_mode="r", allow_pickle=False)
    except (OSError, ValueError) as error:
        raise CrossfitError("matrix_load_failed") from error
    if (
        not isinstance(matrix, np.memmap)
        or matrix.flags.writeable
        or matrix.shape != (EXPECTED_OBSERVATIONS, *EXPECTED_GRID_SHAPE)
        or matrix.dtype != np.dtype("<f4")
    ):
        raise CrossfitError("matrix_array_contract_mismatch")
    return matrix


def extract_features(grid: np.ndarray) -> tuple[float, ...]:
    if grid.shape != EXPECTED_GRID_SHAPE or grid.dtype.kind not in {"f", "i", "u"}:
        raise CrossfitError("feature_grid_contract_mismatch")
    values = np.asarray(grid, dtype=np.float64)
    if not np.isfinite(values).all():
        raise CrossfitError("nonfinite_grid")
    power = values[..., 0] ** 2 + values[..., 1] ** 2
    mean_power = float(np.mean(power, dtype=np.float64))
    if not math.isfinite(mean_power) or mean_power <= 0.0:
        raise CrossfitError("nonpositive_mean_power")
    features = [
        math.log(mean_power),
        float(np.std(power, dtype=np.float64)) / mean_power,
    ]
    for axis in range(3):
        reduced = tuple(index for index in range(3) if index != axis)
        axis_power = np.mean(power, axis=reduced, dtype=np.float64)
        features.append(float(np.std(axis_power, dtype=np.float64)) / mean_power)
    result = tuple(features)
    if len(result) != len(FEATURE_NAMES) or not all(map(math.isfinite, result)):
        raise CrossfitError("nonfinite_features")
    return result


def bind_observations(
    oracle: Mapping[str, Any], adapter: Mapping[str, Any], matrix: np.ndarray
) -> tuple[Observation, ...]:
    if oracle.get("schema") != ORACLE_SCHEMA or oracle.get("status") != "pass":
        raise CrossfitError("oracle_schema_mismatch")
    provenance = adapter.get("provenance")
    if (
        not isinstance(provenance, Mapping)
        or provenance.get("oracle_schema") != ORACLE_SCHEMA
        or provenance.get("oracle_inventory_id") != oracle.get("inventory_id")
    ):
        raise CrossfitError("oracle_adapter_provenance_mismatch")
    raw_oracle = oracle.get("observations")
    raw_rows = adapter.get("rows")
    if (
        not isinstance(raw_oracle, list)
        or len(raw_oracle) != EXPECTED_OBSERVATIONS
        or not isinstance(raw_rows, list)
        or len(raw_rows) != EXPECTED_OBSERVATIONS
    ):
        raise CrossfitError("observation_count_mismatch")
    oracle_by_id: dict[str, Mapping[str, Any]] = {}
    for item in raw_oracle:
        if not isinstance(item, Mapping):
            raise CrossfitError("oracle_observation_schema")
        identifier = item.get("observation_id")
        if not isinstance(identifier, str) or identifier in oracle_by_id:
            raise CrossfitError("oracle_observation_id_invalid")
        oracle_by_id[identifier] = item
    bound: list[Observation] = []
    seen_rows: set[int] = set()
    seen_ids: set[str] = set()
    for binding in raw_rows:
        if not isinstance(binding, Mapping) or set(binding) != {
            "observation_id",
            "row",
        }:
            raise CrossfitError("adapter_row_schema")
        identifier = binding.get("observation_id")
        row = binding.get("row")
        if (
            not isinstance(identifier, str)
            or identifier in seen_ids
            or type(row) is not int
            or row in seen_rows
            or not 0 <= row < EXPECTED_OBSERVATIONS
        ):
            raise CrossfitError("adapter_row_invalid")
        try:
            source = oracle_by_id[identifier]
        except KeyError as error:
            raise CrossfitError("adapter_oracle_id_mismatch") from error
        cause = source.get("controlled_jamming_cause")
        if cause not in CAUSES:
            raise CrossfitError("oracle_cause_invalid")
        bound.append(
            Observation(
                observation_id=identifier,
                cause=cause,
                receiver_group=_known_group(
                    source.get("receiver_group"), "receiver_group_invalid"
                ),
                configuration_group=_known_group(
                    source.get("radar_configuration_group"),
                    "configuration_group_invalid",
                ),
                pair_group=_known_group(
                    source.get("paired_cell_group"), "pair_group_invalid"
                ),
                row=row,
                features=extract_features(matrix[row]),
            )
        )
        seen_ids.add(identifier)
        seen_rows.add(row)
    if seen_ids != set(oracle_by_id) or seen_rows != set(range(EXPECTED_OBSERVATIONS)):
        raise CrossfitError("row_reconciliation_failed")
    observations = tuple(sorted(bound, key=lambda item: item.observation_id))
    validate_groups(observations)
    return observations


def validate_groups(observations: Sequence[Observation]) -> None:
    receivers: dict[str, list[Observation]] = defaultdict(list)
    pairs: dict[str, list[Observation]] = defaultdict(list)
    configurations: dict[str, set[str]] = defaultdict(set)
    for item in observations:
        receivers[item.receiver_group].append(item)
        pairs[item.pair_group].append(item)
        configurations[item.configuration_group].add(item.receiver_group)
    if (
        len(observations) != EXPECTED_OBSERVATIONS
        or len(receivers) != EXPECTED_RECEIVERS
        or {len(items) for items in receivers.values()} != {20}
        or len(pairs) != EXPECTED_PAIRS
        or any(
            len(items) != 2
            or {item.cause for item in items} != set(CAUSES)
            or len({item.receiver_group for item in items}) != 1
            for items in pairs.values()
        )
        or len(configurations) != 8
        or any(len(groups) != 1 for groups in configurations.values())
    ):
        raise CrossfitError("group_contract_mismatch")


def fit_model(observations: Sequence[Observation]) -> FittedModel:
    if len(observations) != 60 or Counter(item.cause for item in observations) != {
        cause: 30 for cause in CAUSES
    }:
        raise CrossfitError("train_fold_contract_mismatch")
    matrix = np.asarray([item.features for item in observations], dtype=np.float64)
    means = np.mean(matrix, axis=0, dtype=np.float64)
    scales = np.std(matrix, axis=0, dtype=np.float64)
    active = tuple(
        index
        for index, scale in enumerate(scales.tolist())
        if math.isfinite(scale) and scale > 0.0
    )
    if not active or not np.isfinite(means).all():
        raise CrossfitError("no_active_features")
    standardized = (matrix[:, active] - means[list(active)]) / scales[list(active)]
    centroids = {
        cause: tuple(
            np.mean(
                standardized[[item.cause == cause for item in observations], :],
                axis=0,
                dtype=np.float64,
            ).tolist()
        )
        for cause in CAUSES
    }
    if not all(math.isfinite(value) for row in centroids.values() for value in row):
        raise CrossfitError("nonfinite_centroid")
    return FittedModel(
        active,
        tuple(means.tolist()),
        tuple(scales.tolist()),
        centroids,
    )


def score_observation(item: Observation, model: FittedModel) -> float:
    standardized = tuple(
        (item.features[index] - model.means[index]) / model.scales[index]
        for index in model.active
    )
    distances = {
        cause: math.fsum(
            (value - centroid) ** 2
            for value, centroid in zip(
                standardized, model.centroids[cause], strict=True
            )
        )
        for cause in CAUSES
    }
    score = distances[CAUSES[0]] - distances[CAUSES[1]]
    if not math.isfinite(score):
        raise CrossfitError("nonfinite_score")
    return score


def predict(item: Observation, model: FittedModel) -> Prediction:
    score = score_observation(item, model)
    predicted = CAUSES[1] if score > 0.0 else CAUSES[0] if score < 0.0 else "abstain"
    return Prediction(item, score, predicted)


def metric_report(predictions: Sequence[Prediction]) -> dict[str, Any]:
    if not predictions:
        raise CrossfitError("empty_metric_partition")
    per_class: dict[str, dict[str, int]] = {}
    recalls: list[float] = []
    f1s: list[float] = []
    for cause in CAUSES:
        true_positive = sum(
            row.observation.cause == cause and row.predicted == cause
            for row in predictions
        )
        false_negative = sum(
            row.observation.cause == cause and row.predicted != cause
            for row in predictions
        )
        false_positive = sum(
            row.observation.cause != cause and row.predicted == cause
            for row in predictions
        )
        recall = true_positive / (true_positive + false_negative)
        denominator = 2 * true_positive + false_positive + false_negative
        f1 = 0.0 if denominator == 0 else 2 * true_positive / denominator
        recalls.append(recall)
        f1s.append(f1)
        per_class[cause] = {
            "false_negative": false_negative,
            "false_positive": false_positive,
            "true_positive": true_positive,
        }
    return {
        "abstentions": sum(row.predicted == "abstain" for row in predictions),
        "balanced_accuracy": round(math.fsum(recalls) / len(recalls), 12),
        "macro_f1": round(math.fsum(f1s) / len(f1s), 12),
        "observations": len(predictions),
        "per_class": per_class,
    }


def crossfit(observations: Sequence[Observation]) -> tuple[Prediction, ...]:
    receiver_groups = sorted({item.receiver_group for item in observations})
    predictions: list[Prediction] = []
    for test_group in receiver_groups:
        train = tuple(
            item for item in observations if item.receiver_group != test_group
        )
        test = tuple(item for item in observations if item.receiver_group == test_group)
        if (
            len(test) != 20
            or len({item.pair_group for item in test}) != 10
            or {item.configuration_group for item in train}
            & {item.configuration_group for item in test}
        ):
            raise CrossfitError("fold_boundary_mismatch")
        model = fit_model(train)
        predictions.extend(predict(item, model) for item in test)
    if (
        len(predictions) != EXPECTED_OBSERVATIONS
        or len({row.observation.observation_id for row in predictions})
        != EXPECTED_OBSERVATIONS
    ):
        raise CrossfitError("crossfit_reconciliation_failed")
    return tuple(sorted(predictions, key=lambda row: row.observation.observation_id))


def _one_sided_sign_p(wins: int, losses: int) -> float:
    trials = wins + losses
    if trials <= 0 or not 0 <= wins <= trials:
        return 1.0
    numerator = sum(math.comb(trials, count) for count in range(wins, trials + 1))
    return numerator / (2**trials)


def paired_report(
    predictions: Sequence[Prediction], policy: Mapping[str, Any]
) -> dict[str, Any]:
    by_pair: dict[str, list[Prediction]] = defaultdict(list)
    for row in predictions:
        by_pair[row.observation.pair_group].append(row)
    wins = losses = ties = both_correct = 0
    for members in by_pair.values():
        if len(members) != 2 or {row.observation.cause for row in members} != set(
            CAUSES
        ):
            raise CrossfitError("prediction_pair_contract_mismatch")
        scores = {row.observation.cause: row.score for row in members}
        difference = scores[CAUSES[1]] - scores[CAUSES[0]]
        wins += difference > 0.0
        losses += difference < 0.0
        ties += difference == 0.0
        both_correct += all(row.predicted == row.observation.cause for row in members)
    if len(by_pair) != EXPECTED_PAIRS or wins + losses + ties != EXPECTED_PAIRS:
        raise CrossfitError("pair_metric_reconciliation_failed")
    p_value = _one_sided_sign_p(wins, losses)
    gate_policy = policy["primary_gate"]
    gate = {
        "minimum_non_tied_pairs": gate_policy["minimum_non_tied_pairs"],
        "non_tied_pairs_passed": wins + losses >= gate_policy["minimum_non_tied_pairs"],
        "p_value_at_most": gate_policy["p_value_at_most"],
        "p_value_passed": p_value <= gate_policy["p_value_at_most"],
        "wins_exceed_losses": wins > losses,
    }
    gate["passed"] = all(
        gate[key]
        for key in ("non_tied_pairs_passed", "p_value_passed", "wins_exceed_losses")
    )
    return {
        "both_members_correct_pairs": both_correct,
        "both_members_correct_rate": round(both_correct / EXPECTED_PAIRS, 12),
        "gate": gate,
        "losses": losses,
        "non_tied_pairs": wins + losses,
        "one_sided_exact_p_value": round(p_value, 12),
        "pairs": EXPECTED_PAIRS,
        "ranking_rate_with_half_credit_for_ties": round(
            (wins + 0.5 * ties) / EXPECTED_PAIRS, 12
        ),
        "ties": ties,
        "wins": wins,
    }


def _validate_report_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in FORBIDDEN_REPORT_KEYS:
                raise CrossfitError("report_contains_forbidden_binding")
            _validate_report_keys(item)
    elif isinstance(value, list):
        for item in value:
            _validate_report_keys(item)


def evaluate(
    oracle: Mapping[str, Any],
    adapter: Mapping[str, Any],
    matrix: np.ndarray,
    policy: Mapping[str, Any],
    *,
    policy_sha256: str,
) -> dict[str, Any]:
    validate_policy(policy)
    observations = bind_observations(oracle, adapter, matrix)
    predictions = crossfit(observations)
    receiver_groups = sorted({row.observation.receiver_group for row in predictions})
    fold_metrics = sorted(
        (
            metric_report(
                [
                    row
                    for row in predictions
                    if row.observation.receiver_group == receiver_group
                ]
            )
            for receiver_group in receiver_groups
        ),
        key=lambda value: json.dumps(value, sort_keys=True),
    )
    paired = paired_report(predictions, policy)
    report = {
        "schema": REPORT_SCHEMA,
        "status": "pass" if paired["gate"]["passed"] else "hypothesis_not_supported",
        "provenance": {
            "adapter_schema": ADAPTER_SCHEMA,
            "oracle_inventory_id": oracle["inventory_id"],
            "oracle_schema": ORACLE_SCHEMA,
            "policy_schema": POLICY_SCHEMA,
            "policy_sha256": policy_sha256,
            "record_id": 6516954,
        },
        "scope": {
            "classes": list(CAUSES),
            "crossfit_folds": EXPECTED_RECEIVERS,
            "observations": EXPECTED_OBSERVATIONS,
            "paired_cells": EXPECTED_PAIRS,
            "test_observations_per_fold": 20,
            "train_observations_per_fold": 60,
        },
        "feature_policy": {
            "features": list(FEATURE_NAMES),
            "grid_shape": list(EXPECTED_GRID_SHAPE),
            "metadata_features": False,
        },
        "model": {
            "classifier": "train_standardized_nearest_centroid",
            "fit_partition": "three_non_test_receiver_groups_per_fold",
            "hyperparameter_search": False,
            "test_predictions_per_observation": 1,
            "threshold": 0.0,
        },
        "heldout_metrics": metric_report(predictions),
        "paired_ranking": paired,
        "per_fold_metrics_without_group_identifiers": fold_metrics,
        "limitations": list(policy["limitations"]),
    }
    _validate_report_keys(report)
    return report


def render_report(report: Mapping[str, Any]) -> bytes:
    _validate_report_keys(report)
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    payload = render_report(report)
    if len(payload) > MAX_JSON_BYTES:
        raise CrossfitError("report_byte_limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--oracle",
        type=Path,
        default=ROOT / "data/derived/eval/mmwave-jamming-observation-oracles.json",
    )
    parser.add_argument(
        "--adapter",
        type=Path,
        default=ROOT / "data/derived/eval/mmwave-jamming-paired-grid-adapter.json",
    )
    parser.add_argument(
        "--matrix",
        type=Path,
        default=ROOT / "data/derived/eval/mmwave-jamming-paired-grid.npy",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=ROOT / "eval/fixtures/mmwave-jamming-receiver-crossfit-v0.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data/derived/eval/mmwave-jamming-receiver-crossfit-report.json",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        policy, policy_bytes = read_json_payload(arguments.policy)
        oracle = read_json(arguments.oracle)
        adapter = read_json(arguments.adapter)
        matrix = open_matrix(arguments.matrix, adapter)
        report = evaluate(
            oracle,
            adapter,
            matrix,
            policy,
            policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
        )
        write_report(arguments.output, report)
    except (CrossfitError, OSError, ValueError) as error:
        print(str(error), file=os.sys.stderr)
        return 2
    print(
        json.dumps(
            {"paired_ranking": report["paired_ranking"], "status": report["status"]},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
