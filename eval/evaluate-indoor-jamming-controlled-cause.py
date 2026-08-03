#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["h5py==3.16.0", "xlrd==2.0.2"]
# ///

"""Run the preregistered indoor controlled-cause smoke evaluation.

The evaluator reconstructs local MAT-file and HDF5-dataset bindings in memory
from the existing oracle compiler. Reports contain only aggregate values and
opaque compiler identifiers; paths, filenames, and dataset names are excluded.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
DEFAULT_ORACLE = (
    ROOT / "data" / "derived" / "eval" / "indoor-jamming-observation-oracles.json"
)
DEFAULT_POLICY = HERE / "fixtures" / "indoor-jamming-controlled-cause-v0.json"
DEFAULT_MANIFEST = ROOT / "data" / "catalog" / "controlled-jamming-artifacts-v1.json"
DEFAULT_RAW_DIR = ROOT / "data" / "raw" / "controlled-jamming"
DEFAULT_RECEIPT_DIR = ROOT / "data" / "receipts" / "controlled-jamming"
DEFAULT_REPORT = (
    ROOT / "data" / "derived" / "eval" / "indoor-jamming-controlled-cause-report.json"
)

POLICY_SCHEMA = "netbraid.indoor_jamming_controlled_cause_policy.v0"
REPORT_SCHEMA = "netbraid.indoor_jamming_controlled_cause_eval.v0"
CAUSES = ("silent", "sine", "gaussian")
PREDICTIONS = (*CAUSES, "abstain")
SPLITS = ("train", "validation", "test")
ATOMIC_GROUPS = (
    "assigned_jammer_setup_group",
    "file_session_group",
    "paired_condition_group",
    "combined_setup_group",
)
CONDITIONING_GROUPS = (
    "tx_rx_setup_group",
    "power_setup_group",
    "distance_setup_group",
)
FEATURE_NAMES = (
    "anonymous_row_0_mean",
    "anonymous_row_0_rms",
    "anonymous_row_0_zero_rate",
    "anonymous_row_1_mean",
    "anonymous_row_1_rms",
    "anonymous_row_1_zero_rate",
)
LIMITATIONS = (
    "conditional_on_one_tx_rx_setup_assigned_power_0.5_and_distance_10m",
    "one_held_out_jammer_setup_does_not_support_population_level_setup_generalization",
    "no_tx_rx_power_or_distance_generalization",
    "anonymous_row_semantics_and_sample_rate_are_not_declared",
    "no_spectral_timing_or_detection_latency_claim",
    "metadata_distinct_extents_do_not_prove_payload_deduplication",
    "controlled_cause_is_not_identity_tamper_actor_or_malicious_intent",
)
TOP_LEVEL_FIELDS = {
    "schema",
    "status",
    "provenance",
    "scope",
    "window_policy",
    "feature_policy",
    "split_policy",
    "split_receipts",
    "model",
    "validation",
    "test_metrics",
    "abstentions",
    "limitations",
}
ORACLE_FIELDS = {
    "schema",
    "inventory_id",
    "status",
    "provenance",
    "assignment",
    "required_split_groups",
    "counts",
    "privacy",
    "unsupported_claims",
    "observations",
}
OBSERVATION_FIELDS = {
    "observation_id",
    "file_session_group",
    "paired_condition_group",
    "tx_rx_setup_group",
    "assigned_jammer_setup_group",
    "power_setup_group",
    "distance_setup_group",
    "combined_setup_group",
    "controlled_cause",
    "condition_relative_jamming_power",
    "assigned_relative_jamming_power",
    "distance_meters",
    "duration_seconds",
    "dataset_sample_count",
    "event_identity",
    "physical_source_identity",
    "physical_device_identity",
    "variant_identity",
    "tamper",
    "actor_identity",
    "malicious_intent",
}
UNSUPPORTED_FIELDS = (
    "event_identity",
    "physical_source_identity",
    "physical_device_identity",
    "variant_identity",
    "tamper",
    "actor_identity",
    "malicious_intent",
)
OPAQUE_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
WINDOW_BYTE_BUDGET = 2 * 65_536 * 8


class EvaluationInputError(ValueError):
    """Stable fail-closed reason for invalid inputs or protocol state."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class DuplicateJsonKeyError(ValueError):
    """Raised when a strict JSON object repeats a key."""


@dataclass(frozen=True)
class SourceIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class BoundObservation:
    observation_id: str
    controlled_cause: str
    sample_count: int
    assigned_power: float
    distance_meters: float
    groups: Mapping[str, str]
    source_path: Path
    dataset_path: str
    source_identity: SourceIdentity | None = None


@dataclass(frozen=True)
class FeatureOutcome:
    vector: tuple[float, ...] | None
    reason: str | None
    verified_windows: int = 0


@dataclass(frozen=True)
class FittedModel:
    active_indices: tuple[int, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    centroids: Mapping[str, tuple[float, ...]]
    radii: Mapping[str, float]


WindowReader = Callable[[str | os.PathLike[str], str, int, int], Mapping[str, Any]]


def _source_identity(path: Path) -> SourceIdentity:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvaluationInputError("source_identity_unavailable") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise EvaluationInputError("source_identity_not_regular")
    return SourceIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load local module: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COMPILER = _load_module(
    "netbraid_compile_indoor_jamming_oracles",
    HERE / "compile-indoor-jamming-oracles.py",
)
HDF5_WINDOW = _load_module("netbraid_hdf5_window", HERE / "hdf5_window.py")


def _strict_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(key)
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise DuplicateJsonKeyError("non_finite_number")


def _read_strict_json(path: Path, error_prefix: str) -> tuple[Any, bytes]:
    try:
        before = path.lstat()
    except OSError as error:
        raise EvaluationInputError(f"{error_prefix}_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise EvaluationInputError(f"{error_prefix}_not_regular")
    if not 0 < before.st_size <= MAX_JSON_BYTES:
        raise EvaluationInputError(f"{error_prefix}_size_limit")
    try:
        with path.open("rb") as source:
            opened = os.fstat(source.fileno())
            if (before.st_dev, before.st_ino, before.st_size) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
            ):
                raise EvaluationInputError(f"{error_prefix}_identity_changed")
            encoded = source.read(MAX_JSON_BYTES + 1)
            after = os.fstat(source.fileno())
    except EvaluationInputError:
        raise
    except OSError as error:
        raise EvaluationInputError(f"{error_prefix}_read_failed") from error
    if (
        len(encoded) != opened.st_size
        or len(encoded) > MAX_JSON_BYTES
        or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
    ):
        raise EvaluationInputError(f"{error_prefix}_changed_during_read")
    try:
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise EvaluationInputError(f"{error_prefix}_invalid_json") from error
    return value, encoded


def _expected_policy() -> dict[str, Any]:
    return {
        "campaign_id": "indoor-jamming-controlled-cause-v0",
        "feature_policy": {
            "aggregation": "mean_across_four_windows",
            "features": list(FEATURE_NAMES),
            "metadata_features": False,
            "row_semantics": "anonymous",
        },
        "limitations": list(LIMITATIONS),
        "model": {
            "classifier": "standardized_nearest_centroid",
            "fit": "train_only",
            "radius": "maximum_train_distance_per_class",
            "test_uses": 1,
            "tie_policy": "abstain",
            "zero_variance_features": "drop",
        },
        "preregistration": {
            "execution_state": "not_executed",
            "missing_required_fields": "reject",
            "unknown_fields": "reject",
        },
        "schema": POLICY_SCHEMA,
        "slice": {
            "assigned_relative_jamming_power": 0.5,
            "causes": list(CAUSES),
            "distance_meters": 10.0,
            "expected_complete_triplets": 8,
            "expected_jammer_setup_repetitions": [1, 1, 1, 2, 3],
            "expected_minimum_extent_columns": 145_920_978,
            "expected_observations": 24,
        },
        "split_policy": {
            "atomic_groups": list(ATOMIC_GROUPS),
            "conditioning_groups": list(CONDITIONING_GROUPS),
            "role_by_jammer_setup_repetition": {
                "1": "train",
                "2": "validation",
                "3": "test",
            },
        },
        "validation_gate": {
            "balanced_accuracy_strictly_greater_than": 1 / 3,
            "coverage_at_least": 2 / 3,
        },
        "window_policy": {
            "columns": 65_536,
            "count": 4,
            "expected_starts": [29_151_427, 58_335_623, 87_519_818, 116_704_014],
            "interior_denominator": 5,
            "positions": [1, 2, 3, 4],
        },
    }


def load_policy(path: Path) -> tuple[Mapping[str, Any], str]:
    value, encoded = _read_strict_json(path, "policy")
    if value != _expected_policy():
        raise EvaluationInputError("policy_contract_mismatch")
    return value, hashlib.sha256(encoded).hexdigest()


def _known_group_id(value: Any) -> str:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"state", "group_id"}
        or value.get("state") != "known"
        or not isinstance(value.get("group_id"), str)
        or OPAQUE_ID_PATTERN.fullmatch(value["group_id"]) is None
    ):
        raise EvaluationInputError("oracle_required_group_not_known")
    return value["group_id"]


def validate_oracle(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != ORACLE_FIELDS:
        raise EvaluationInputError("oracle_schema_fields")
    if value.get("schema") != COMPILER.OUTPUT_SCHEMA:
        raise EvaluationInputError("unsupported_oracle_schema")
    if value.get("status") != "pass":
        raise EvaluationInputError("oracle_status_not_pass")
    if (
        not isinstance(value.get("inventory_id"), str)
        or OPAQUE_ID_PATTERN.fullmatch(value["inventory_id"]) is None
    ):
        raise EvaluationInputError("oracle_inventory_id")
    provenance = value.get("provenance")
    if (
        not isinstance(provenance, Mapping)
        or provenance.get("record_id") != COMPILER.RECORD_ID
        or provenance.get("manifest_schema") != COMPILER.MANIFEST_SCHEMA
        or provenance.get("workbook_truth_basis") != "publisher_workbook"
        or provenance.get("all_artifact_bytes_rehashed") is not True
        or provenance.get("integrity_basis")
        != "full_local_md5_sha256_rehash_and_exact_fetch_receipts"
    ):
        raise EvaluationInputError("oracle_full_digest_required")
    if value.get("assignment") != {
        "roles_assigned": False,
        "partitions_assigned": 0,
        "train_test_split_assigned": False,
    }:
        raise EvaluationInputError("oracle_assignment_contract")
    if value.get("required_split_groups") != list(COMPILER.REQUIRED_SPLIT_GROUPS):
        raise EvaluationInputError("oracle_split_group_contract")
    if value.get("privacy") != {
        "dataset_elements_read": 0,
        "paths_retained": 0,
        "filenames_retained": 0,
        "raw_tx_rx_ids_retained": 0,
        "raw_assigned_jammer_ids_retained": 0,
    }:
        raise EvaluationInputError("oracle_privacy_contract")
    observations = value.get("observations")
    if not isinstance(observations, list) or len(observations) != 93:
        raise EvaluationInputError("oracle_observation_count")
    observed_ids: set[str] = set()
    cause_counts: Counter[str] = Counter()
    for observation in observations:
        if (
            not isinstance(observation, Mapping)
            or set(observation) != OBSERVATION_FIELDS
        ):
            raise EvaluationInputError("oracle_observation_schema")
        observation_id = observation.get("observation_id")
        if (
            not isinstance(observation_id, str)
            or OPAQUE_ID_PATTERN.fullmatch(observation_id) is None
            or observation_id in observed_ids
        ):
            raise EvaluationInputError("oracle_observation_id")
        observed_ids.add(observation_id)
        cause = observation.get("controlled_cause")
        if cause not in CAUSES:
            raise EvaluationInputError("oracle_controlled_cause")
        cause_counts[cause] += 1
        if (
            type(observation.get("dataset_sample_count")) is not int
            or observation["dataset_sample_count"] <= 0
        ):
            raise EvaluationInputError("oracle_sample_count")
        for group in COMPILER.REQUIRED_SPLIT_GROUPS:
            _known_group_id(observation[group])
        for field in UNSUPPORTED_FIELDS:
            if observation[field] != {
                "state": "not_observed",
                "support": "unsupported",
                "group_id": None,
            }:
                raise EvaluationInputError("oracle_unsupported_claim_contract")
    if cause_counts != Counter({cause: 31 for cause in CAUSES}):
        raise EvaluationInputError("oracle_cause_counts")
    counts = value.get("counts")
    if (
        not isinstance(counts, Mapping)
        or counts.get("scenario_segments") != 93
        or counts.get("paired_three_condition_groups") != 31
        or counts.get("causes") != {cause: 31 for cause in sorted(CAUSES)}
        or counts.get("dataset_samples")
        != sum(item["dataset_sample_count"] for item in observations)
    ):
        raise EvaluationInputError("oracle_count_mismatch")
    return value


def load_oracle(path: Path) -> Mapping[str, Any]:
    value, _encoded = _read_strict_json(path, "oracle")
    return validate_oracle(value)


def _compiler_equivalent(
    full_digest_oracle: Mapping[str, Any], current_oracle: Mapping[str, Any]
) -> bool:
    full_copy = copy.deepcopy(full_digest_oracle)
    current_copy = copy.deepcopy(current_oracle)
    full_copy.pop("provenance", None)
    current_copy.pop("provenance", None)
    if full_copy != current_copy:
        return False
    full_provenance = full_digest_oracle["provenance"]
    current_provenance = current_oracle["provenance"]
    return all(
        full_provenance.get(field) == current_provenance.get(field)
        for field in ("record_id", "manifest_schema", "workbook_truth_basis")
    )


def reconstruct_bindings(
    oracle: Mapping[str, Any],
    manifest: Path,
    raw_dir: Path,
    receipt_dir: Path,
) -> tuple[BoundObservation, ...]:
    """Rebuild private source bindings through the compiler's exact mapping."""

    try:
        record = COMPILER.load_record(manifest)
        current = COMPILER.compile_inventory(
            record, raw_dir, receipt_dir, full_digest=False
        )
    except COMPILER.OracleCompileError as error:
        raise EvaluationInputError(f"compiler_preflight_{error}") from error
    if not _compiler_equivalent(oracle, current):
        raise EvaluationInputError("oracle_compiler_mapping_mismatch")

    record_dir = raw_dir / str(COMPILER.RECORD_ID)
    receipt_record_dir = receipt_dir / str(COMPILER.RECORD_ID)
    identities_by_name: dict[str, SourceIdentity] = {}
    for artifact in record.artifacts:
        source_path = record_dir / artifact.filename
        try:
            verified = COMPILER.verify_artifact(
                source_path,
                receipt_record_dir / f"{artifact.filename}.json",
                artifact,
                full_digest=True,
            )
        except COMPILER.OracleCompileError as error:
            raise EvaluationInputError(f"compiler_full_digest_{error}") from error
        current = _source_identity(source_path)
        if (
            current.device,
            current.inode,
            current.size,
            current.modified_ns,
        ) != (verified.device, verified.inode, verified.size, verified.mtime_ns):
            raise EvaluationInputError("source_changed_after_full_digest")
        identities_by_name[artifact.filename] = current

    by_id = {item["observation_id"]: item for item in oracle["observations"]}
    bindings: list[BoundObservation] = []
    dataset_by_cause = {cause: dataset for _token, cause, dataset in COMPILER.CAUSES}
    for group_index, filename in enumerate(COMPILER.EXPECTED_MAT_NAMES, 1):
        for cause in CAUSES:
            observation_id = COMPILER._opaque_id("observation", group_index, cause)
            observation = by_id.get(observation_id)
            if observation is None:
                raise EvaluationInputError("oracle_compiler_binding_missing")
            groups = {
                field: _known_group_id(observation[field])
                for field in COMPILER.REQUIRED_SPLIT_GROUPS
            }
            bindings.append(
                BoundObservation(
                    observation_id=observation_id,
                    controlled_cause=cause,
                    sample_count=observation["dataset_sample_count"],
                    assigned_power=observation["assigned_relative_jamming_power"],
                    distance_meters=observation["distance_meters"],
                    groups=groups,
                    source_path=record_dir / filename,
                    dataset_path=dataset_by_cause[cause],
                    source_identity=identities_by_name[filename],
                )
            )
    if {item.observation_id for item in bindings} != set(by_id):
        raise EvaluationInputError("oracle_compiler_binding_extra")
    return tuple(bindings)


def _window_plan(
    minimum_extent: int, policy: Mapping[str, Any]
) -> tuple[tuple[int, int], ...]:
    window = policy["window_policy"]
    length = window["columns"]
    denominator = window["interior_denominator"]
    intervals = tuple(
        (
            position * minimum_extent // denominator - length // 2,
            position * minimum_extent // denominator + length - length // 2,
        )
        for position in window["positions"]
    )
    starts = [start for start, _stop in intervals]
    if starts != window["expected_starts"]:
        raise EvaluationInputError("window_start_contract")
    if any(start < 0 or stop > minimum_extent for start, stop in intervals):
        raise EvaluationInputError("window_not_interior")
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
        raise EvaluationInputError("window_overlap")
    if any(stop - start != length for start, stop in intervals):
        raise EvaluationInputError("window_length_contract")
    return intervals


def preflight(
    observations: Sequence[BoundObservation], policy: Mapping[str, Any]
) -> tuple[dict[str, tuple[BoundObservation, ...]], tuple[tuple[int, int], ...]]:
    slice_policy = policy["slice"]
    selected = tuple(
        item
        for item in observations
        if item.assigned_power == slice_policy["assigned_relative_jamming_power"]
        and item.distance_meters == slice_policy["distance_meters"]
    )
    if len(selected) != slice_policy["expected_observations"]:
        raise EvaluationInputError("slice_observation_count")
    if Counter(item.controlled_cause for item in selected) != Counter(
        {cause: 8 for cause in CAUSES}
    ):
        raise EvaluationInputError("slice_cause_count")

    by_file: dict[str, list[BoundObservation]] = defaultdict(list)
    for item in selected:
        by_file[item.groups["file_session_group"]].append(item)
    if len(by_file) != slice_policy["expected_complete_triplets"]:
        raise EvaluationInputError("slice_triplet_count")
    for triplet in by_file.values():
        if (
            len(triplet) != 3
            or {item.controlled_cause for item in triplet} != set(CAUSES)
            or len({item.groups["paired_condition_group"] for item in triplet}) != 1
            or len({item.groups["assigned_jammer_setup_group"] for item in triplet})
            != 1
            or len({item.groups["combined_setup_group"] for item in triplet}) != 1
        ):
            raise EvaluationInputError("slice_incomplete_triplet")

    for field in CONDITIONING_GROUPS:
        if len({item.groups[field] for item in selected}) != 1:
            raise EvaluationInputError("conditioning_group_not_constant")
    for cause in CAUSES:
        extents = [
            item.sample_count for item in selected if item.controlled_cause == cause
        ]
        if len(extents) != len(set(extents)):
            raise EvaluationInputError("slice_extent_not_unique_per_cause")

    repetition_by_jammer: Counter[str] = Counter(
        triplet[0].groups["assigned_jammer_setup_group"] for triplet in by_file.values()
    )
    if (
        sorted(repetition_by_jammer.values())
        != slice_policy["expected_jammer_setup_repetitions"]
    ):
        raise EvaluationInputError("jammer_repetition_contract")
    role_by_repetition = {
        int(key): role
        for key, role in policy["split_policy"][
            "role_by_jammer_setup_repetition"
        ].items()
    }
    partitions: dict[str, list[BoundObservation]] = {role: [] for role in SPLITS}
    for item in selected:
        repetition = repetition_by_jammer[item.groups["assigned_jammer_setup_group"]]
        try:
            role = role_by_repetition[repetition]
        except KeyError as error:
            raise EvaluationInputError("jammer_repetition_role_missing") from error
        partitions[role].append(item)
    frozen = {
        role: tuple(sorted(items, key=lambda item: item.observation_id))
        for role, items in partitions.items()
    }
    expected_role_counts = {"train": 9, "validation": 6, "test": 9}
    if {role: len(frozen[role]) for role in SPLITS} != expected_role_counts:
        raise EvaluationInputError("split_observation_count")
    for field in ATOMIC_GROUPS:
        role_values = {
            role: {item.groups[field] for item in frozen[role]} for role in SPLITS
        }
        for left_index, left in enumerate(SPLITS):
            for right in SPLITS[left_index + 1 :]:
                if role_values[left] & role_values[right]:
                    raise EvaluationInputError("atomic_group_crosses_roles")

    minimum_extent = min(item.sample_count for item in selected)
    if minimum_extent != slice_policy["expected_minimum_extent_columns"]:
        raise EvaluationInputError("minimum_extent_contract")
    intervals = _window_plan(minimum_extent, policy)
    return frozen, intervals


def _numeric_row_features(
    row: Any, window_columns: int
) -> tuple[float, float, float] | None:
    if not isinstance(row, Mapping) or set(row) != {
        "finite",
        "nonfinite",
        "zero",
        "sum",
        "sumsq",
    }:
        return None
    finite = row.get("finite")
    nonfinite = row.get("nonfinite")
    zero = row.get("zero")
    total = row.get("sum")
    sumsq = row.get("sumsq")
    if (
        type(finite) is not int
        or finite != window_columns
        or type(nonfinite) is not int
        or nonfinite != 0
        or type(zero) is not int
        or not 0 <= zero <= window_columns
        or isinstance(total, bool)
        or not isinstance(total, (int, float))
        or isinstance(sumsq, bool)
        or not isinstance(sumsq, (int, float))
    ):
        return None
    mean = float(total) / finite
    mean_square = float(sumsq) / finite
    if not math.isfinite(mean) or not math.isfinite(mean_square) or mean_square < 0:
        return None
    rms = math.sqrt(mean_square)
    variance = mean_square - mean * mean
    tolerance = 1e-12 * max(1.0, abs(mean_square), mean * mean)
    if not math.isfinite(rms) or not math.isfinite(variance) or variance < -tolerance:
        return None
    zero_rate = zero / window_columns
    if not math.isfinite(zero_rate):
        return None
    return mean, rms, zero_rate


def extract_features(
    observation: BoundObservation,
    intervals: Sequence[tuple[int, int]],
    reader: WindowReader,
) -> FeatureOutcome:
    vectors: list[tuple[float, ...]] = []
    for expected_start, expected_stop in intervals:
        try:
            summary = reader(
                observation.source_path,
                observation.dataset_path,
                expected_start,
                expected_stop,
            )
        except EvaluationInputError:
            raise
        except HDF5_WINDOW.Hdf5WindowError as error:
            return FeatureOutcome(None, f"window_read_{error}", len(vectors))
        except (OSError, RuntimeError, TypeError, ValueError):
            return FeatureOutcome(None, "window_read_failed", len(vectors))
        if not isinstance(summary, Mapping):
            return FeatureOutcome(None, "window_summary_schema", len(vectors))
        if summary.get("truncated") is not False:
            return FeatureOutcome(None, "window_truncated", len(vectors))
        expected_interval = {"start": expected_start, "stop": expected_stop}
        if (
            summary.get("requested_interval") != expected_interval
            or summary.get("selected_interval") != expected_interval
        ):
            return FeatureOutcome(None, "window_interval_mismatch", len(vectors))
        if summary.get("selected_bytes") != WINDOW_BYTE_BUDGET:
            return FeatureOutcome(None, "window_selected_bytes_mismatch", len(vectors))
        rows = summary.get("rows")
        if not isinstance(rows, list) or len(rows) != 2:
            return FeatureOutcome(None, "window_row_schema", len(vectors))
        row_features = [
            _numeric_row_features(row, expected_stop - expected_start) for row in rows
        ]
        if any(value is None for value in row_features):
            return FeatureOutcome(None, "window_invalid_aggregate", len(vectors))
        vector = tuple(value for row in row_features for value in row or ())
        if len(vector) != len(FEATURE_NAMES) or not all(map(math.isfinite, vector)):
            return FeatureOutcome(None, "window_nonfinite_feature", len(vectors))
        vectors.append(vector)
    if len(vectors) != 4:
        return FeatureOutcome(None, "fewer_than_four_valid_windows", len(vectors))
    averaged = tuple(
        math.fsum(vector[index] for vector in vectors) / len(vectors)
        for index in range(len(FEATURE_NAMES))
    )
    if not all(map(math.isfinite, averaged)):
        return FeatureOutcome(None, "nonfinite_feature_average", len(vectors))
    return FeatureOutcome(averaged, None, len(vectors))


def _extract_role(
    observations: Sequence[BoundObservation],
    intervals: Sequence[tuple[int, int]],
    reader: WindowReader,
) -> dict[str, FeatureOutcome]:
    return {
        item.observation_id: extract_features(item, intervals, reader)
        for item in observations
    }


def _standardize(vector: Sequence[float], model: FittedModel) -> tuple[float, ...]:
    return tuple(
        (vector[index] - model.means[index]) / model.scales[index]
        for index in model.active_indices
    )


def fit_model(
    observations: Sequence[BoundObservation],
    outcomes: Mapping[str, FeatureOutcome],
) -> FittedModel:
    vectors: list[tuple[float, ...]] = []
    for observation in observations:
        outcome = outcomes[observation.observation_id]
        if outcome.vector is None:
            raise EvaluationInputError("train_observation_abstained")
        vectors.append(outcome.vector)
    if Counter(item.controlled_cause for item in observations) != Counter(
        {cause: 3 for cause in CAUSES}
    ):
        raise EvaluationInputError("train_class_count")
    means = tuple(
        math.fsum(vector[index] for vector in vectors) / len(vectors)
        for index in range(len(FEATURE_NAMES))
    )
    scales = tuple(
        math.sqrt(
            math.fsum((vector[index] - means[index]) ** 2 for vector in vectors)
            / len(vectors)
        )
        for index in range(len(FEATURE_NAMES))
    )
    active = tuple(
        index
        for index, scale in enumerate(scales)
        if math.isfinite(scale) and scale > 0.0
    )
    if not active:
        raise EvaluationInputError("no_nonzero_variance_features")
    provisional = FittedModel(active, means, scales, {}, {})
    standardized = {
        observation.observation_id: _standardize(vector, provisional)
        for observation, vector in zip(observations, vectors)
    }
    centroids: dict[str, tuple[float, ...]] = {}
    radii: dict[str, float] = {}
    for cause in CAUSES:
        class_vectors = [
            standardized[item.observation_id]
            for item in observations
            if item.controlled_cause == cause
        ]
        centroid = tuple(
            math.fsum(vector[index] for vector in class_vectors) / len(class_vectors)
            for index in range(len(active))
        )
        centroids[cause] = centroid
        radii[cause] = max(math.dist(vector, centroid) for vector in class_vectors)
    return FittedModel(active, means, scales, centroids, radii)


def predict(vector: Sequence[float], model: FittedModel) -> tuple[str, str | None]:
    if len(vector) != len(FEATURE_NAMES) or not all(map(math.isfinite, vector)):
        return "abstain", "nonfinite_feature_vector"
    standardized = _standardize(vector, model)
    distances = {
        cause: math.dist(standardized, model.centroids[cause]) for cause in CAUSES
    }
    minimum = min(distances.values())
    nearest = [cause for cause in CAUSES if distances[cause] == minimum]
    if len(nearest) != 1:
        return "abstain", "non_unique_nearest_centroid"
    selected = nearest[0]
    if distances[selected] > model.radii[selected]:
        return "abstain", "outside_class_support_radius"
    return selected, None


def _rounded(value: float) -> float:
    return round(value, 12)


def metric_summary(
    observations: Sequence[BoundObservation], predictions: Mapping[str, str]
) -> dict[str, Any]:
    matrix = [[0 for _prediction in PREDICTIONS] for _cause in CAUSES]
    for item in observations:
        prediction = predictions[item.observation_id]
        if prediction not in PREDICTIONS:
            raise EvaluationInputError("prediction_outside_controlled_cause")
        matrix[CAUSES.index(item.controlled_cause)][PREDICTIONS.index(prediction)] += 1
    per_class: dict[str, Any] = {}
    recalls: list[float] = []
    f1_values: list[float] = []
    for class_index, cause in enumerate(CAUSES):
        tp = matrix[class_index][class_index]
        denominator = sum(matrix[class_index])
        fp = sum(matrix[row][class_index] for row in range(len(CAUSES))) - tp
        fn = denominator - tp
        recall = tp / denominator
        f1 = 0.0 if 2 * tp + fp + fn == 0 else 2 * tp / (2 * tp + fp + fn)
        recalls.append(recall)
        f1_values.append(f1)
        per_class[cause] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "recall": {
                "numerator": tp,
                "denominator": denominator,
                "value": _rounded(recall),
            },
            "f1": _rounded(f1),
        }
    total = len(observations)
    abstained = sum(row[-1] for row in matrix)
    return {
        "observations": total,
        "confusion": {
            "true_labels": list(CAUSES),
            "predicted_labels": list(PREDICTIONS),
            "rows_true_columns_predicted": matrix,
        },
        "coverage": {
            "numerator": total - abstained,
            "denominator": total,
            "value": _rounded((total - abstained) / total),
        },
        "balanced_accuracy": _rounded(math.fsum(recalls) / len(recalls)),
        "macro_f1": _rounded(math.fsum(f1_values) / len(f1_values)),
        "per_class": per_class,
    }


def _group_results(
    observations: Sequence[BoundObservation], predictions: Mapping[str, str], field: str
) -> list[dict[str, Any]]:
    grouped: dict[str, list[BoundObservation]] = defaultdict(list)
    for item in observations:
        grouped[item.groups[field]].append(item)
    results = [metric_summary(items, predictions) for items in grouped.values()]
    return sorted(results, key=lambda item: json.dumps(item, sort_keys=True))


def _complete_triplets(
    observations: Sequence[BoundObservation], predictions: Mapping[str, str]
) -> list[dict[str, Any]]:
    grouped: dict[str, list[BoundObservation]] = defaultdict(list)
    for item in observations:
        grouped[item.groups["file_session_group"]].append(item)
    results = [
        {
            "correct": sum(
                predictions[item.observation_id] == item.controlled_cause
                for item in items
            ),
            "observations": len(items),
            "success": all(
                predictions[item.observation_id] == item.controlled_cause
                for item in items
            ),
        }
        for items in grouped.values()
    ]
    return sorted(results, key=lambda item: json.dumps(item, sort_keys=True))


def _score_role(
    observations: Sequence[BoundObservation],
    outcomes: Mapping[str, FeatureOutcome],
    model: FittedModel,
) -> tuple[dict[str, Any], Counter[str]]:
    predictions: dict[str, str] = {}
    reasons: Counter[str] = Counter()
    for item in observations:
        outcome = outcomes[item.observation_id]
        if outcome.vector is None:
            prediction = "abstain"
            reason = outcome.reason or "feature_unavailable"
        else:
            prediction, reason = predict(outcome.vector, model)
        predictions[item.observation_id] = prediction
        if reason is not None:
            reasons[reason] += 1
    metrics = metric_summary(observations, predictions)
    metrics["complete_triplets"] = _complete_triplets(observations, predictions)
    metrics["per_group_metrics_without_identifiers"] = {
        "assigned_jammer_setup_group": _group_results(
            observations, predictions, "assigned_jammer_setup_group"
        ),
        "file_session_group": _group_results(
            observations, predictions, "file_session_group"
        ),
    }
    return metrics, reasons


def _split_receipts(
    partitions: Mapping[str, Sequence[BoundObservation]],
) -> dict[str, Any]:
    receipts: dict[str, Any] = {}
    for role in SPLITS:
        items = partitions[role]
        receipts[role] = {
            "observations": len(items),
            "complete_triplets": len(
                {item.groups["file_session_group"] for item in items}
            ),
            "per_cause": {
                cause: sum(item.controlled_cause == cause for item in items)
                for cause in CAUSES
            },
            "assigned_jammer_setup_group_count": len(
                {item.groups["assigned_jammer_setup_group"] for item in items}
            ),
            "file_session_group_count": len(
                {item.groups["file_session_group"] for item in items}
            ),
        }
    return receipts


def _validation_gate(
    validation_metrics: Mapping[str, Any], gate_policy: Mapping[str, Any]
) -> dict[str, Any]:
    coverage_passed = (
        validation_metrics["coverage"]["value"] >= gate_policy["coverage_at_least"]
    )
    balanced_accuracy_passed = (
        validation_metrics["balanced_accuracy"]
        > gate_policy["balanced_accuracy_strictly_greater_than"]
    )
    return {
        "coverage_at_least": gate_policy["coverage_at_least"],
        "coverage_passed": coverage_passed,
        "balanced_accuracy_strictly_greater_than": gate_policy[
            "balanced_accuracy_strictly_greater_than"
        ],
        "balanced_accuracy_passed": balanced_accuracy_passed,
        "passed": coverage_passed and balanced_accuracy_passed,
    }


def _model_receipt(model: FittedModel) -> dict[str, Any]:
    return {
        "classifier": "standardized_nearest_centroid",
        "fit_partition": "train",
        "active_features": [FEATURE_NAMES[index] for index in model.active_indices],
        "dropped_zero_variance_features": [
            name
            for index, name in enumerate(FEATURE_NAMES)
            if index not in model.active_indices
        ],
        "feature_means": [_rounded(value) for value in model.means],
        "feature_scales": [_rounded(value) for value in model.scales],
        "centroids": {
            cause: [_rounded(value) for value in model.centroids[cause]]
            for cause in CAUSES
        },
        "support_radii": {cause: _rounded(model.radii[cause]) for cause in CAUSES},
        "nearest_policy": "unique_and_within_selected_class_train_support_radius",
        "test_uses": 1,
    }


def evaluate_bound_observations(
    observations: Sequence[BoundObservation],
    policy: Mapping[str, Any],
    policy_sha256: str,
    oracle: Mapping[str, Any],
    reader: WindowReader,
) -> dict[str, Any]:
    partitions, intervals = preflight(observations, policy)
    attempted_reads = 0
    completed_reads = 0

    def counted_reader(
        source_path: str | os.PathLike[str],
        dataset_path: str,
        start: int,
        stop: int,
    ) -> Mapping[str, Any]:
        nonlocal attempted_reads, completed_reads
        attempted_reads += 1
        result = reader(source_path, dataset_path, start, stop)
        completed_reads += 1
        return result

    train_outcomes = _extract_role(partitions["train"], intervals, counted_reader)
    model = fit_model(partitions["train"], train_outcomes)
    validation_outcomes = _extract_role(
        partitions["validation"], intervals, counted_reader
    )
    validation_metrics, validation_reasons = _score_role(
        partitions["validation"], validation_outcomes, model
    )
    gate_policy = policy["validation_gate"]
    gate = _validation_gate(validation_metrics, gate_policy)
    gate_passed = gate["passed"]
    validation = {
        "metrics": validation_metrics,
        "gate": gate,
    }

    test_metrics: dict[str, Any] | None = None
    test_reasons: Counter[str] | None = None
    if gate_passed:
        test_outcomes = _extract_role(partitions["test"], intervals, counted_reader)
        test_metrics, test_reasons = _score_role(
            partitions["test"], test_outcomes, model
        )

    verified_selected_windows = sum(
        outcome.verified_windows
        for outcomes in (train_outcomes, validation_outcomes)
        for outcome in outcomes.values()
    )
    if gate_passed:
        verified_selected_windows += sum(
            outcome.verified_windows for outcome in test_outcomes.values()
        )

    minimum_extent = min(
        item.sample_count for role in SPLITS for item in partitions[role]
    )
    report = {
        "schema": REPORT_SCHEMA,
        "status": "pass" if gate_passed else "validation_failed",
        "provenance": {
            "record_id": COMPILER.RECORD_ID,
            "oracle_schema": oracle["schema"],
            "oracle_inventory_id": oracle["inventory_id"],
            "oracle_integrity_basis": oracle["provenance"]["integrity_basis"],
            "policy_schema": policy["schema"],
            "policy_sha256": policy_sha256,
            "binding": "reconstructed_in_memory_from_oracle_compiler",
        },
        "scope": {
            "target": "controlled_cause",
            "classes": list(CAUSES),
            "assigned_relative_jamming_power": policy["slice"][
                "assigned_relative_jamming_power"
            ],
            "distance_meters": policy["slice"]["distance_meters"],
            "observations": 24,
            "complete_triplets": 8,
            "conditioning_group_counts": {
                field: len(
                    {item.groups[field] for role in SPLITS for item in partitions[role]}
                )
                for field in CONDITIONING_GROUPS
            },
        },
        "window_policy": {
            "minimum_extent_columns": minimum_extent,
            "window_columns": policy["window_policy"]["columns"],
            "intervals": [{"start": start, "stop": stop} for start, stop in intervals],
            "selected_bytes_per_window": WINDOW_BYTE_BUDGET,
            "planned_reads": 96,
            "planned_selected_bytes": 96 * WINDOW_BYTE_BUDGET,
            "attempted_reads": attempted_reads,
            "completed_reads": completed_reads,
            "failed_reader_calls": attempted_reads - completed_reads,
            "verified_selected_windows": verified_selected_windows,
            "verified_completed_selected_bytes": verified_selected_windows
            * WINDOW_BYTE_BUDGET,
            "formula": "floor(k*minimum_extent/5)-floor(window_columns/2)",
        },
        "feature_policy": policy["feature_policy"],
        "split_policy": policy["split_policy"],
        "split_receipts": _split_receipts(partitions),
        "model": _model_receipt(model),
        "validation": validation,
        "test_metrics": test_metrics,
        "abstentions": {
            "validation": {
                "count": sum(validation_reasons.values()),
                "reasons": dict(sorted(validation_reasons.items())),
            },
            "test": (
                None
                if test_reasons is None
                else {
                    "count": sum(test_reasons.values()),
                    "reasons": dict(sorted(test_reasons.items())),
                }
            ),
        },
        "limitations": list(LIMITATIONS),
    }
    render_report(report)
    return report


def _validate_report_value(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in {"path", "source_path", "dataset_path", "filename", "filenames"}:
                raise EvaluationInputError("report_contains_private_binding")
            _validate_report_value(item)
    elif isinstance(value, list):
        for item in value:
            _validate_report_value(item)
    elif isinstance(value, float) and not math.isfinite(value):
        raise EvaluationInputError("report_nonfinite_number")


def render_report(report: Mapping[str, Any]) -> bytes:
    if set(report) != TOP_LEVEL_FIELDS:
        raise EvaluationInputError("report_top_level_fields")
    _validate_report_value(report)
    try:
        encoded = (
            json.dumps(report, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise EvaluationInputError("report_not_json_serializable") from error
    if len(encoded) > MAX_REPORT_BYTES:
        raise EvaluationInputError("report_size_limit")
    return encoded


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    encoded = render_report(report)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or path.exists() and not path.is_file():
            raise EvaluationInputError("unsafe_report_path")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            path.chmod(0o600)
        finally:
            if temporary.exists():
                temporary.unlink()
    except EvaluationInputError:
        raise
    except OSError as error:
        raise EvaluationInputError("report_write_failed") from error


def identity_bound_reader(
    bindings: Sequence[BoundObservation], reader: WindowReader
) -> WindowReader:
    expected_by_path: dict[Path, SourceIdentity] = {}
    for binding in bindings:
        if binding.source_identity is None:
            raise EvaluationInputError("missing_source_identity")
        previous = expected_by_path.setdefault(
            binding.source_path, binding.source_identity
        )
        if previous != binding.source_identity:
            raise EvaluationInputError("conflicting_source_identity")

    def read(
        source_path: str | os.PathLike[str],
        dataset_path: str,
        start: int,
        stop: int,
    ) -> Mapping[str, Any]:
        path = Path(source_path)
        expected = expected_by_path.get(path)
        if expected is None or _source_identity(path) != expected:
            raise EvaluationInputError("source_changed_since_full_digest")
        result = reader(source_path, dataset_path, start, stop)
        if _source_identity(path) != expected:
            raise EvaluationInputError("source_changed_since_full_digest")
        return result

    return read


def run(
    oracle_path: Path,
    policy_path: Path,
    manifest: Path,
    raw_dir: Path,
    receipt_dir: Path,
    report_path: Path,
) -> dict[str, Any]:
    policy, policy_sha256 = load_policy(policy_path)
    oracle = load_oracle(oracle_path)
    bindings = reconstruct_bindings(oracle, manifest, raw_dir, receipt_dir)

    def selected_reader(
        source_path: str | os.PathLike[str],
        dataset_path: str,
        start: int,
        stop: int,
    ) -> Mapping[str, Any]:
        return HDF5_WINDOW.read_column_window(
            source_path,
            dataset_path,
            start,
            stop,
            byte_budget=WINDOW_BYTE_BUDGET,
        )

    report = evaluate_bound_observations(
        bindings,
        policy,
        policy_sha256,
        oracle,
        identity_bound_reader(bindings, selected_reader),
    )
    write_report(report_path, report)
    return report


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        report = run(
            arguments.oracle,
            arguments.policy,
            arguments.manifest,
            arguments.raw_dir,
            arguments.receipt_dir,
            arguments.report,
        )
    except EvaluationInputError as error:
        print(f"error: {error.code}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema": report["schema"],
                "status": report["status"],
                "validation_passed": report["validation"]["gate"]["passed"],
                "test_evaluated": report["test_metrics"] is not None,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
