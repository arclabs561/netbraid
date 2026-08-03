#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Evaluate exact-event cross-modal retrieval from the private XRF55 cache."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = ROOT / "data" / "derived" / "eval"
DEFAULT_ADAPTER = DEFAULT_INPUT_DIR / "xrf55-feature-cache-adapter.json"
DEFAULT_MATRICES = {
    modality: DEFAULT_INPUT_DIR / f"xrf55-feature-cache-{modality}.npy"
    for modality in ("wifi", "rfid", "mmwave")
}
DEFAULT_REPORT = DEFAULT_INPUT_DIR / "xrf55-cross-modal-retrieval-report.json"
REPORT_SCHEMA = "netbraid.xrf55_cross_modal_retrieval_eval.v0"
RIDGE_ALPHA = 0.1
MAX_ADAPTER_BYTES = 4 * 1024**2
MAX_MATRIX_BYTES = 16 * 1024**2
READ_CHUNK_BYTES = 1024**2
OPAQUE_ID = re.compile(r"[a-f0-9]{64}\Z")
MODALITY_DIRECTIONS = tuple(
    (source, target)
    for source in ("wifi", "rfid", "mmwave")
    for target in ("wifi", "rfid", "mmwave")
    if source != target
)


class Xrf55RetrievalError(RuntimeError):
    """Stable failure at the XRF55 retrieval-evaluation boundary."""


class DuplicateJsonKeyError(ValueError):
    """Raised when strict JSON contains a duplicate object key."""


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Xrf55RetrievalError("module_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FEATURES = _load_module("xrf55_features", HERE / "xrf55_features.py")


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    group_id: str
    repetition: int
    row: int
    split: str


@dataclass(frozen=True)
class LoadedCache:
    adapter: Mapping[str, Any]
    events: tuple[EventRecord, ...]
    matrices: Mapping[str, np.memmap]


@dataclass(frozen=True)
class Standardizer:
    means: np.ndarray
    scales: np.ndarray
    active: np.ndarray


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    document = {}
    for key, value in pairs:
        if key in document:
            raise DuplicateJsonKeyError(key)
        document[key] = value
    return document


def _load_json(path: Path) -> Any:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise Xrf55RetrievalError("adapter_unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not 0 < metadata.st_size <= MAX_ADAPTER_BYTES
    ):
        raise Xrf55RetrievalError("unsafe_adapter_path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Xrf55RetrievalError("adapter_open_failed") from error
    try:
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if _identity(opened) != _identity(metadata):
                raise Xrf55RetrievalError("adapter_identity_changed")
            encoded = source.read(MAX_ADAPTER_BYTES + 1)
            after = os.fstat(source.fileno())
            if (
                _identity(after) != _identity(metadata)
                or len(encoded) != metadata.st_size
            ):
                raise Xrf55RetrievalError("adapter_changed_during_read")
        return json.loads(encoded.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise Xrf55RetrievalError("invalid_adapter_json") from error


def _require_fields(document: Any, expected: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(document, Mapping) or set(document) != expected:
        raise Xrf55RetrievalError(code)
    return document


def _parse_events(documents: Any) -> tuple[EventRecord, ...]:
    if not isinstance(documents, list) or len(documents) != 160:
        raise Xrf55RetrievalError("event_count_mismatch")
    events = []
    for index, raw in enumerate(documents):
        item = _require_fields(
            raw,
            {"event_id", "group_id", "repetition", "row", "split"},
            "invalid_event_schema",
        )
        event_id = item["event_id"]
        group_id = item["group_id"]
        repetition = item["repetition"]
        row = item["row"]
        split = item["split"]
        if (
            not isinstance(event_id, str)
            or OPAQUE_ID.fullmatch(event_id) is None
            or not isinstance(group_id, str)
            or OPAQUE_ID.fullmatch(group_id) is None
            or type(repetition) is not int
            or repetition not in FEATURES.PUBLISHER_REPETITIONS
            or type(row) is not int
            or row != index
            or split
            != ("train" if repetition in FEATURES.TRAIN_REPETITIONS else "test")
        ):
            raise Xrf55RetrievalError("invalid_event_record")
        events.append(EventRecord(event_id, group_id, repetition, row, split))
    if len({event.event_id for event in events}) != len(events):
        raise Xrf55RetrievalError("duplicate_event_id")
    by_group: defaultdict[str, set[int]] = defaultdict(set)
    for event in events:
        by_group[event.group_id].add(event.repetition)
    if len(by_group) != 8 or any(
        repetitions != set(FEATURES.PUBLISHER_REPETITIONS)
        for repetitions in by_group.values()
    ):
        raise Xrf55RetrievalError("candidate_group_contract_mismatch")
    return tuple(events)


def _validate_adapter(
    document: Any,
) -> tuple[Mapping[str, Any], tuple[EventRecord, ...]]:
    adapter = _require_fields(
        document,
        {
            "schema",
            "provenance",
            "integrity",
            "feature_policy",
            "split_policy",
            "events",
            "counts",
            "privacy",
        },
        "invalid_adapter_schema",
    )
    if adapter["schema"] != FEATURES.SCHEMA:
        raise Xrf55RetrievalError("adapter_schema_mismatch")
    if adapter["feature_policy"] != FEATURES.feature_policy_document():
        raise Xrf55RetrievalError("feature_policy_mismatch")
    if adapter["split_policy"] != {
        "candidate_set": "same_opaque_performer_action_group",
        "publisher_train_repetitions": sorted(FEATURES.TRAIN_REPETITIONS),
        "publisher_test_repetitions": sorted(FEATURES.TEST_REPETITIONS),
    }:
        raise Xrf55RetrievalError("split_policy_mismatch")
    if adapter["counts"] != {
        "archives": 2,
        "events": 160,
        "features_per_modality": FEATURES.FEATURE_COUNT,
        "groups": 8,
        "modalities": 3,
        "split_events": {"test": 48, "train": 112},
    }:
        raise Xrf55RetrievalError("adapter_count_mismatch")
    privacy = _require_fields(
        adapter["privacy"],
        {
            "archive_names_retained",
            "local_paths_retained",
            "member_names_retained",
            "raw_action_identifiers_retained",
            "raw_performer_identifiers_retained",
            "raw_scene_identifiers_retained",
        },
        "invalid_privacy_schema",
    )
    if any(type(value) is not int or value != 0 for value in privacy.values()):
        raise Xrf55RetrievalError("privacy_contract_mismatch")
    integrity = _require_fields(
        adapter["integrity"],
        {"all_archive_bytes_freshly_rehashed", "basis", "artifacts"},
        "invalid_integrity_schema",
    )
    if (
        integrity["all_archive_bytes_freshly_rehashed"] is not False
        or integrity["basis"]
        != "exact_size_and_fetch_receipt_metadata_plus_selected_member_crc"
    ):
        raise Xrf55RetrievalError("integrity_basis_mismatch")
    events = _parse_events(adapter["events"])
    return adapter, events


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_regular(path: Path, expected_bytes: int) -> tuple[str, tuple[int, ...]]:
    try:
        before = path.lstat()
    except OSError as error:
        raise Xrf55RetrievalError("matrix_unavailable") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size != expected_bytes
        or not 0 < before.st_size <= MAX_MATRIX_BYTES
    ):
        raise Xrf55RetrievalError("unsafe_matrix_path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Xrf55RetrievalError("matrix_open_failed") from error
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if _identity(opened) != _identity(before):
            raise Xrf55RetrievalError("matrix_identity_changed")
        while chunk := source.read(READ_CHUNK_BYTES):
            digest.update(chunk)
        after = os.fstat(source.fileno())
        if _identity(after) != _identity(before):
            raise Xrf55RetrievalError("matrix_changed_during_hash")
    return digest.hexdigest(), _identity(before)


def _load_matrix(path: Path, artifact: Any) -> np.memmap:
    contract = _require_fields(
        artifact, {"bytes", "dtype", "sha256", "shape"}, "invalid_artifact_schema"
    )
    expected_bytes = contract["bytes"]
    if (
        type(expected_bytes) is not int
        or contract["dtype"] != "<f8"
        or contract["shape"] != [160, FEATURES.FEATURE_COUNT]
        or not isinstance(contract["sha256"], str)
        or OPAQUE_ID.fullmatch(contract["sha256"]) is None
    ):
        raise Xrf55RetrievalError("invalid_artifact_contract")
    digest, identity = _hash_regular(path, expected_bytes)
    if digest != contract["sha256"]:
        raise Xrf55RetrievalError("matrix_digest_mismatch")
    try:
        matrix = np.load(path, mmap_mode="r", allow_pickle=False)
    except (OSError, ValueError) as error:
        raise Xrf55RetrievalError("matrix_npy_invalid") from error
    try:
        after = path.lstat()
    except OSError as error:
        raise Xrf55RetrievalError("matrix_unavailable") from error
    if (
        not isinstance(matrix, np.memmap)
        or matrix.mode != "r"
        or matrix.dtype.str != "<f8"
        or matrix.shape != (160, FEATURES.FEATURE_COUNT)
        or _identity(after) != identity
        or not bool(np.isfinite(matrix).all())
    ):
        raise Xrf55RetrievalError("matrix_contract_mismatch")
    return matrix


def load_cache(adapter_path: Path, matrix_paths: Mapping[str, Path]) -> LoadedCache:
    adapter, events = _validate_adapter(_load_json(adapter_path))
    integrity = adapter["integrity"]
    artifacts = _require_fields(
        integrity["artifacts"], set(FEATURES.MODALITIES), "artifact_set_mismatch"
    )
    if set(matrix_paths) != set(FEATURES.MODALITIES):
        raise Xrf55RetrievalError("matrix_path_set_mismatch")
    matrices = {
        modality: _load_matrix(matrix_paths[modality], artifacts[modality])
        for modality in FEATURES.MODALITIES
    }
    return LoadedCache(adapter, events, matrices)


def _fit_standardizer(matrix: np.ndarray) -> Standardizer:
    means = np.mean(matrix, axis=0, dtype=np.float64)
    centered = matrix - means
    scales = np.sqrt(np.mean(centered * centered, axis=0, dtype=np.float64))
    tolerance = np.finfo(np.float64).eps * np.maximum(1.0, np.abs(means))
    active = scales > tolerance
    if not bool(active.any()):
        raise Xrf55RetrievalError("no_active_features")
    return Standardizer(means, scales, active)


def _standardize(matrix: np.ndarray, policy: Standardizer) -> np.ndarray:
    return (matrix[:, policy.active] - policy.means[policy.active]) / policy.scales[
        policy.active
    ]


def _standardize_full(matrix: np.ndarray, policy: Standardizer) -> np.ndarray:
    scales = np.where(policy.active, policy.scales, 1.0)
    result = (matrix - policy.means) / scales
    result[:, ~policy.active] = 0.0
    return result


def _ridge_weights(source: np.ndarray, target: np.ndarray) -> np.ndarray:
    gram = source.T @ source
    regularized = gram + RIDGE_ALPHA * np.eye(gram.shape[0], dtype=np.float64)
    try:
        weights = np.linalg.solve(regularized, source.T @ target)
    except np.linalg.LinAlgError as error:
        raise Xrf55RetrievalError("ridge_fit_failed") from error
    if not bool(np.isfinite(weights).all()):
        raise Xrf55RetrievalError("ridge_fit_nonfinite")
    return weights


def _rank(
    prediction: np.ndarray, candidates: Sequence[tuple[str, np.ndarray]], truth: str
) -> int:
    scored = []
    for event_id, candidate in candidates:
        difference = prediction - candidate
        distance = float(difference @ difference)
        if not math.isfinite(distance):
            raise Xrf55RetrievalError("nonfinite_retrieval_distance")
        scored.append((distance, event_id))
    ordered = [event_id for _, event_id in sorted(scored)]
    try:
        return ordered.index(truth) + 1
    except ValueError as error:
        raise Xrf55RetrievalError("truth_not_in_candidate_set") from error


def _metrics(ranks: Sequence[int]) -> dict[str, Any]:
    if not ranks:
        raise Xrf55RetrievalError("empty_metric_input")
    reciprocal_rank_sum = sum(1.0 / rank for rank in ranks)
    top1 = sum(rank == 1 for rank in ranks)
    return {
        "mean_rank": round(sum(ranks) / len(ranks), 12),
        "mrr": round(reciprocal_rank_sum / len(ranks), 12),
        "queries": len(ranks),
        "top1_correct": top1,
        "top1_rate": round(top1 / len(ranks), 12),
    }


def _evaluate_direction(
    cache: LoadedCache, source_name: str, target_name: str
) -> dict[str, Any]:
    train_rows = [event.row for event in cache.events if event.split == "train"]
    test_events = [event for event in cache.events if event.split == "test"]
    source_train = np.asarray(cache.matrices[source_name][train_rows], dtype=np.float64)
    target_train = np.asarray(cache.matrices[target_name][train_rows], dtype=np.float64)
    source_policy = _fit_standardizer(source_train)
    target_policy = _fit_standardizer(target_train)
    standardized_source_train = _standardize(source_train, source_policy)
    standardized_target_train = _standardize(target_train, target_policy)
    weights = _ridge_weights(standardized_source_train, standardized_target_train)

    source_test = np.asarray(
        cache.matrices[source_name][[event.row for event in test_events]],
        dtype=np.float64,
    )
    target_test = np.asarray(
        cache.matrices[target_name][[event.row for event in test_events]],
        dtype=np.float64,
    )
    learned_predictions = _standardize(source_test, source_policy) @ weights
    learned_targets = _standardize(target_test, target_policy)
    unaligned_predictions = _standardize_full(source_test, source_policy)
    unaligned_targets = _standardize_full(target_test, target_policy)

    positions = {event.event_id: index for index, event in enumerate(test_events)}
    by_group: defaultdict[str, list[EventRecord]] = defaultdict(list)
    for event in test_events:
        by_group[event.group_id].append(event)
    if len(by_group) != 8 or any(len(events) != 6 for events in by_group.values()):
        raise Xrf55RetrievalError("test_candidate_set_mismatch")

    learned_ranks = []
    unaligned_ranks = []
    per_group = []
    for group_id in sorted(by_group):
        group_events = sorted(by_group[group_id], key=lambda event: event.event_id)
        learned_candidates = [
            (event.event_id, learned_targets[positions[event.event_id]])
            for event in group_events
        ]
        unaligned_candidates = [
            (event.event_id, unaligned_targets[positions[event.event_id]])
            for event in group_events
        ]
        group_learned = []
        group_unaligned = []
        for event in group_events:
            position = positions[event.event_id]
            group_learned.append(
                _rank(learned_predictions[position], learned_candidates, event.event_id)
            )
            group_unaligned.append(
                _rank(
                    unaligned_predictions[position],
                    unaligned_candidates,
                    event.event_id,
                )
            )
        learned_ranks.extend(group_learned)
        unaligned_ranks.extend(group_unaligned)
        per_group.append(
            {
                "group_id": group_id,
                "learned": _metrics(group_learned),
                "unaligned": _metrics(group_unaligned),
            }
        )
    return {
        "source": source_name,
        "target": target_name,
        "model": {
            "ridge_alpha": RIDGE_ALPHA,
            "source_active_features": int(source_policy.active.sum()),
            "target_active_features": int(target_policy.active.sum()),
            "train_pairs": len(train_rows),
        },
        "learned": _metrics(learned_ranks),
        "unaligned": _metrics(unaligned_ranks),
        "per_group": per_group,
    }


def evaluate(cache: LoadedCache) -> dict[str, Any]:
    directions = [
        _evaluate_direction(cache, source, target)
        for source, target in MODALITY_DIRECTIONS
    ]
    return {
        "schema": REPORT_SCHEMA,
        "task": {
            "candidate_events_per_query": 6,
            "candidate_policy": "same_opaque_performer_action_group",
            "distance": "squared_euclidean_in_train_standardized_target_space",
            "exact_event_retrieval": True,
            "fit_split": "publisher_repetitions_1_through_14",
            "test_split": "publisher_repetitions_15_through_20",
        },
        "chance_reference": {
            "mrr": round(sum(1.0 / rank for rank in range(1, 7)) / 6, 12),
            "top1_rate": round(1.0 / 6.0, 12),
        },
        "matrix_access": {
            "allow_pickle": False,
            "kind": "numpy.memmap",
            "mode": "r",
        },
        "directions": directions,
        "counts": {
            "directions": len(directions),
            "groups": 8,
            "test_queries_per_direction": 48,
            "train_pairs_per_direction": 112,
        },
        "privacy": dict(cache.adapter["privacy"]),
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise Xrf55RetrievalError("unsafe_report_directory")
    if os.path.lexists(path):
        target = path.lstat()
        if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
            raise Xrf55RetrievalError("unsafe_report_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    for modality in FEATURES.MODALITIES:
        parser.add_argument(
            f"--{modality}-matrix", type=Path, default=DEFAULT_MATRICES[modality]
        )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    matrix_paths = {
        modality: getattr(arguments, f"{modality}_matrix")
        for modality in FEATURES.MODALITIES
    }
    try:
        cache = load_cache(arguments.adapter, matrix_paths)
        report = evaluate(cache)
        _write_report(arguments.report, report)
    except (OSError, ValueError, Xrf55RetrievalError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(report["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
