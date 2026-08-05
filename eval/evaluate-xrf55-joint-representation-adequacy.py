#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Evaluate the preregistered XRF55 joint representation privately."""

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
DEFAULT_CACHE_DIR = ROOT / "data" / "derived" / "eval" / "xrf55-joint-representation-v0"
DEFAULT_REPORT = DEFAULT_CACHE_DIR / "representation-adequacy-report.json"

ROLE_CACHE_SCHEMA = "netbraid.xrf55_joint_role_cache.v0"
REPORT_SCHEMA = "netbraid.xrf55_joint_representation_adequacy.v0"
PUBLISHER_IMPLEMENTATION_REVISION = "6cf95821e45277ee97c55e9c68d67bc7e33962ad"
ROLE_ORDER = ("train", "calibration", "validation")
MODALITIES = ("wifi", "rfid", "mmwave")
PAIR_METHODS = ("wifi_rfid", "wifi_mmwave", "rfid_mmwave")
PAIR_MODALITIES = {
    "wifi_rfid": ("wifi", "rfid"),
    "wifi_mmwave": ("wifi", "mmwave"),
    "rfid_mmwave": ("rfid", "mmwave"),
}
RIDGE_ALPHA = 0.1
FEATURE_COUNT = 512
EVENTS_PER_GROUP = 20
MAX_JSON_BYTES = 4 * 1024**2
MAX_MATRIX_BYTES = 2 * 1024**2
READ_CHUNK_BYTES = 1024**2
OPAQUE_ID = re.compile(r"[a-f0-9]{64}\Z")


class Xrf55JointEvaluationError(RuntimeError):
    """Stable failure at the joint-representation evaluator boundary."""


class DuplicateJsonKeyError(ValueError):
    """Raised when strict JSON contains a duplicate object key."""


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Xrf55JointEvaluationError("module_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


JOINT = _load_module("xrf55_joint_features", HERE / "xrf55_joint_features.py")
ROLE_GROUP_RANKS = JOINT.ROLE_GROUP_RANKS
ROLE_EVENT_COUNTS = JOINT.ROLE_EVENT_COUNTS
ROLE_GROUP_COUNTS = {
    role: last - first + 1 for role, (first, last) in ROLE_GROUP_RANKS.items()
}


@dataclass(frozen=True)
class RolePaths:
    adapter: Path
    matrices: Mapping[str, Path]


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    group_id: str
    role: str
    row: int


@dataclass(frozen=True)
class RoleAdapter:
    role: str
    document: Mapping[str, Any]
    digest: str
    source_binding: Mapping[str, str]
    source_digest: str
    feature_policy_digest: str
    role_policy_digest: str
    events: tuple[EventRecord, ...]
    artifacts: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class LoadedRole:
    adapter: RoleAdapter
    matrices: Mapping[str, np.memmap]


@dataclass(frozen=True)
class Standardizer:
    means: np.ndarray
    scales: np.ndarray
    active: np.ndarray


@dataclass(frozen=True)
class DirectionModel:
    source: str
    target: str
    weights: np.ndarray
    normalizer: float


@dataclass(frozen=True)
class FitBundle:
    standardizers: Mapping[str, Standardizer]
    directions: Mapping[tuple[str, str], DirectionModel]
    digest: str


@dataclass(frozen=True)
class GroupScores:
    group_id: str
    same: np.ndarray
    methods: Mapping[str, np.ndarray]


@dataclass(frozen=True)
class ScoredRole:
    groups: tuple[GroupScores, ...]


@dataclass(frozen=True)
class Thresholds:
    same: float
    different: float


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise DuplicateJsonKeyError(key)
        document[key] = value
    return document


def _reject_json_constant(value: str) -> None:
    raise ValueError(value)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_regular_bytes(path: Path, maximum: int, kind: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise Xrf55JointEvaluationError(f"{kind}_unavailable") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or not 0 < before.st_size <= maximum
    ):
        raise Xrf55JointEvaluationError(f"unsafe_{kind}_path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Xrf55JointEvaluationError(f"{kind}_open_failed") from error
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if _identity(opened) != _identity(before):
            raise Xrf55JointEvaluationError(f"{kind}_identity_changed")
        encoded = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if _identity(after) != _identity(before) or len(encoded) != before.st_size:
            raise Xrf55JointEvaluationError(f"{kind}_changed_during_read")
    return encoded


def _load_json(path: Path, kind: str) -> tuple[Any, bytes]:
    encoded = _read_regular_bytes(path, MAX_JSON_BYTES, kind)
    try:
        document = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
        ValueError,
    ) as error:
        raise Xrf55JointEvaluationError(f"invalid_{kind}_json") from error
    return document, encoded


def _require_fields(document: Any, expected: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(document, Mapping) or set(document) != expected:
        raise Xrf55JointEvaluationError(code)
    return document


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise Xrf55JointEvaluationError("noncanonical_document") from error


def _json_digest(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + _canonical_json(value)).hexdigest()


def role_paths(directory: Path, role: str) -> RolePaths:
    if role not in ROLE_ORDER:
        raise Xrf55JointEvaluationError("invalid_role")
    stem = f"xrf55-joint-{role}"
    return RolePaths(
        directory / f"{stem}-adapter.json",
        {modality: directory / f"{stem}-{modality}.npy" for modality in MODALITIES},
    )


def cache_paths(directory: Path) -> dict[str, RolePaths]:
    return {role: role_paths(directory, role) for role in ROLE_ORDER}


def _parse_provenance(raw: Any) -> Mapping[str, Any]:
    provenance = _require_fields(
        raw,
        {
            "dataset",
            "publisher_implementation_revision",
            "publisher_project",
        },
        "invalid_provenance_schema",
    )
    if (
        provenance["dataset"] != "XRF55 processed RF arrays"
        or provenance["publisher_implementation_revision"]
        != PUBLISHER_IMPLEMENTATION_REVISION
        or provenance["publisher_project"] != "https://aiotgroup.github.io/XRF55/"
    ):
        raise Xrf55JointEvaluationError("provenance_contract_mismatch")
    return provenance


def _parse_source_binding(raw: Any) -> tuple[Mapping[str, str], str]:
    source = _require_fields(
        raw,
        {"archive_profile_set_sha256", "archive_receipt_set_sha256"},
        "invalid_source_schema",
    )
    if any(
        not isinstance(value, str) or OPAQUE_ID.fullmatch(value) is None
        for value in source.values()
    ):
        raise Xrf55JointEvaluationError("source_digest_mismatch")
    return source, _json_digest(b"netbraid.xrf55-joint.source-binding.v0\x00", source)


def _role_policy(role: str) -> dict[str, Any]:
    first, last = ROLE_GROUP_RANKS[role]
    return {
        **JOINT.role_policy_document(),
        "first_group_rank": first,
        "last_group_rank": last,
        "modalities_colocated": list(MODALITIES),
        "role": role,
        "whole_groups_disjoint": True,
    }


def _parse_events(role: str, documents: Any) -> tuple[EventRecord, ...]:
    expected_count = ROLE_EVENT_COUNTS[role]
    if not isinstance(documents, list) or len(documents) != expected_count:
        raise Xrf55JointEvaluationError("role_event_count_mismatch")
    events = []
    for index, raw in enumerate(documents):
        item = _require_fields(
            raw,
            {"event_id", "group_id", "role", "row"},
            "invalid_role_event_schema",
        )
        event_id = item["event_id"]
        group_id = item["group_id"]
        if (
            not isinstance(event_id, str)
            or OPAQUE_ID.fullmatch(event_id) is None
            or not isinstance(group_id, str)
            or OPAQUE_ID.fullmatch(group_id) is None
            or item["role"] != role
            or type(item["row"]) is not int
            or item["row"] != index
        ):
            raise Xrf55JointEvaluationError("invalid_role_event_record")
        events.append(EventRecord(event_id, group_id, role, index))
    if len({event.event_id for event in events}) != expected_count:
        raise Xrf55JointEvaluationError("duplicate_role_event_id")
    by_group: defaultdict[str, int] = defaultdict(int)
    for event in events:
        by_group[event.group_id] += 1
    if len(by_group) != ROLE_GROUP_COUNTS[role] or any(
        count != EVENTS_PER_GROUP for count in by_group.values()
    ):
        raise Xrf55JointEvaluationError("role_group_event_contract_mismatch")
    return tuple(events)


def _validate_artifacts(role: str, raw: Any) -> Mapping[str, Mapping[str, Any]]:
    artifacts = _require_fields(raw, set(MODALITIES), "artifact_set_mismatch")
    expected_shape = [ROLE_EVENT_COUNTS[role], FEATURE_COUNT]
    validated = {}
    for modality in MODALITIES:
        artifact = _require_fields(
            artifacts[modality],
            {"bytes", "dtype", "sha256", "shape"},
            "invalid_artifact_schema",
        )
        if (
            type(artifact["bytes"]) is not int
            or not 0 < artifact["bytes"] <= MAX_MATRIX_BYTES
            or artifact["dtype"] != "<f8"
            or artifact["shape"] != expected_shape
            or not isinstance(artifact["sha256"], str)
            or OPAQUE_ID.fullmatch(artifact["sha256"]) is None
        ):
            raise Xrf55JointEvaluationError("invalid_artifact_contract")
        validated[modality] = artifact
    return validated


def _load_role_adapter(role: str, paths: RolePaths) -> RoleAdapter:
    document, encoded = _load_json(paths.adapter, "adapter")
    adapter = _require_fields(
        document,
        {
            "counts",
            "events",
            "feature_policy",
            "integrity",
            "privacy",
            "provenance",
            "role_policy",
            "schema",
        },
        "invalid_role_adapter_schema",
    )
    if adapter["schema"] != ROLE_CACHE_SCHEMA:
        raise Xrf55JointEvaluationError("role_adapter_schema_mismatch")
    _parse_provenance(adapter["provenance"])
    feature_policy = JOINT.feature_policy_document()
    feature_digest = _json_digest(
        b"netbraid.xrf55-joint.feature-policy.v0\x00", feature_policy
    )
    if adapter["feature_policy"] != feature_policy:
        raise Xrf55JointEvaluationError("feature_policy_mismatch")
    role_policy = _role_policy(role)
    role_digest = _json_digest(
        b"netbraid.xrf55-joint.role-policy.v0\x00",
        JOINT.role_policy_document(),
    )
    if adapter["role_policy"] != role_policy:
        raise Xrf55JointEvaluationError("role_policy_mismatch")
    counts = _require_fields(
        adapter["counts"],
        {
            "archives",
            "events",
            "features_per_modality",
            "groups",
            "modalities",
            "roles",
        },
        "invalid_role_count_schema",
    )
    if counts != {
        "archives": 2,
        "events": ROLE_EVENT_COUNTS[role],
        "features_per_modality": FEATURE_COUNT,
        "groups": ROLE_GROUP_COUNTS[role],
        "modalities": len(MODALITIES),
        "roles": 1,
    }:
        raise Xrf55JointEvaluationError("role_count_mismatch")
    privacy = _require_fields(
        adapter["privacy"],
        {
            "archive_names_retained",
            "local_paths_retained",
            "member_names_retained",
            "raw_action_identifiers_retained",
            "raw_labels_retained",
            "raw_performer_identifiers_retained",
            "raw_repetition_identifiers_retained",
            "raw_scene_identifiers_retained",
            "raw_source_values_retained",
        },
        "invalid_privacy_schema",
    )
    if any(type(value) is not int or value != 0 for value in privacy.values()):
        raise Xrf55JointEvaluationError("privacy_contract_mismatch")
    integrity = _require_fields(
        adapter["integrity"],
        {
            "all_archive_bytes_freshly_rehashed",
            "artifacts",
            "basis",
            "feature_policy_sha256",
            "role_policy_sha256",
            "source",
        },
        "invalid_integrity_schema",
    )
    if (
        integrity["all_archive_bytes_freshly_rehashed"] is not False
        or integrity["basis"]
        != "exact_size_and_fetch_receipt_metadata_plus_selected_member_crc"
    ):
        raise Xrf55JointEvaluationError("integrity_basis_mismatch")
    if integrity["feature_policy_sha256"] != feature_digest:
        raise Xrf55JointEvaluationError("feature_policy_digest_mismatch")
    if integrity["role_policy_sha256"] != role_digest:
        raise Xrf55JointEvaluationError("role_policy_digest_mismatch")
    source_binding, source_digest = _parse_source_binding(integrity["source"])
    artifacts = _validate_artifacts(role, integrity["artifacts"])
    events = _parse_events(role, adapter["events"])
    return RoleAdapter(
        role,
        adapter,
        hashlib.sha256(encoded).hexdigest(),
        source_binding,
        source_digest,
        feature_digest,
        role_digest,
        events,
        artifacts,
    )


def _hash_regular(path: Path, expected_bytes: int) -> tuple[str, tuple[int, ...]]:
    try:
        before = path.lstat()
    except OSError as error:
        raise Xrf55JointEvaluationError("matrix_unavailable") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size != expected_bytes
        or not 0 < before.st_size <= MAX_MATRIX_BYTES
    ):
        raise Xrf55JointEvaluationError("unsafe_matrix_path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Xrf55JointEvaluationError("matrix_open_failed") from error
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if _identity(opened) != _identity(before):
            raise Xrf55JointEvaluationError("matrix_identity_changed")
        while chunk := source.read(READ_CHUNK_BYTES):
            digest.update(chunk)
        after = os.fstat(source.fileno())
        if _identity(after) != _identity(before):
            raise Xrf55JointEvaluationError("matrix_changed_during_hash")
    return digest.hexdigest(), _identity(before)


def _load_matrix(
    path: Path, artifact: Mapping[str, Any], expected_shape: tuple[int, int]
) -> np.memmap:
    digest, identity = _hash_regular(path, artifact["bytes"])
    if digest != artifact["sha256"]:
        raise Xrf55JointEvaluationError("matrix_digest_mismatch")
    try:
        matrix = np.load(path, mmap_mode="r", allow_pickle=False)
    except (OSError, ValueError) as error:
        raise Xrf55JointEvaluationError("matrix_npy_invalid") from error
    try:
        after = path.lstat()
    except OSError as error:
        raise Xrf55JointEvaluationError("matrix_unavailable") from error
    if (
        not isinstance(matrix, np.memmap)
        or matrix.mode != "r"
        or matrix.flags.writeable
        or matrix.dtype.str != "<f8"
        or matrix.shape != expected_shape
        or _identity(after) != identity
        or not bool(np.isfinite(matrix).all())
    ):
        raise Xrf55JointEvaluationError("matrix_contract_mismatch")
    return matrix


def _load_role_matrices(adapter: RoleAdapter, paths: RolePaths) -> LoadedRole:
    if set(paths.matrices) != set(MODALITIES):
        raise Xrf55JointEvaluationError("matrix_path_set_mismatch")
    expected_shape = (ROLE_EVENT_COUNTS[adapter.role], FEATURE_COUNT)
    matrices = {
        modality: _load_matrix(
            paths.matrices[modality], adapter.artifacts[modality], expected_shape
        )
        for modality in MODALITIES
    }
    return LoadedRole(adapter, matrices)


def _verify_adapter_set(adapters: Mapping[str, RoleAdapter]) -> None:
    if set(adapters) != set(ROLE_ORDER):
        raise Xrf55JointEvaluationError("role_set_mismatch")
    if len({adapter.source_digest for adapter in adapters.values()}) != 1:
        raise Xrf55JointEvaluationError("role_source_mismatch")
    if len({adapter.feature_policy_digest for adapter in adapters.values()}) != 1:
        raise Xrf55JointEvaluationError("role_feature_policy_mismatch")
    group_owner: dict[str, str] = {}
    event_owner: dict[str, str] = {}
    for role in ROLE_ORDER:
        for event in adapters[role].events:
            prior_group = group_owner.setdefault(event.group_id, role)
            if prior_group != role:
                raise Xrf55JointEvaluationError("role_group_overlap")
            prior_event = event_owner.setdefault(event.event_id, role)
            if prior_event != role:
                raise Xrf55JointEvaluationError("role_event_overlap")


def load_roles(paths_by_role: Mapping[str, RolePaths]) -> dict[str, LoadedRole]:
    if set(paths_by_role) != set(ROLE_ORDER):
        raise Xrf55JointEvaluationError("role_path_set_mismatch")
    adapters = {
        role: _load_role_adapter(role, paths_by_role[role]) for role in ROLE_ORDER
    }
    _verify_adapter_set(adapters)
    return {
        role: _load_role_matrices(adapters[role], paths_by_role[role])
        for role in ROLE_ORDER
    }


def _fit_standardizer(matrix: np.ndarray) -> Standardizer:
    values = np.asarray(matrix, dtype=np.float64)
    means = np.mean(values, axis=0, dtype=np.float64)
    centered = values - means
    scales = np.sqrt(np.mean(centered * centered, axis=0, dtype=np.float64))
    tolerance = np.finfo(np.float64).eps * np.maximum(1.0, np.abs(means))
    active = scales > tolerance
    if (
        not bool(active.any())
        or not bool(np.isfinite(means).all())
        or not bool(np.isfinite(scales).all())
    ):
        raise Xrf55JointEvaluationError("no_active_features")
    return Standardizer(means, scales, active)


def _standardize(matrix: np.ndarray, policy: Standardizer) -> np.ndarray:
    result = (
        np.asarray(matrix, dtype=np.float64)[:, policy.active]
        - policy.means[policy.active]
    ) / policy.scales[policy.active]
    if not bool(np.isfinite(result).all()):
        raise Xrf55JointEvaluationError("nonfinite_standardized_feature")
    return result


def _ridge_weights(source: np.ndarray, target: np.ndarray) -> np.ndarray:
    gram = source.T @ source
    regularized = gram + RIDGE_ALPHA * np.eye(gram.shape[0], dtype=np.float64)
    try:
        weights = np.linalg.solve(regularized, source.T @ target)
    except np.linalg.LinAlgError as error:
        raise Xrf55JointEvaluationError("ridge_fit_failed") from error
    if not bool(np.isfinite(weights).all()):
        raise Xrf55JointEvaluationError("ridge_fit_nonfinite")
    return weights


def _mean_squared_residual(prediction: np.ndarray, target: np.ndarray) -> np.ndarray:
    difference = prediction - target
    result = np.mean(difference * difference, axis=-1, dtype=np.float64)
    if not bool(np.isfinite(result).all()) or bool((result < 0.0).any()):
        raise Xrf55JointEvaluationError("nonfinite_residual")
    return result


def _update_array_digest(digest: Any, array: np.ndarray) -> None:
    contiguous = np.ascontiguousarray(array)
    digest.update(contiguous.dtype.str.encode("ascii"))
    digest.update(b"\x00")
    digest.update(json.dumps(contiguous.shape).encode("ascii"))
    digest.update(b"\x00")
    digest.update(contiguous.tobytes())


def _fit_digest(
    standardizers: Mapping[str, Standardizer],
    directions: Mapping[tuple[str, str], DirectionModel],
) -> str:
    digest = hashlib.sha256(b"netbraid.xrf55-joint-ridge-model.v0\x00")
    for modality in MODALITIES:
        digest.update(modality.encode("ascii") + b"\x00")
        policy = standardizers[modality]
        _update_array_digest(digest, policy.means)
        _update_array_digest(digest, policy.scales)
        _update_array_digest(digest, policy.active)
    for source in MODALITIES:
        for target in MODALITIES:
            if source == target:
                continue
            model = directions[(source, target)]
            digest.update(source.encode("ascii") + b"\x00")
            digest.update(target.encode("ascii") + b"\x00")
            _update_array_digest(digest, model.weights)
            digest.update(model.normalizer.hex().encode("ascii") + b"\x00")
    return digest.hexdigest()


def fit_train_role(train: LoadedRole) -> FitBundle:
    if train.adapter.role != "train":
        raise Xrf55JointEvaluationError("fit_role_mismatch")
    standardizers = {
        modality: _fit_standardizer(train.matrices[modality]) for modality in MODALITIES
    }
    standardized = {
        modality: _standardize(train.matrices[modality], standardizers[modality])
        for modality in MODALITIES
    }
    directions = {}
    for source in MODALITIES:
        for target in MODALITIES:
            if source == target:
                continue
            weights = _ridge_weights(standardized[source], standardized[target])
            residuals = _mean_squared_residual(
                standardized[source] @ weights, standardized[target]
            )
            normalizer = float(np.mean(residuals, dtype=np.float64))
            if not math.isfinite(normalizer) or normalizer <= 0.0:
                raise Xrf55JointEvaluationError("zero_train_residual_normalizer")
            directions[(source, target)] = DirectionModel(
                source, target, weights, normalizer
            )
    return FitBundle(
        standardizers,
        directions,
        _fit_digest(standardizers, directions),
    )


def _direction_score_grid(
    standardized: Mapping[str, np.ndarray],
    rows: Sequence[int],
    model: DirectionModel,
) -> np.ndarray:
    source = standardized[model.source][rows]
    target = standardized[model.target][rows]
    prediction = source @ model.weights
    residual = _mean_squared_residual(
        prediction[:, np.newaxis, :], target[np.newaxis, :, :]
    )
    result = residual / model.normalizer
    if not bool(np.isfinite(result).all()) or bool((result < 0.0).any()):
        raise Xrf55JointEvaluationError("invalid_normalized_residual")
    return result


def score_role(role: LoadedRole, fit: FitBundle) -> ScoredRole:
    standardized = {
        modality: _standardize(role.matrices[modality], fit.standardizers[modality])
        for modality in MODALITIES
    }
    by_group: defaultdict[str, list[EventRecord]] = defaultdict(list)
    for event in role.adapter.events:
        by_group[event.group_id].append(event)
    if len(by_group) != ROLE_GROUP_COUNTS[role.adapter.role]:
        raise Xrf55JointEvaluationError("score_group_count_mismatch")
    groups = []
    for group_id in sorted(by_group):
        events = sorted(by_group[group_id], key=lambda event: event.event_id)
        if len(events) != EVENTS_PER_GROUP:
            raise Xrf55JointEvaluationError("score_group_size_mismatch")
        rows = [event.row for event in events]
        pair_scores = {}
        for method in PAIR_METHODS:
            left, right = PAIR_MODALITIES[method]
            forward = _direction_score_grid(
                standardized, rows, fit.directions[(left, right)]
            )
            reverse = _direction_score_grid(
                standardized, rows, fit.directions[(right, left)]
            ).T
            pair_scores[method] = ((forward + reverse) / 2.0).reshape(-1)
        same = np.eye(EVENTS_PER_GROUP, dtype=bool).reshape(-1)
        groups.append(GroupScores(group_id, same, pair_scores))
    return ScoredRole(tuple(groups))


def _quantile(values: np.ndarray, quantile: float) -> float:
    if values.size == 0 or not bool(np.isfinite(values).all()):
        raise Xrf55JointEvaluationError("invalid_calibration_class")
    result = float(np.quantile(values, quantile, method="linear"))
    if not math.isfinite(result) or result < 0.0:
        raise Xrf55JointEvaluationError("invalid_calibration_quantile")
    return result


def calibrate(scored: ScoredRole) -> dict[str, Thresholds]:
    same = np.concatenate([group.same for group in scored.groups])
    thresholds = {}
    for method in PAIR_METHODS:
        values = np.concatenate([group.methods[method] for group in scored.groups])
        thresholds[method] = Thresholds(
            _quantile(values[same], 0.9),
            _quantile(values[~same], 0.1),
        )
    return thresholds


def _threshold_document(thresholds: Mapping[str, Thresholds]) -> dict[str, Any]:
    return {
        method: {
            "different_threshold": thresholds[method].different.hex(),
            "ordered": thresholds[method].same < thresholds[method].different,
            "same_threshold": thresholds[method].same.hex(),
        }
        for method in PAIR_METHODS
    }


def _rate(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "denominator": denominator,
        "numerator": numerator,
        "rate": round(numerator / denominator, 12) if denominator else None,
    }


def metrics(
    scores: np.ndarray, same: np.ndarray, thresholds: Thresholds
) -> dict[str, Any]:
    values = np.asarray(scores, dtype=np.float64)
    references = np.asarray(same, dtype=bool)
    if (
        values.shape != references.shape
        or values.ndim != 1
        or values.size == 0
        or not bool(np.isfinite(values).all())
        or not thresholds.same < thresholds.different
    ):
        raise Xrf55JointEvaluationError("invalid_metric_input")
    predicted_same = values <= thresholds.same
    predicted_different = values >= thresholds.different
    abstained = ~(predicted_same | predicted_different)
    false_links = int((~references & predicted_same).sum())
    false_nonmatches = int((references & predicted_different).sum())
    same_support = int(references.sum())
    different_support = int((~references).sum())
    decided = int((~abstained).sum())
    errors = false_links + false_nonmatches
    return {
        "support": {
            "different": different_support,
            "same": same_support,
            "total": int(values.size),
        },
        "coverage": _rate(decided, int(values.size)),
        "abstention": _rate(int(abstained.sum()), int(values.size)),
        "selective_risk": _rate(errors, decided),
        "false_link": _rate(false_links, different_support),
        "false_nonmatch": _rate(false_nonmatches, same_support),
    }


def summarize(
    scored: ScoredRole, thresholds: Mapping[str, Thresholds]
) -> dict[str, Any]:
    overall_same = np.concatenate([group.same for group in scored.groups])
    result = {}
    for method in PAIR_METHODS:
        overall_scores = np.concatenate(
            [group.methods[method] for group in scored.groups]
        )
        result[method] = {
            "overall": metrics(overall_scores, overall_same, thresholds[method]),
            "by_group": {
                f"group_{index:02d}": metrics(
                    group.methods[method], group.same, thresholds[method]
                )
                for index, group in enumerate(scored.groups, start=1)
            },
        }
    return result


def _at_least(value: Mapping[str, Any], numerator: int, denominator: int) -> bool:
    return value["numerator"] * denominator >= numerator * value["denominator"]


def _at_most(value: Mapping[str, Any], numerator: int, denominator: int) -> bool:
    return value["numerator"] * denominator <= numerator * value["denominator"]


def validation_gate(summary: Mapping[str, Any]) -> dict[str, Any]:
    quality = {}
    for method in PAIR_METHODS:
        scopes = {
            "overall": summary[method]["overall"],
            **summary[method]["by_group"],
        }
        quality[method] = {
            scope: {
                "coverage_at_least_half": _at_least(metrics_["coverage"], 1, 2),
                "false_link_at_most_five_percent": _at_most(
                    metrics_["false_link"], 5, 100
                ),
                "false_nonmatch_at_most_ten_percent": _at_most(
                    metrics_["false_nonmatch"], 10, 100
                ),
            }
            for scope, metrics_ in scopes.items()
        }
    passed = all(
        all(checks.values())
        for method in quality.values()
        for checks in method.values()
    )
    return {"passed": passed, "quality": quality}


def _calibration_support(scored: ScoredRole) -> dict[str, Any]:
    def support(group: GroupScores) -> dict[str, int]:
        same = int(group.same.sum())
        return {
            "different": int(group.same.size - same),
            "same": same,
            "total": int(group.same.size),
        }

    same = sum(int(group.same.sum()) for group in scored.groups)
    total = sum(int(group.same.size) for group in scored.groups)
    return {
        "overall": {"different": total - same, "same": same, "total": total},
        "by_group": {
            f"group_{index:02d}": support(group)
            for index, group in enumerate(scored.groups, start=1)
        },
    }


def _role_bindings(roles: Mapping[str, LoadedRole]) -> dict[str, Any]:
    return {
        role: {
            "adapter_sha256": roles[role].adapter.digest,
            "matrix_sha256": {
                modality: roles[role].adapter.artifacts[modality]["sha256"]
                for modality in MODALITIES
            },
            "role_policy_sha256": roles[role].adapter.role_policy_digest,
        }
        for role in ROLE_ORDER
    }


def _privacy_document() -> dict[str, int]:
    return {
        "labels_retained": 0,
        "local_paths_retained": 0,
        "opaque_event_ids_retained": 0,
        "opaque_group_ids_retained": 0,
        "raw_feature_values_retained": 0,
        "raw_source_values_retained": 0,
    }


def evaluate_roles(roles: Mapping[str, LoadedRole]) -> dict[str, Any]:
    if set(roles) != set(ROLE_ORDER):
        raise Xrf55JointEvaluationError("role_set_mismatch")
    fit = fit_train_role(roles["train"])
    calibration_scores = score_role(roles["calibration"], fit)
    thresholds = calibrate(calibration_scores)
    ordered = all(
        threshold.same < threshold.different for threshold in thresholds.values()
    )
    report = {
        "schema": REPORT_SCHEMA,
        "status": "calibration_failed",
        "bindings": {
            "feature_policy_sha256": roles["train"].adapter.feature_policy_digest,
            "roles": _role_bindings(roles),
            "source": dict(roles["train"].adapter.source_binding),
            "source_binding_sha256": roles["train"].adapter.source_digest,
        },
        "matrix_access": {
            "allow_pickle": False,
            "kind": "numpy.memmap",
            "mode": "r",
        },
        "model": {
            "directed_maps": 6,
            "digest": fit.digest,
            "normalization": "train_positive_paired_mean_residual",
            "ridge_alpha": RIDGE_ALPHA.hex(),
            "standardization": "train_only_mean_population_std_active_coordinates",
        },
        "task": {
            "candidate_policy": "complete_20_by_20_ordered_grid_within_opaque_group",
            "methods": list(PAIR_METHODS),
            "quantiles": {"different": "q10-linear", "same": "q90-linear"},
            "relation": "same_event",
        },
        "privacy": _privacy_document(),
        "calibration": {
            "gate": {
                "all_pairs_ordered": ordered,
                "ordered": {
                    method: thresholds[method].same < thresholds[method].different
                    for method in PAIR_METHODS
                },
            },
            "support": _calibration_support(calibration_scores),
            "thresholds": _threshold_document(thresholds),
        },
        "validation": None,
    }
    if not ordered:
        return report
    validation_scores = score_role(roles["validation"], fit)
    validation_summary = summarize(validation_scores, thresholds)
    gate = validation_gate(validation_summary)
    report["validation"] = {"gate": gate, "metrics": validation_summary}
    report["status"] = "validation_pass" if gate["passed"] else "validation_failed"
    return report


def run_evaluation(paths_by_role: Mapping[str, RolePaths]) -> dict[str, Any]:
    return evaluate_roles(load_roles(paths_by_role))


def _encode_report(report: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                report,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise Xrf55JointEvaluationError("noncanonical_output") from error


def _write_atomic(path: Path, report: Mapping[str, Any]) -> None:
    encoded = _encode_report(report)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise Xrf55JointEvaluationError("unsafe_output_directory")
    if os.path.lexists(path):
        target = path.lstat()
        if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
            raise Xrf55JointEvaluationError("unsafe_output_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--report", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        report = run_evaluation(cache_paths(arguments.cache_dir))
        report_path = arguments.report or arguments.cache_dir / DEFAULT_REPORT.name
        _write_atomic(report_path, report)
    except (OSError, ValueError, Xrf55JointEvaluationError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
