#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Compile a private deterministic XRF55 feature cache from selected members."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
DEFAULT_RAW_DIR = ROOT / "data" / "raw"
DEFAULT_RECEIPT_DIR = ROOT / "data" / "receipts" / "xrf55"
DEFAULT_OUTPUT_DIR = ROOT / "data" / "derived" / "eval"
DEFAULT_ADAPTER = DEFAULT_OUTPUT_DIR / "xrf55-feature-cache-adapter.json"
DEFAULT_MATRICES = {
    "wifi": DEFAULT_OUTPUT_DIR / "xrf55-feature-cache-wifi.npy",
    "rfid": DEFAULT_OUTPUT_DIR / "xrf55-feature-cache-rfid.npy",
    "mmwave": DEFAULT_OUTPUT_DIR / "xrf55-feature-cache-mmwave.npy",
}
PUBLISHER_IMPLEMENTATION_REVISION = "6cf95821e45277ee97c55e9c68d67bc7e33962ad"
MAX_SELECTED_MEMBER_BYTES = 8 * 1024**2
READ_CHUNK_BYTES = 1024**2


class Xrf55CacheCompileError(RuntimeError):
    """Stable failure at the XRF55 cache-compilation boundary."""


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Xrf55CacheCompileError("module_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROFILE = _load_module("_xrf55_cache_layout_profile", HERE / "profile-xrf55-layout.py")
FEATURES = _load_module("xrf55_features", HERE / "xrf55_features.py")
ROLE_CACHE_SCHEMA = "netbraid.xrf55_trimodal_role_cache.v0"
ROLE_ORDER = ("train", "calibration", "validation", "locked_test")
PRE_GATE_ROLES = ROLE_ORDER[:-1]
ROLE_GROUP_RANKS = {
    "train": (1, 8),
    "calibration": (9, 10),
    "validation": (11, 12),
    "locked_test": (13, 16),
}
ROLE_EVENT_COUNTS = {
    role: (last - first + 1) * len(FEATURES.PUBLISHER_REPETITIONS)
    for role, (first, last) in ROLE_GROUP_RANKS.items()
}
ROLE_OUTPUT_FILENAMES = {
    "train": {
        "adapter": "xrf55-trimodal-fusion-train-adapter.json",
        "wifi": "xrf55-trimodal-fusion-train-wifi.npy",
        "rfid": "xrf55-trimodal-fusion-train-rfid.npy",
        "mmwave": "xrf55-trimodal-fusion-train-mmwave.npy",
    },
    "calibration": {
        "adapter": "xrf55-trimodal-fusion-calibration-adapter.json",
        "wifi": "xrf55-trimodal-fusion-calibration-wifi.npy",
        "rfid": "xrf55-trimodal-fusion-calibration-rfid.npy",
        "mmwave": "xrf55-trimodal-fusion-calibration-mmwave.npy",
    },
    "validation": {
        "adapter": "xrf55-trimodal-fusion-validation-adapter.json",
        "wifi": "xrf55-trimodal-fusion-validation-wifi.npy",
        "rfid": "xrf55-trimodal-fusion-validation-rfid.npy",
        "mmwave": "xrf55-trimodal-fusion-validation-mmwave.npy",
    },
    "locked_test": {
        "adapter": "xrf55-trimodal-fusion-locked-test-adapter.json",
        "wifi": "xrf55-trimodal-fusion-locked-test-wifi.npy",
        "rfid": "xrf55-trimodal-fusion-locked-test-rfid.npy",
        "mmwave": "xrf55-trimodal-fusion-locked-test-mmwave.npy",
    },
}


@dataclass(frozen=True)
class ArchiveSource:
    path: Path
    expected_bytes: int
    contract: Mapping[str, Any]
    inspection: Any


@dataclass(frozen=True)
class OutputSet:
    adapter: Path
    matrices: Mapping[str, Path]


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _inspection_identity(inspection: Any) -> tuple[int, int, int, int, int]:
    identity = inspection.identity
    return (
        identity.device,
        identity.inode,
        identity.size,
        identity.modified_ns,
        identity.changed_ns,
    )


def _open_verified(source: ArchiveSource):
    expected = _inspection_identity(source.inspection)
    try:
        before = source.path.lstat()
    except OSError as error:
        raise Xrf55CacheCompileError("archive_unavailable") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or _identity(before) != expected
    ):
        raise Xrf55CacheCompileError("archive_changed_after_layout_profile")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(source.path, flags)
    except OSError as error:
        raise Xrf55CacheCompileError("archive_open_failed") from error
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != expected:
            raise Xrf55CacheCompileError("archive_identity_changed")
        return os.fdopen(descriptor, "rb"), expected
    except BaseException:
        os.close(descriptor)
        raise


def load_archive_sources(raw_dir: Path, receipt_dir: Path) -> tuple[ArchiveSource, ...]:
    selected = {
        name: PROFILE.FETCH.SOURCES[name] for name in PROFILE.PROCESSED_CONTRACTS
    }
    status = PROFILE.FETCH.local_status(selected, raw_dir, receipt_dir)
    sources = []
    for name, spec in selected.items():
        observed = status["datasets"][name]
        valid_receipt = (
            observed["central_receipt_state"] == "valid"
            or observed["legacy_receipt_state"] == "valid"
        )
        if observed["archive_state"] != "present" or not valid_receipt:
            raise Xrf55CacheCompileError("archive_or_receipt_metadata_unready")
        path = raw_dir / str(spec["filename"])
        expected_bytes = int(spec["archive_bytes"])
        contract = PROFILE.PROCESSED_CONTRACTS[name]
        inspection = PROFILE.profile_archive(path, expected_bytes, contract)
        sources.append(ArchiveSource(path, expected_bytes, contract, inspection))
    return tuple(sources)


def _read_member(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> np.ndarray:
    if not 0 < member.file_size <= MAX_SELECTED_MEMBER_BYTES:
        raise Xrf55CacheCompileError("selected_member_size_limit")
    try:
        with archive.open(member, mode="r") as payload:
            encoded = payload.read(MAX_SELECTED_MEMBER_BYTES + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise Xrf55CacheCompileError("selected_member_read_failed") from error
    if len(encoded) != member.file_size:
        raise Xrf55CacheCompileError("selected_member_extent_mismatch")
    buffer = io.BytesIO(encoded)
    try:
        array = np.load(buffer, allow_pickle=False)
    except (OSError, ValueError) as error:
        raise Xrf55CacheCompileError("selected_member_npy_invalid") from error
    if not isinstance(array, np.ndarray) or buffer.tell() != len(encoded):
        raise Xrf55CacheCompileError("selected_member_npy_extent_mismatch")
    return array


def compile_matrices(
    sources: Sequence[ArchiveSource],
    *,
    group_count: int = FEATURES.DEFAULT_GROUP_COUNT,
    repetitions: Sequence[int] = FEATURES.PUBLISHER_REPETITIONS,
    layouts: Mapping[str, Any] = FEATURES.OFFICIAL_LAYOUTS,
    extractor: Callable[..., np.ndarray] = FEATURES.feature_vector,
) -> tuple[tuple[Any, ...], dict[str, np.ndarray]]:
    observations = set()
    subject_groups = set()
    for source in sources:
        if observations.intersection(source.inspection.observations):
            raise Xrf55CacheCompileError("processed_archive_observation_overlap")
        if subject_groups.intersection(source.inspection.subject_groups):
            raise Xrf55CacheCompileError("processed_archive_group_overlap")
        observations.update(source.inspection.observations)
        subject_groups.update(source.inspection.subject_groups)
    try:
        events = FEATURES.select_campaign(
            observations, group_count=group_count, repetitions=repetitions
        )
    except FEATURES.Xrf55FeatureError as error:
        raise Xrf55CacheCompileError(str(error)) from error

    row_by_observation = {event.observation: event.row for event in events}
    matrices = {
        modality: np.empty((len(events), FEATURES.FEATURE_COUNT), dtype="<f8")
        for modality in FEATURES.MODALITIES
    }
    observed_cells = set()

    for source in sources:
        file_object, expected_identity = _open_verified(source)
        with file_object:
            try:
                archive = zipfile.ZipFile(file_object, mode="r", allowZip64=True)
            except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
                raise Xrf55CacheCompileError("invalid_zip_archive") from error
            with archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    parts, _ = PROFILE.safe_member_name(member.filename)
                    scene, subject, action, repetition, modality = (
                        PROFILE.processed_observation(parts, source.contract)
                    )
                    observation = (scene, subject, action, repetition)
                    row = row_by_observation.get(observation)
                    if row is None:
                        continue
                    cell = (row, modality)
                    if cell in observed_cells:
                        raise Xrf55CacheCompileError("duplicate_selected_modality")
                    array = _read_member(archive, member)
                    try:
                        vector = extractor(modality, array, layouts=layouts)
                    except FEATURES.Xrf55FeatureError as error:
                        raise Xrf55CacheCompileError(str(error)) from error
                    if (
                        vector.shape != (FEATURES.FEATURE_COUNT,)
                        or vector.dtype.str != "<f8"
                    ):
                        raise Xrf55CacheCompileError("invalid_feature_vector")
                    matrices[modality][row] = vector
                    observed_cells.add(cell)
            if _identity(os.fstat(file_object.fileno())) != expected_identity:
                raise Xrf55CacheCompileError("archive_changed_during_cache_compile")

    expected_cells = {
        (event.row, modality) for event in events for modality in FEATURES.MODALITIES
    }
    if observed_cells != expected_cells:
        raise Xrf55CacheCompileError("incomplete_selected_event_grid")
    return events, matrices


def _normalize_roles(roles: Sequence[str]) -> tuple[str, ...]:
    requested = tuple(roles)
    if (
        not requested
        or len(set(requested)) != len(requested)
        or any(role not in ROLE_ORDER for role in requested)
    ):
        raise Xrf55CacheCompileError("invalid_role_request")
    return tuple(role for role in ROLE_ORDER if role in requested)


def select_role_events(
    observations: Sequence[Any], roles: Sequence[str] = ROLE_ORDER
) -> dict[str, tuple[Any, ...]]:
    """Partition the first 16 complete ranked groups into fixed whole-group roles."""

    selected_roles = _normalize_roles(roles)
    try:
        campaign = FEATURES.select_campaign(
            observations,
            group_count=ROLE_GROUP_RANKS["locked_test"][1],
            repetitions=FEATURES.PUBLISHER_REPETITIONS,
        )
    except FEATURES.Xrf55FeatureError as error:
        raise Xrf55CacheCompileError(str(error)) from error

    ranked_group_ids = tuple(dict.fromkeys(event.group_id for event in campaign))
    if len(ranked_group_ids) != ROLE_GROUP_RANKS["locked_test"][1]:
        raise Xrf55CacheCompileError("role_group_count_mismatch")
    role_by_group = {}
    for role, (first, last) in ROLE_GROUP_RANKS.items():
        for group_id in ranked_group_ids[first - 1 : last]:
            role_by_group[group_id] = role

    partitioned: dict[str, list[Any]] = {role: [] for role in selected_roles}
    for event in campaign:
        role = role_by_group[event.group_id]
        if role not in partitioned:
            continue
        role_events = partitioned[role]
        role_events.append(
            FEATURES.CampaignEvent(
                event_id=event.event_id,
                group_id=event.group_id,
                observation=event.observation,
                repetition=event.repetition,
                row=len(role_events),
                split=role,
            )
        )

    result = {role: tuple(partitioned[role]) for role in selected_roles}
    if any(len(result[role]) != ROLE_EVENT_COUNTS[role] for role in selected_roles):
        raise Xrf55CacheCompileError("role_event_count_mismatch")
    return result


def compile_role_matrices(
    sources: Sequence[ArchiveSource],
    *,
    roles: Sequence[str] = PRE_GATE_ROLES,
    layouts: Mapping[str, Any] = FEATURES.OFFICIAL_LAYOUTS,
    extractor: Callable[..., np.ndarray] = FEATURES.feature_vector,
) -> tuple[dict[str, tuple[Any, ...]], dict[str, dict[str, np.ndarray]]]:
    """Compile only the member payloads belonging to the requested fixed roles."""

    observations = set()
    subject_groups = set()
    for source in sources:
        if observations.intersection(source.inspection.observations):
            raise Xrf55CacheCompileError("processed_archive_observation_overlap")
        if subject_groups.intersection(source.inspection.subject_groups):
            raise Xrf55CacheCompileError("processed_archive_group_overlap")
        observations.update(source.inspection.observations)
        subject_groups.update(source.inspection.subject_groups)

    events_by_role = select_role_events(tuple(observations), roles)
    row_by_observation = {
        event.observation: (role, event.row)
        for role, events in events_by_role.items()
        for event in events
    }
    matrices = {
        role: {
            modality: np.empty((len(events), FEATURES.FEATURE_COUNT), dtype="<f8")
            for modality in FEATURES.MODALITIES
        }
        for role, events in events_by_role.items()
    }
    observed_cells = set()

    for source in sources:
        file_object, expected_identity = _open_verified(source)
        with file_object:
            try:
                archive = zipfile.ZipFile(file_object, mode="r", allowZip64=True)
            except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
                raise Xrf55CacheCompileError("invalid_zip_archive") from error
            with archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    parts, _ = PROFILE.safe_member_name(member.filename)
                    scene, subject, action, repetition, modality = (
                        PROFILE.processed_observation(parts, source.contract)
                    )
                    selected = row_by_observation.get(
                        (scene, subject, action, repetition)
                    )
                    if selected is None:
                        continue
                    role, row = selected
                    cell = (role, row, modality)
                    if cell in observed_cells:
                        raise Xrf55CacheCompileError("duplicate_selected_modality")
                    array = _read_member(archive, member)
                    try:
                        vector = extractor(modality, array, layouts=layouts)
                    except FEATURES.Xrf55FeatureError as error:
                        raise Xrf55CacheCompileError(str(error)) from error
                    if (
                        vector.shape != (FEATURES.FEATURE_COUNT,)
                        or vector.dtype.str != "<f8"
                    ):
                        raise Xrf55CacheCompileError("invalid_feature_vector")
                    matrices[role][modality][row] = vector
                    observed_cells.add(cell)
            if _identity(os.fstat(file_object.fileno())) != expected_identity:
                raise Xrf55CacheCompileError("archive_changed_during_cache_compile")

    expected_cells = {
        (role, event.row, modality)
        for role, events in events_by_role.items()
        for event in events
        for modality in FEATURES.MODALITIES
    }
    if observed_cells != expected_cells:
        raise Xrf55CacheCompileError("incomplete_selected_event_grid")
    return events_by_role, matrices


def _prepare_target(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise Xrf55CacheCompileError("unsafe_output_directory")
    if os.path.lexists(path):
        target = path.lstat()
        if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
            raise Xrf55CacheCompileError("unsafe_output_path")


def _hash_file(path: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as source:
        while chunk := source.read(READ_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _write_npy_temporary(target: Path, matrix: np.ndarray) -> tuple[str, str, int]:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            np.save(output, matrix, allow_pickle=False)
            output.flush()
            os.fsync(output.fileno())
        digest, size = _hash_file(temporary)
        return temporary, digest, size
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise


def _adapter_document(
    events: Sequence[Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    archive_count: int,
) -> dict[str, Any]:
    counts_by_split = {
        split: sum(event.split == split for event in events)
        for split in ("train", "test", "other")
    }
    counts_by_split = {key: value for key, value in counts_by_split.items() if value}
    return {
        "schema": FEATURES.SCHEMA,
        "provenance": {
            "dataset": "XRF55 processed RF arrays",
            "publisher_implementation_revision": PUBLISHER_IMPLEMENTATION_REVISION,
            "publisher_project": "https://aiotgroup.github.io/XRF55/",
        },
        "integrity": {
            "all_archive_bytes_freshly_rehashed": False,
            "basis": "exact_size_and_fetch_receipt_metadata_plus_selected_member_crc",
            "artifacts": dict(sorted(artifacts.items())),
        },
        "feature_policy": FEATURES.feature_policy_document(),
        "split_policy": {
            "candidate_set": "same_opaque_performer_action_group",
            "publisher_train_repetitions": sorted(FEATURES.TRAIN_REPETITIONS),
            "publisher_test_repetitions": sorted(FEATURES.TEST_REPETITIONS),
        },
        "events": FEATURES.campaign_document(events),
        "counts": {
            "archives": archive_count,
            "events": len(events),
            "features_per_modality": FEATURES.FEATURE_COUNT,
            "groups": len({event.group_id for event in events}),
            "modalities": len(FEATURES.MODALITIES),
            "split_events": counts_by_split,
        },
        "privacy": {
            "archive_names_retained": 0,
            "local_paths_retained": 0,
            "member_names_retained": 0,
            "raw_action_identifiers_retained": 0,
            "raw_performer_identifiers_retained": 0,
            "raw_scene_identifiers_retained": 0,
        },
    }


def _role_adapter_document(
    role: str,
    events: Sequence[Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    archive_count: int,
) -> dict[str, Any]:
    first_rank, last_rank = ROLE_GROUP_RANKS[role]
    return {
        "schema": ROLE_CACHE_SCHEMA,
        "provenance": {
            "dataset": "XRF55 processed RF arrays",
            "publisher_implementation_revision": PUBLISHER_IMPLEMENTATION_REVISION,
            "publisher_project": "https://aiotgroup.github.io/XRF55/",
        },
        "integrity": {
            "all_archive_bytes_freshly_rehashed": False,
            "basis": "exact_size_and_fetch_receipt_metadata_plus_selected_member_crc",
            "artifacts": dict(sorted(artifacts.items())),
        },
        "feature_policy": FEATURES.feature_policy_document(),
        "role_policy": {
            "assignment": "complete_opaque_performer_action_group_rank",
            "first_group_rank": first_rank,
            "last_group_rank": last_rank,
            "modalities_colocated": list(FEATURES.MODALITIES),
            "role": role,
            "whole_groups_disjoint": True,
        },
        "events": [
            {
                "event_id": event.event_id,
                "group_id": event.group_id,
                "role": role,
                "row": event.row,
            }
            for event in events
        ],
        "counts": {
            "archives": archive_count,
            "events": len(events),
            "features_per_modality": FEATURES.FEATURE_COUNT,
            "groups": len({event.group_id for event in events}),
            "modalities": len(FEATURES.MODALITIES),
        },
        "privacy": {
            "archive_names_retained": 0,
            "local_paths_retained": 0,
            "member_names_retained": 0,
            "raw_action_identifiers_retained": 0,
            "raw_labels_retained": 0,
            "raw_performer_identifiers_retained": 0,
            "raw_repetition_identifiers_retained": 0,
            "raw_scene_identifiers_retained": 0,
            "raw_source_values_retained": 0,
        },
    }


def _write_cache_files(
    outputs: OutputSet,
    matrices: Mapping[str, np.ndarray],
    document: Callable[[Mapping[str, Mapping[str, Any]]], dict[str, Any]],
) -> dict[str, Any]:
    paths = [outputs.adapter, *(outputs.matrices[name] for name in FEATURES.MODALITIES)]
    if len({path.resolve(strict=False) for path in paths}) != len(paths):
        raise Xrf55CacheCompileError("duplicate_output_path")
    for path in paths:
        _prepare_target(path)

    temporaries = {}
    artifacts = {}
    try:
        for modality in FEATURES.MODALITIES:
            temporary, digest, size = _write_npy_temporary(
                outputs.matrices[modality], matrices[modality]
            )
            temporaries[modality] = temporary
            artifacts[modality] = {
                "bytes": size,
                "dtype": matrices[modality].dtype.str,
                "sha256": digest,
                "shape": list(matrices[modality].shape),
            }
        adapter = document(artifacts)
        descriptor, temporary_adapter = tempfile.mkstemp(
            prefix=f".{outputs.adapter.name}.", dir=outputs.adapter.parent
        )
        temporaries["adapter"] = temporary_adapter
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(adapter, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        for modality in FEATURES.MODALITIES:
            os.replace(temporaries.pop(modality), outputs.matrices[modality])
        os.replace(temporaries.pop("adapter"), outputs.adapter)
        return adapter
    finally:
        for temporary in temporaries.values():
            if os.path.lexists(temporary):
                os.unlink(temporary)


def write_cache(
    outputs: OutputSet,
    events: Sequence[Any],
    matrices: Mapping[str, np.ndarray],
    archive_count: int,
) -> dict[str, Any]:
    return _write_cache_files(
        outputs,
        matrices,
        lambda artifacts: _adapter_document(events, artifacts, archive_count),
    )


def role_output_set(directory: Path, role: str) -> OutputSet:
    selected_role = _normalize_roles((role,))[0]
    filenames = ROLE_OUTPUT_FILENAMES[selected_role]
    return OutputSet(
        directory / filenames["adapter"],
        {modality: directory / filenames[modality] for modality in FEATURES.MODALITIES},
    )


def write_role_caches(
    outputs: Mapping[str, OutputSet],
    events: Mapping[str, Sequence[Any]],
    matrices: Mapping[str, Mapping[str, np.ndarray]],
    archive_count: int,
) -> dict[str, dict[str, Any]]:
    roles = _normalize_roles(tuple(events))
    if not set(roles).issubset(outputs) or set(matrices) != set(roles):
        raise Xrf55CacheCompileError("role_output_set_mismatch")
    paths = [
        path
        for role in roles
        for path in (
            outputs[role].adapter,
            *(outputs[role].matrices[name] for name in FEATURES.MODALITIES),
        )
    ]
    if len({path.resolve(strict=False) for path in paths}) != len(paths):
        raise Xrf55CacheCompileError("duplicate_output_path")

    adapters = {}
    for role in roles:
        if len(events[role]) != ROLE_EVENT_COUNTS[role]:
            raise Xrf55CacheCompileError("role_event_count_mismatch")
        adapters[role] = _write_cache_files(
            outputs[role],
            matrices[role],
            lambda artifacts, role=role: _role_adapter_document(
                role, events[role], artifacts, archive_count
            ),
        )
    return adapters


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    parser.add_argument("--wifi-matrix", type=Path, default=DEFAULT_MATRICES["wifi"])
    parser.add_argument("--rfid-matrix", type=Path, default=DEFAULT_MATRICES["rfid"])
    parser.add_argument(
        "--mmwave-matrix", type=Path, default=DEFAULT_MATRICES["mmwave"]
    )
    parser.add_argument("--group-count", type=int, default=FEATURES.DEFAULT_GROUP_COUNT)
    parser.add_argument(
        "--role-cache-dir",
        type=Path,
        help="write fixed group-disjoint role caches instead of the legacy cache",
    )
    parser.add_argument(
        "--role",
        action="append",
        choices=ROLE_ORDER,
        help="role to compile; defaults to train, calibration, and validation",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    matrices = {
        "wifi": arguments.wifi_matrix,
        "rfid": arguments.rfid_matrix,
        "mmwave": arguments.mmwave_matrix,
    }
    try:
        if (
            arguments.role_cache_dir is not None
            and arguments.group_count != FEATURES.DEFAULT_GROUP_COUNT
        ):
            raise Xrf55CacheCompileError("role_cache_group_count_is_fixed")
        sources = load_archive_sources(arguments.raw_dir, arguments.receipt_dir)
        if arguments.role_cache_dir is None:
            if arguments.role is not None:
                raise Xrf55CacheCompileError("role_cache_directory_required")
            events, feature_matrices = compile_matrices(
                sources, group_count=arguments.group_count
            )
            adapter = write_cache(
                OutputSet(arguments.adapter, matrices),
                events,
                feature_matrices,
                len(sources),
            )
            summary = adapter["counts"]
        else:
            roles = _normalize_roles(arguments.role or PRE_GATE_ROLES)
            role_events, role_matrices = compile_role_matrices(sources, roles=roles)
            outputs = {
                "train": role_output_set(arguments.role_cache_dir, "train"),
                "calibration": role_output_set(arguments.role_cache_dir, "calibration"),
                "validation": role_output_set(arguments.role_cache_dir, "validation"),
                "locked_test": role_output_set(arguments.role_cache_dir, "locked_test"),
            }
            adapters = write_role_caches(
                outputs, role_events, role_matrices, len(sources)
            )
            summary = {role: adapters[role]["counts"] for role in roles}
    except (
        OSError,
        ValueError,
        zipfile.BadZipFile,
        PROFILE.Xrf55ProfileError,
        Xrf55CacheCompileError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
