#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Compile private deterministic XRF55 joint-grid role caches."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
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
DEFAULT_OUTPUT_DIR = (
    ROOT / "data" / "derived" / "eval" / "xrf55-joint-representation-v0"
)
SCHEMA = "netbraid.xrf55_joint_role_cache.v0"
READ_CHUNK_BYTES = 1024**2


class Xrf55JointCacheCompileError(RuntimeError):
    """Stable failure at the joint role-cache compilation boundary."""


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Xrf55JointCacheCompileError("module_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load_module("_xrf55_joint_cache_base", HERE / "compile-xrf55-feature-cache.py")
JOINT = _load_module("xrf55_joint_features", HERE / "xrf55_joint_features.py")
FEATURES = JOINT.FEATURES
ROLE_ORDER = JOINT.ROLE_ORDER
OUTPUT_FILENAMES = {
    "train": {
        "adapter": "xrf55-joint-train-adapter.json",
        "wifi": "xrf55-joint-train-wifi.npy",
        "rfid": "xrf55-joint-train-rfid.npy",
        "mmwave": "xrf55-joint-train-mmwave.npy",
    },
    "calibration": {
        "adapter": "xrf55-joint-calibration-adapter.json",
        "wifi": "xrf55-joint-calibration-wifi.npy",
        "rfid": "xrf55-joint-calibration-rfid.npy",
        "mmwave": "xrf55-joint-calibration-mmwave.npy",
    },
    "validation": {
        "adapter": "xrf55-joint-validation-adapter.json",
        "wifi": "xrf55-joint-validation-wifi.npy",
        "rfid": "xrf55-joint-validation-rfid.npy",
        "mmwave": "xrf55-joint-validation-mmwave.npy",
    },
}


@dataclass(frozen=True)
class SourceBinding:
    """Path-free source admission digests retained by every role adapter."""

    archive_count: int
    archive_profile_set_sha256: str
    archive_receipt_set_sha256: str


@dataclass(frozen=True)
class OutputSet:
    adapter: Path
    matrices: Mapping[str, Path]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _content_digest(domain: str, value: Any) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\0" + _canonical_bytes(value)
    ).hexdigest()


def _valid_digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _validate_source_binding(binding: SourceBinding, source_count: int) -> None:
    if (
        type(binding.archive_count) is not int
        or binding.archive_count <= 0
        or binding.archive_count != source_count
        or not _valid_digest(binding.archive_profile_set_sha256)
        or not _valid_digest(binding.archive_receipt_set_sha256)
    ):
        raise Xrf55JointCacheCompileError("invalid_source_binding")


def _normalized_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return {
            "actions": sorted(value["actions"]),
            "repetitions": sorted(value["repetitions"]),
            "scenes": sorted(value["scenes"]),
            "subject_groups": int(value["subject_groups"]),
        }
    except (KeyError, TypeError, ValueError) as error:
        raise Xrf55JointCacheCompileError("invalid_processed_contract") from error


def load_source_set(
    raw_dir: Path, receipt_dir: Path
) -> tuple[tuple[Any, ...], SourceBinding]:
    """Reuse existing archive admission and bind its exact receipt metadata."""

    sources = BASE.load_archive_sources(raw_dir, receipt_dir)
    selected = {
        name: BASE.PROFILE.FETCH.SOURCES[name]
        for name in BASE.PROFILE.PROCESSED_CONTRACTS
    }
    status = BASE.PROFILE.FETCH.local_status(selected, raw_dir, receipt_dir)
    receipts = []
    profiles = []
    if len(sources) != len(selected):
        raise Xrf55JointCacheCompileError("source_count_mismatch")

    for source, (name, spec) in zip(sources, selected.items(), strict=True):
        expected_path = raw_dir / str(spec["filename"])
        if source.path != expected_path:
            raise Xrf55JointCacheCompileError("source_path_mismatch")
        observed = status["datasets"][name]
        if observed["central_receipt_state"] == "valid":
            receipt_path = BASE.PROFILE.FETCH.receipt_path(expected_path, receipt_dir)
        elif observed["legacy_receipt_state"] == "valid":
            receipt_path = BASE.PROFILE.FETCH.legacy_receipt_path(expected_path)
        else:
            raise Xrf55JointCacheCompileError("receipt_metadata_changed")
        try:
            receipt = BASE.PROFILE.FETCH._read_receipt(receipt_path)  # noqa: SLF001
            receipt_sha256 = receipt["sha256"]
            expected_receipt = BASE.PROFILE.FETCH.source_receipt(
                spec, int(spec["archive_bytes"]), receipt_sha256
            )
        except (KeyError, TypeError, BASE.PROFILE.FETCH.FetchError) as error:
            raise Xrf55JointCacheCompileError("receipt_metadata_changed") from error
        if receipt != expected_receipt:
            raise Xrf55JointCacheCompileError("receipt_metadata_changed")
        receipts.append(receipt)
        profiles.append(
            {
                "contract": _normalized_contract(source.contract),
                "inspection": source.inspection.report,
            }
        )

    return tuple(sources), SourceBinding(
        archive_count=len(sources),
        archive_profile_set_sha256=_content_digest(
            "netbraid.xrf55-joint.archive-profile-set.v0", profiles
        ),
        archive_receipt_set_sha256=_content_digest(
            "netbraid.xrf55-joint.archive-receipt-set.v0", receipts
        ),
    )


def role_output_set(directory: Path, role: str) -> OutputSet:
    if role not in ROLE_ORDER:
        raise Xrf55JointCacheCompileError("invalid_role")
    filenames = OUTPUT_FILENAMES[role]
    return OutputSet(
        adapter=directory / filenames["adapter"],
        matrices={
            modality: directory / filenames[modality]
            for modality in FEATURES.MODALITIES
        },
    )


def _all_outputs(directory: Path) -> dict[str, OutputSet]:
    return {role: role_output_set(directory, role) for role in ROLE_ORDER}


def _output_paths(outputs: Mapping[str, OutputSet]) -> tuple[Path, ...]:
    return tuple(
        path
        for role in ROLE_ORDER
        for path in (
            outputs[role].adapter,
            *(outputs[role].matrices[modality] for modality in FEATURES.MODALITIES),
        )
    )


def _prepare_outputs(
    outputs: Mapping[str, OutputSet], sources: Sequence[Any]
) -> tuple[Path, ...]:
    paths = _output_paths(outputs)
    resolved = tuple(path.resolve(strict=False) for path in paths)
    if len(set(resolved)) != len(resolved):
        raise Xrf55JointCacheCompileError("duplicate_output_path")
    source_paths = {source.path.resolve(strict=True) for source in sources}
    if source_paths.intersection(resolved):
        raise Xrf55JointCacheCompileError("output_aliases_source")
    try:
        for path in paths:
            BASE._prepare_target(path)  # noqa: SLF001
    except BASE.Xrf55CacheCompileError as error:
        raise Xrf55JointCacheCompileError(str(error)) from error
    return paths


def _collect_events(sources: Sequence[Any]) -> dict[str, tuple[Any, ...]]:
    observations: set[Any] = set()
    subject_groups: set[Any] = set()
    for source in sources:
        if observations.intersection(source.inspection.observations):
            raise Xrf55JointCacheCompileError("processed_archive_observation_overlap")
        if subject_groups.intersection(source.inspection.subject_groups):
            raise Xrf55JointCacheCompileError("processed_archive_group_overlap")
        observations.update(source.inspection.observations)
        subject_groups.update(source.inspection.subject_groups)
    try:
        return JOINT.select_role_events(observations)
    except FEATURES.Xrf55FeatureError as error:
        raise Xrf55JointCacheCompileError(str(error)) from error


def _new_memmap(target: Path, rows: int) -> tuple[Path, np.memmap]:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        matrix = np.lib.format.open_memmap(
            temporary,
            mode="w+",
            dtype=np.dtype("<f8"),
            shape=(rows, JOINT.FEATURE_COUNT),
            fortran_order=False,
        )
        return temporary, matrix
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise


def _close_memmap(matrix: np.memmap) -> None:
    matrix.flush()
    mapping = getattr(matrix, "_mmap", None)
    if mapping is not None:
        mapping.close()


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(READ_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _verify_temporary_matrix(
    path: Path, expected_shape: tuple[int, int]
) -> tuple[str, int]:
    try:
        matrix = np.load(path, mmap_mode="r", allow_pickle=False)
    except (OSError, ValueError) as error:
        raise Xrf55JointCacheCompileError("temporary_matrix_invalid") from error
    try:
        if (
            not isinstance(matrix, np.memmap)
            or matrix.shape != expected_shape
            or matrix.dtype.str != "<f8"
            or not matrix.flags.c_contiguous
        ):
            raise Xrf55JointCacheCompileError("temporary_matrix_invalid")
    finally:
        _close_memmap(matrix)
    return _hash_file(path)


def _compile_temporary_matrices(
    sources: Sequence[Any],
    outputs: Mapping[str, OutputSet],
    events: Mapping[str, Sequence[Any]],
    *,
    layouts: Mapping[str, Any],
    extractor: Callable[..., np.ndarray],
) -> tuple[dict[str, dict[str, Path]], dict[str, dict[str, dict[str, Any]]]]:
    row_by_observation = {
        event.observation: (role, event.row)
        for role in ROLE_ORDER
        for event in events[role]
    }
    temporary_paths: dict[str, dict[str, Path]] = {role: {} for role in ROLE_ORDER}
    matrices: dict[str, dict[str, np.memmap]] = {role: {} for role in ROLE_ORDER}
    observed_cells: set[tuple[str, int, str]] = set()
    try:
        for role in ROLE_ORDER:
            for modality in FEATURES.MODALITIES:
                temporary, matrix = _new_memmap(
                    outputs[role].matrices[modality], len(events[role])
                )
                temporary_paths[role][modality] = temporary
                matrices[role][modality] = matrix

        for source in sources:
            file_object, expected_identity = BASE._open_verified(source)  # noqa: SLF001
            with file_object:
                try:
                    archive = zipfile.ZipFile(file_object, mode="r", allowZip64=True)
                except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
                    raise Xrf55JointCacheCompileError("invalid_zip_archive") from error
                with archive:
                    for member in archive.infolist():
                        if member.is_dir():
                            continue
                        parts, _ = BASE.PROFILE.safe_member_name(member.filename)
                        scene, subject, action, repetition, modality = (
                            BASE.PROFILE.processed_observation(parts, source.contract)
                        )
                        selected = row_by_observation.get(
                            (scene, subject, action, repetition)
                        )
                        if selected is None:
                            continue
                        role, row = selected
                        cell = (role, row, modality)
                        if cell in observed_cells:
                            raise Xrf55JointCacheCompileError(
                                "duplicate_selected_modality"
                            )
                        array = BASE._read_member(archive, member)  # noqa: SLF001
                        try:
                            vector = extractor(modality, array, layouts=layouts)
                        except FEATURES.Xrf55FeatureError as error:
                            raise Xrf55JointCacheCompileError(str(error)) from error
                        if (
                            vector.shape != (JOINT.FEATURE_COUNT,)
                            or vector.dtype.str != "<f8"
                        ):
                            raise Xrf55JointCacheCompileError(
                                "invalid_joint_feature_vector"
                            )
                        matrices[role][modality][row] = vector
                        observed_cells.add(cell)
                if BASE._identity(os.fstat(file_object.fileno())) != expected_identity:  # noqa: SLF001
                    raise Xrf55JointCacheCompileError(
                        "archive_changed_during_cache_compile"
                    )

        expected_cells = {
            (role, event.row, modality)
            for role in ROLE_ORDER
            for event in events[role]
            for modality in FEATURES.MODALITIES
        }
        if observed_cells != expected_cells:
            raise Xrf55JointCacheCompileError("incomplete_selected_event_grid")

        artifacts: dict[str, dict[str, dict[str, Any]]] = {
            role: {} for role in ROLE_ORDER
        }
        for role in ROLE_ORDER:
            for modality in FEATURES.MODALITIES:
                matrix = matrices[role].pop(modality)
                _close_memmap(matrix)
                path = temporary_paths[role][modality]
                with path.open("rb") as source:
                    os.fsync(source.fileno())
                shape = (len(events[role]), JOINT.FEATURE_COUNT)
                digest, size = _verify_temporary_matrix(path, shape)
                artifacts[role][modality] = {
                    "bytes": size,
                    "dtype": "<f8",
                    "sha256": digest,
                    "shape": list(shape),
                }
        return temporary_paths, artifacts
    except BaseException:
        for role_matrices in matrices.values():
            for matrix in role_matrices.values():
                _close_memmap(matrix)
        for role_paths in temporary_paths.values():
            for path in role_paths.values():
                if os.path.lexists(path):
                    os.unlink(path)
        raise


def _adapter_document(
    role: str,
    events: Sequence[Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    source_binding: SourceBinding,
) -> dict[str, Any]:
    feature_policy = JOINT.feature_policy_document()
    role_policy = JOINT.role_policy_document()
    first_rank, last_rank = JOINT.ROLE_GROUP_RANKS[role]
    return {
        "schema": SCHEMA,
        "provenance": {
            "dataset": "XRF55 processed RF arrays",
            "publisher_implementation_revision": BASE.PUBLISHER_IMPLEMENTATION_REVISION,
            "publisher_project": "https://aiotgroup.github.io/XRF55/",
        },
        "integrity": {
            "all_archive_bytes_freshly_rehashed": False,
            "artifacts": dict(sorted(artifacts.items())),
            "basis": ("exact_size_and_fetch_receipt_metadata_plus_selected_member_crc"),
            "feature_policy_sha256": _content_digest(
                "netbraid.xrf55-joint.feature-policy.v0", feature_policy
            ),
            "role_policy_sha256": _content_digest(
                "netbraid.xrf55-joint.role-policy.v0", role_policy
            ),
            "source": {
                "archive_profile_set_sha256": (
                    source_binding.archive_profile_set_sha256
                ),
                "archive_receipt_set_sha256": (
                    source_binding.archive_receipt_set_sha256
                ),
            },
        },
        "feature_policy": feature_policy,
        "role_policy": {
            **role_policy,
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
            "archives": source_binding.archive_count,
            "events": len(events),
            "features_per_modality": JOINT.FEATURE_COUNT,
            "groups": len({event.group_id for event in events}),
            "modalities": len(FEATURES.MODALITIES),
            "roles": 1,
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


def _write_adapter_temporary(target: Path, document: Mapping[str, Any]) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        return temporary
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise


def _backup_path(target: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{target.name}.backup.", dir=target.parent
    )
    os.close(descriptor)
    os.unlink(name)
    return Path(name)


def _publish(
    output_dir: Path,
    outputs: Mapping[str, OutputSet],
    matrix_temporaries: Mapping[str, Mapping[str, Path]],
    adapter_temporaries: Mapping[str, Path],
) -> None:
    matrix_publications = (
        (
            matrix_temporaries["train"]["wifi"],
            output_dir / "xrf55-joint-train-wifi.npy",
        ),
        (
            matrix_temporaries["train"]["rfid"],
            output_dir / "xrf55-joint-train-rfid.npy",
        ),
        (
            matrix_temporaries["train"]["mmwave"],
            output_dir / "xrf55-joint-train-mmwave.npy",
        ),
        (
            matrix_temporaries["calibration"]["wifi"],
            output_dir / "xrf55-joint-calibration-wifi.npy",
        ),
        (
            matrix_temporaries["calibration"]["rfid"],
            output_dir / "xrf55-joint-calibration-rfid.npy",
        ),
        (
            matrix_temporaries["calibration"]["mmwave"],
            output_dir / "xrf55-joint-calibration-mmwave.npy",
        ),
        (
            matrix_temporaries["validation"]["wifi"],
            output_dir / "xrf55-joint-validation-wifi.npy",
        ),
        (
            matrix_temporaries["validation"]["rfid"],
            output_dir / "xrf55-joint-validation-rfid.npy",
        ),
        (
            matrix_temporaries["validation"]["mmwave"],
            output_dir / "xrf55-joint-validation-mmwave.npy",
        ),
    )
    adapter_publications = (
        (adapter_temporaries["train"], output_dir / "xrf55-joint-train-adapter.json"),
        (
            adapter_temporaries["calibration"],
            output_dir / "xrf55-joint-calibration-adapter.json",
        ),
        (
            adapter_temporaries["validation"],
            output_dir / "xrf55-joint-validation-adapter.json",
        ),
    )
    publications = matrix_publications + adapter_publications
    targets = tuple(target for _, target in publications)
    if set(targets) != set(_output_paths(outputs)):
        raise Xrf55JointCacheCompileError("output_contract_mismatch")
    backups: dict[Path, Path] = {}
    replaced: set[Path] = set()
    try:
        for target in targets:
            if not os.path.lexists(target):
                continue
            metadata = target.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise Xrf55JointCacheCompileError("unsafe_output_path")
            backup = _backup_path(target)
            os.replace(target, backup)
            backups[target] = backup

        for temporary, target in publications:
            os.replace(temporary, target)
            replaced.add(target)
    except BaseException:
        for target in reversed(targets):
            backup = backups.get(target)
            if backup is not None and os.path.lexists(backup):
                os.replace(backup, target)
            elif target in replaced and os.path.lexists(target):
                os.unlink(target)
        raise
    finally:
        for backup in backups.values():
            if os.path.lexists(backup):
                os.unlink(backup)


def compile_joint_role_cache(
    sources: Sequence[Any],
    output_dir: Path,
    source_binding: SourceBinding,
    *,
    layouts: Mapping[str, Any] = FEATURES.OFFICIAL_LAYOUTS,
    extractor: Callable[..., np.ndarray] = JOINT.feature_vector,
) -> dict[str, dict[str, Any]]:
    """Compile all three fixed roles and publish each adapter last."""

    sources = tuple(sources)
    _validate_source_binding(source_binding, len(sources))
    outputs = _all_outputs(output_dir)
    _prepare_outputs(outputs, sources)
    events = _collect_events(sources)
    matrix_temporaries: dict[str, dict[str, Path]] = {}
    adapter_temporaries: dict[str, Path] = {}
    try:
        matrix_temporaries, artifacts = _compile_temporary_matrices(
            sources,
            outputs,
            events,
            layouts=layouts,
            extractor=extractor,
        )
        adapters = {
            role: _adapter_document(role, events[role], artifacts[role], source_binding)
            for role in ROLE_ORDER
        }
        adapter_temporaries = {
            role: _write_adapter_temporary(outputs[role].adapter, adapters[role])
            for role in ROLE_ORDER
        }
        _publish(output_dir, outputs, matrix_temporaries, adapter_temporaries)
        return adapters
    finally:
        for role_paths in matrix_temporaries.values():
            for path in role_paths.values():
                if os.path.lexists(path):
                    os.unlink(path)
        for path in adapter_temporaries.values():
            if os.path.lexists(path):
                os.unlink(path)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        sources, source_binding = load_source_set(
            arguments.raw_dir, arguments.receipt_dir
        )
        adapters = compile_joint_role_cache(
            sources, arguments.output_dir, source_binding
        )
    except (
        OSError,
        ValueError,
        zipfile.BadZipFile,
        BASE.PROFILE.Xrf55ProfileError,
        BASE.Xrf55CacheCompileError,
        Xrf55JointCacheCompileError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 2
    summary = {role: adapters[role]["counts"] for role in ROLE_ORDER}
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
